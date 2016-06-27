#!/usr/bin/env python
# -*- encoding: utf-8 -*-
import time
import struct
import socket, threading
import asyncore, sys
import logging

from ether2any.pytap import TapDevice
import netifaces

import re
regex_ipv4 = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')

class resettableTimer():
    """ A class implementing a timer, checking for timeout every n seconds

    Sadly, python does not provide a timer which is resettable, so here
    is an implementation for that"""
    check_interval = 1

    def __init__(self, timeout, timeout_function, timeout_function_args=()):
        self._timeout = timeout
        self._timeout_function = lambda: timeout_function(*timeout_function_args)

        self._timeout_time = time.time()
        self._timer = threading.Timer(self.check_interval, self._check_function)
        self._timer.start()

    def _check_function(self):
        """ Check every 1 second if we have a read timeout """
        if (time.time() - self._timeout_time) > self._timeout:
            logging.debug('Timeout!')
            self._timeout_function()
        else:
            self._timer = threading.Timer(self.check_interval, self._check_function)
            self._timer.start()

    def reset(self):
        self._timeout_time = time.time()

    def stop(self):
        self._timer.cancel()
        
    def is_running(self):
        return self._timer.is_alive()

class dispatcher_with_addr(asyncore.dispatcher):
    """ Basically asyncore.dispatcher, with recvfrom and sendto and respective buffering

    recvfrom is only used by the server to dynamically adapt to new loadbalancer-clients
    sendto is used by both, since it's udp"""
    
    _repr = ''
    weight = 1
    
    def __init__(self, sock, control):
        asyncore.dispatcher.__init__(self, sock)
        if self.socket:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            self.set_reuse_addr()

        self.control = control
        self.port = control.port
        self.out_buffer = []
        if not self._repr:
            self._repr = '<unbound>'

    def timeout_close(self):
        logging.info('{} exited due to not receiving data for {} seconds'.format(repr(self), self.timeout))
        self.handle_close()

    def writable(self):
        return len(self.out_buffer) > 0
    
    def handle_write(self):
        """ Get a packet from the buffer and write it to the address """
        packet, addr = self.out_buffer.pop() if self.out_buffer else ('',())
        logging.debug('Sending {}b packet  to {}'.format(len(packet), repr(addr)))
        if len(self.out_buffer) > 10:
            print len(self.out_buffer)
        while len(packet) > 0:
            num_sent = self.sendto(packet, addr)
            logging.debug('\t {}b sent'.format(num_sent))
            if num_sent == 0:
                break
            packet = packet[num_sent:]

    def send(self, data, addr):
        """ Append to buffer and start sending """ 
        self.out_buffer.append((data, addr))
        #self.initiate_send()

    def sendto(self, data, addr):
        """ Wrapper for exceptions around sendto """
        try:
            result = self.socket.sendto(data, addr)
            return result
        except socket.error, why:
            if why.args[0] == asyncore.EWOULDBLOCK:
                return 0
            elif why.args[0] in asyncore._DISCONNECTED:
                self.handle_close()
                return 0
            else:
                raise

    def handle_read(self):
        """ Read a datagram and write to the tun/tap device """
        data = self.recv(4096)
        if data:
            logging.debug('Reading {}b packet from loadbalancing'.format(len(data)))
            self.timer.reset()
            self.control.write(data)
 
    def recvfrom(self, buffer_size):
        """ Wrapper for exceptions around recvfrom """
        try:
            data, addr = self.socket.recvfrom(buffer_size)
            if not data:
                # a closed connection is indicated by signaling
                # a read condition, and having recv() return 0.
                self.handle_close()
                return '',()
            else:
                return data, addr
        except socket.error, why:
            # winsock sometimes raises ENOTCONN
            if why.args[0] in _DISCONNECTED:
                self.handle_close()
                return '', ()
            else:
                raise

    def __repr__(self):
        return 'Loadbalancer:{}'.format(self._repr)
        

class LoadbalancerClient(dispatcher_with_addr):
    """ LoadbalancerClients get spawned to transmit data from the tun/tap device to the server

    Their focus is to take care that their traffic is routable via 
    different paths (binding to specific interfaces/ip/ports) and
    authenticating themselves to the server."""

    def __init__(self, control, routing_spec):
        sock = self.parse_routing_spec(routing_spec)
        dispatcher_with_addr.__init__(self, sock, control)

        self.loadbalancer_bind()
        self.send_configs()
        self.timer = resettableTimer(30, self.handle_close)

    def send_configs(self):
        """ Send auth and configuration """
        conf_packet = "{}{:3d}".format(self.control.secret, self.weight_downlink)
        self.send(conf_packet, self.control.destination)

    def parse_routing_spec(self, routing_spec):
        """ Parse routing_spec and create socket accordingly. 

            Parse the user-submitted routing specifications, which are in the format:
            [interface|IPaddress(v4/v6)][:src-port][$downlink:uplink]
            The interface/IP/port are used for binding the socket and determining
            the protocol-version of the socket.
            The uplink/downlink are saved and the downlink gets transmitted to the
            server, the uplink gets used by the LoadbalancerClientControl for 
            weighted balancing
        """

        if '=' in routing_spec:
            try:
                routing_spec, weights = routing_spec.rsplit('=', 1)
                downlink, uplink = weights.split(':')
                self.weight_downlink, self.weight = int(downlink), int(uplink)
                
            except Exception as e:
                logging.exception('Error parsing weight specifications "{}": {}'.format(weights, e.strerror))
        else:
            self.weight_downlink, self.weight_uplink = 1,1

        # Test if there is an interface with that name
        interfaces = netifaces.interfaces()
        if ':' in routing_spec and routing_spec not in interfaces:
            # So either ipv6 or interface/ipv4/ipv6:port
            try:
                socket.inet_pton(socket.AF_INET6, routing_spec)
                ip_addr, port = routing_spec, 0
            except socket.error:
                # not ipv6, so interface/ipv4/ipv6:port
                interface_name, port = routing_spec.split(':')
                port = int(port)
                try:
                    socket.inet_pton(socket.AF_INET6, interface_name)
                    ip_addr = interface_name
                except socket.error:
                    # not ipv6, so ipv4 or interface-name
                    if re.match(regex_ipv4, interface_name):
                        ip_addr = interface_name
                    else:
                        ip_addr = self.get_ip_addr_from_interface(interface_name)
        else:
            # ':' is not there or it is a subinterface/strange-name
            port = 0
            if re.match(regex_ipv4, routing_spec):
                ip_addr = routing_spec
            else:
                ip_addr = self.get_ip_addr_from_interface(routing_spec)
                if not ip_addr:
                    logging.error('Cannot bind to specified interface "{}", has no address!'.format(routing_spec))
                    raise socket.error()
                        
        try:
            socket.inet_pton(socket.AF_INET6, ip_addr)
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        except:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self._addr = (ip_addr, port)
        self._repr = '{}:{}'.format(ip_addr, port)

        return sock
    
    def get_ip_addr_from_interface(self, interface):
        try:
            if_ = netifaces.ifaddresses(interface)
        except:
            return
        
        # Find first address we can find (either v4 or v6)
        for addr_ip4 in if_.get(2,{}):
            if 'addr' in addr_ip4:
                return addr_ip4['addr']
        for addr_ip6 in if_.get(10,{}):
            if 'addr' in addr_ip6:
                return addr_ip6['addr']

    def loadbalancer_bind(self):
        """ bind to the interface and the specified port (or random) """

        try:
            self.bind(self._addr)
            logging.debug('Bound to {}:{}'.format(*self.addr))
        except IOError as e:
            logging.exception('Exception when binding loadbalancer to {}: |{}|'.format(repr(self._addr), e.strerror))
            return
        
    def handle_close(self):
        """ Empty buffer, close and remove from pool """
        self.out_buffer = []
        self.close()
        self.timer.stop()
        if self in self.control.loadbalancing_pool:
            self.control.loadbalancing_pool.remove(self)
        logging.info('{} Closed'.format(repr(self)))

class LoadbalancerServer(dispatcher_with_addr):
    """ Helper class to spawn server-loadbalancers for connecting client-loadbalancers """

    def __init__(self, control):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dispatcher_with_addr.__init__(self, sock, control)

        self.bind(('0.0.0.0', control.port))
        self._repr = '{}:{}'.format(*self.addr)
        logging.debug('Waiting for clients on {}'.format(self._repr))


    def handle_read(self):
        """ Read received data and write to tun/tap device.

        If the source of the data is unknown, create a Client for it, if authorization succeeds"""
        data, addr = self.recvfrom(4096)
        if not data:
            return
        
        # write to device and return, if the source-addr is already known
        for item in self.control.loadbalancing_pool:
            if item.addr == addr:
                logging.debug('Reading {}b packet from {}'.format(len(data), repr(addr)))
                item.timer.reset()
                self.control.write(data)
                return
    
        logging.info('New client incoming from {}'.format(repr(addr)))
        new_client = Client(addr, data, self.control)
        if new_client.authorized:
            logging.info('\tAuth successfull from {}'.format(repr(addr)))
            self.control.loadbalancing_pool.append(new_client)
    
    def handle_close(self):
        """ Empty buffer, close and remove from pool """
        self.out_buffer = []
        self.close()
        logging.info('{} Closed'.format(repr(self)))


class Client():
    """ Struct for the server to store the client addresses and configurations in.

    Handles authorization and stores the address and the weight."""
    def __init__(self, addr, data, control):
        self.addr = addr
        self.control = control
        self.authorized, data = self.authorize(data)
        if not self.authorized:
            return
        self.weight = int(data[:3]) if data[:3].isdigit() else 1
        self.timer = resettableTimer(30, self.handle_close)

    def authorize(self, data):
        """ Check the passphrases """
        auth, remaining = data[:len(self.control.secret)], data[len(self.control.secret):]
        if auth != self.control.secret:
            #self.control.loadbalancer.send('403 unauthorized!', self.addr)
            return False, remaining
        return True, remaining

    def handle_close(self):
        self.control.loadbalancing_pool.remove(self)
        if self.timer.is_running:
            self.timer.stop()
        
    def send(self, packet, destination=None):
        """ Send via loadbalancer """
        # Destination-argument is for compatebility with the LoadbalancerClient
        self.control.loadbalancer.send(packet, self.addr)
        
    def __repr__(self):
        return "Client:{}:{}".format(*self.addr)

class LoadbalancerControl(asyncore.file_dispatcher):
    """ Base Class of the Loadbalancing. Handles the tun/tap-device and spawns loadbalancers."""
    
    def __init__(self, options={}):
        self.shutdown = False           # Loadbalancers shouldn't reconnect
        self.buffer = []
        self.loadbalancing_pool = []
        self.rr = 0                     # RoundRobin iterator counter
        self.weighted_rr_queue = []     # Weighted RoundRobin queue
        
        self.secret = options.get('secret','')
        self.port = options.get('port',11111)
        mode = options.get('mode','rr')
        if mode not in self.available_modes.keys():
            logging.error('Unknown Mode "{}"!'.format(mode))
        self.balancing_mode = self.available_modes.get(mode, 'rr')
        
        _tap = options.get('tap', True)
        _name = options.get('name', '')
        _mtu = 1496-28-200
        self.dev = TapDevice(tap=_tap, name=_name)
        self.dev.ifconfig(mtu=_mtu)

        asyncore.file_dispatcher.__init__(self, self.dev.getFD())

        self.dev.up()
        if options.get('tunnel_address', False):
            self.dev.ifconfig(address=options.get('tunnel_address'))

        logging.debug('Interface ready')

    def eth_addr (self, a) :
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
        return b

    def validate(self, data):
        eth_length = 14
         
        eth_header = data[:eth_length]
        eth = struct.unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
#        print 'Destination MAC : ' + self.eth_addr(data[0:6]) + ' Source MAC : ' + self.eth_addr(data[6:12]) + ' Protocol : ' + str(eth_protocol)

        ip_header = data[eth_length:20+eth_length]
        iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
        version_ihl = iph[0]
        ihl = version_ihl & 0xF

        iph_length = ihl * 4
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

#        udp_header = data[iph_length+eth_length:iph_length+20+eth_length]
#        udph = struct.unpack('!HHLLBBHHH' , udp_header)
#        print "[{}] - {}:{} -> {}:{}".format(protocol, s_addr,udph[0], d_addr,udph[1])

    def writable(self):
        return len(self.buffer) > 0

    def handle_write(self):
        """ Write local buffer to interface """
        try:
            if len(self.buffer) == 0:
                return
            packet = self.buffer.pop()
            logging.debug('\tWriting {}byte packet to device'.format(len(packet)))
            self.dev.write(packet)
        except OSError as e:
            if e.errno == 22:
                # Invalid packet
                logging.debug('\tFailed to write invalid packet "{}"'.format(packet))
            else:
                logging.exception('\tWriting "{}" to device caused exception: {}'.format(packet, e.strerror))
        except Exception as e:
            logging.exception('\tWriting "{}" to device caused exception: {}'.format(packet, e.strerror))

    def write(self, packet):
        """ Store received packets from loadbalancers to local buffer """
        if packet:
#            self.validate(packet)
            self.buffer.append(packet)

    def handle_read_event(self):
        """ Balance received packets to loadbalancers """
        packet = self.dev.read()
        self.balancing_mode(self, packet)

    def balance_data_round_robin(self, packet):
        """ Use Round Robin to distribute each packet via revolving loadbalancers """
        if len(self.loadbalancing_pool) == 0:
            return
        
#        logging.debug('Sending {}byte packet via {}'.format(len(packet), repr(self.loadbalancing_pool[self.rr])))
        try:
            self.loadbalancing_pool[self.rr].send(packet, self.destination)
        except Exception as e:
            raise e
            logging.exception('Error {} while sending {}b data via Loadbalancer_{}'.format(e.strerror, len(packet), self.rr))
            
        self.rr = self.rr+1 if self.rr < len(self.loadbalancing_pool)-1 else 0

    def balance_data_weighted_round_robin(self, packet):
        """ Use Round Robin to distribute each packet via revolving loadbalancers """
        if len(self.loadbalancing_pool) == 0:
            return
        
        if len(self.weighted_rr_queue) == 0:
            for lb in self.loadbalancing_pool:
                for _ in range(lb.weight):
                    self.weighted_rr_queue.append(lb)
                    
        current = self.weighted_rr_queue.pop(0)
        logging.debug('Sending {}byte packet via {}'.format(len(packet), repr(current)))
        
        try:
            current.send(packet, self.destination)
        except Exception as e:
            logging.exception('Error {} while sending {}b data via Loadbalancer_{}'.format(e.strerror, len(packet), current))
            
        if len(self.weighted_rr_queue) > 0 and self.weighted_rr_queue[0] != current:
            for i in range(current.weight):
                self.weighted_rr_queue.append(current)
                
    available_modes = {'rr':balance_data_round_robin,
                       'wrr':balance_data_weighted_round_robin,
                      }
    def quit(self):
        """ Gracefully close all loadbalancers and self """
        self.shutdown = True
        logging.debug('Closing loadbalancers...')
        # Loadbalancer modifies the pool in close, so make a static list
        for item in list(self.loadbalancing_pool):
            item.handle_close()

        if len(self.loadbalancing_pool) > 0:
            logging.debug('Waiting for loadbalancers to close...')
            for i in range(5):
                if len(self.loadbalancing_pool) == 0:
                    break
                time.sleep(1)
            else:
                for item in self.loadbalancing_pool:
                    item.handle_close()
                    del item

        logging.debug('Closing self...')
        self.dev.close()

class LoadbalancerClientControl(LoadbalancerControl):
    """ Spawns as many loadbalancers as requested and forward data in between"""

    def __init__(self, destination, routing_specifications, options):
        LoadbalancerControl.__init__(self, options)

        # Use default port, if none specified
        if not ":" in destination:
            self.destination = (destination, self.port)
        else:
            self.destination = destination.rsplit(':',1)

        # Is destination a v6-address?
        try:
            socket.inet_pton(socket.AF_INET6, self.destination[0])
            self.set_socket(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
        except:
            self.set_socket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))


        for routing_specs in routing_specifications:
            self.assign_loadbalancer_to_specs(routing_specs)

    def assign_loadbalancer_to_specs(self, routing_specs):
        """ Build a loadbalancer, which binds to the specified interface address """
        logging.debug('Building Loadbalancer for {}'.format(routing_specs))
        self.loadbalancing_pool.append(LoadbalancerClient(self, routing_specs))

class LoadbalancerServerControl(LoadbalancerControl):
    destination = None
    def __init__(self, options):
        LoadbalancerControl.__init__(self, options)

        self.loadbalancer = LoadbalancerServer(self)

if __name__ == '__main__':
    import argparse
    argparser = argparse.ArgumentParser(description="Creates a tun/tap device, which sends packets via multiple interfaces to a corresponding server. This is an implementation of link aggregation / bonding, except with a dynamic distribution algorithm, allowing for example for weighted interfaces.", epilog="Created and Maintained by Kai Sisterhenn under GPLv3, sistason@sistason.de")
    argparser.add_argument('--remote', '-r', help='Run as client, connecting to specified destination IP')
    argparser.add_argument('routing', nargs='*', help='Bind to specific sources by setting [interface/IPaddress][:port] and add [=downlink:uplink] to balance the traffic (client option).')
    argparser.add_argument('--port', '-p', type=int, default=11111, help='Set the port on which to connect to / listen on')
    # TODO: to two-factor-authentication
    argparser.add_argument('--secret','-s',  help='Set a passphrase to authenticate connecting clients. Will stop accidental usage by other programs, but is transmitted trivially in the clear, so don\'t think it does security.')
    argparser.add_argument('--name', '-n',  help='Name of the tap/tun device', default='')
    argparser.add_argument('--tun', '-t',  type=bool, help='Use a tun device instead of a tap device', default=False)
    argparser.add_argument('--address', '-a', help='Address of the tun/tap device')
    argparser.add_argument('--mode', '-m', choices=LoadbalancerControl.available_modes.keys(), default='rr', help='Balancing Mode')
    argparser.add_argument('--verbose', '-v', action='count', help='Be more verbose', default=0)
    argparser.add_argument('--quiet', '-q', action='count', help='Be less verbose', default=0)

    p=vars(argparser.parse_args())
    
    destination = p['remote']
    routings = p['routing']
    options = {'port':p['port'], 'secret':p['secret'], 'name':p['name'], 'tap':not p['tun'], 'tunnel_address':p['address'], 'mode':p['mode']}

    loglevel_ = 20 - p['verbose']*10 + p['quiet']*10
    logging.basicConfig(format='%(asctime)s - %(message)s', datefmt='%H:%M:%S', level=loglevel_)

    if destination:
        loadbalancer = LoadbalancerClientControl(destination, routings, options)
    else:
        loadbalancer = LoadbalancerServerControl(options)
    
    try:
        asyncore.loop()
    except Exception as e:
        logging.exception(e)
    finally:
        loadbalancer.quit()
