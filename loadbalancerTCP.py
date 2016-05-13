#!/usr/bin/env python
# -*- encoding: utf-8 -*-
import time
import struct
import socket
import asyncore, sys
import logging

from pytap import TapDevice
import netifaces

import re
regex_ipv4 = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')

class Loadbalancer(asyncore.dispatcher):
    out_buffer = []

    def __init__(self, sock, control):
        asyncore.dispatcher.__init__(self, sock)
        if self.socket:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
#            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
            self.set_reuse_addr()
        self.control = control
        self.port = control.port

    def initiate_send(self):
        packet = self.out_buffer.pop() if len(self.out_buffer) else ''
        logging.debug('Sending {}b packet  to  loadbalancing'.format(len(packet)))
        while len(packet) > 0:
            num_sent = asyncore.dispatcher.send(self, packet)
            logging.debug('\t {}b sent'.format(num_sent))
            if num_sent == 0:
                break
            packet = packet[num_sent:]

    def writable(self):
        return (not self.connected) or len(self.out_buffer)

    def handle_read(self):
        """ Everything read goes into the device """
        data = self.recv(8192)
        if data:
            logging.debug('Reading {}b packet from loadbalancing'.format(len(data)))
            self.control.write(data)

    def send(self, data):
        logging.debug('\tAdding {}b packet  to  buffer'.format(len(data)))
        self.out_buffer.append(data)
        self.initiate_send()


# NOTE: dispatcher already connects before send, when disconnected, right?
#    def send(self, data):
#        """ Wrap the builtin send with a reconnector """
#        try:
#            asyncore.dispatcher_with_send.send(self, data)
#        except socket.error as e:
#            if e.errno == 32:
#                self.loadbalancer_connect()
#            else:
#                logging.exception("{} - Could not send data because: {}".format(self, e.strerror))

    def handle_close(self):
        """ Empty buffer and close """
        self.out_buffer = []
        self.close()
        if self in self.control.loadbalancer_pool:
            self.control.loadbalancer_pool.remove(self)
        logging.info('{} Closed'.format(repr(self)))

    def __repr__(self):
        try:
            return 'Loadbalancer:{}'.format(self.addr[-1])
        except:
            return 'Loadbalancer:<unbound>'

class LoadbalancerServer(Loadbalancer):
    def handle_read(self):
        """ Check for auth before first read """
        data = self.recv(8192)
        if data:
            self.control.write(self.authorize(data))

    def authorize(self, data):
        """ Do authentication """
        if data[:len(self.control.secret)] != self.control.secret:
            self.send('403 unauthorized!')
            self.close()
            return
        # If auth is successfull, replace with the normal read func
        self.handle_read = lambda: Loadbalancer.handle_read(self)
        return data[len(self.control.secret):]
        

class LoadbalancerClient(Loadbalancer):
    def __init__(self, control, interface_spec):
        sock = self.parse_interface_spec(interface_spec)
        Loadbalancer.__init__(self, sock, control)
        self.setup()

    def authorize(self):
        """ Do authentication """
        self.send(self.control.secret)

    def parse_interface_spec(self, interface_spec):
        """ Parse interface_spec and make socket accordingly. """

        # Test if there is an interface with that name
        interfaces = netifaces.interfaces()
        if ':' in interface_spec and interface_spec not in interfaces:
            # So either ipv6 or interface/ipv4/ipv6:port
            try:
                socket.inet_pton(socket.AF_INET6, interface_spec)
                ip_addr, port = interface_spec, 0
            except socket.error:
                # not ipv6, so interface/ipv4/ipv6:port
                interface_name, port = interface_spec.split(':')
                port = int(port)
                try:
                    socket.inet_pton(socket.AF_INET6, interface_name)
                    ip_addr = interface_name
                except socket.error:
                    # not ipv6, so ipv4 or interface-name
                    if re.match(regex_ipv4, interface_name):
                        ip_addr = interface_name
                    else:
                        ip_addr = get_ip_address(interface_name, self.socket)
        else:
            # ':' is not there or it is a subinterface/strange-name
            port = 0
            if re.match(regex_ipv4, interface_spec):
                ip = interface_spec
            else:
                if_ = netifaces.ifaddresses(interface_spec)
                # Find first address we can find (either v4 or v6)
                for addr_family,addrs in if_.items():
                    for addr in addrs:
                        if 'addr' in addr:
                            ip_addr = addr['addr']
                            break
                else:
                    logging.error('Cannot bind to specified interface "{}", has no address!'.format(interface_spec))
                    raise socket.error()
                        
        try:
            socket.inet_pton(socket.AF_INET6, ip_addr)
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        except:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self._addr = (ip_addr, port)

        return sock

    def setup(self):
        """ Bind and connect """

        self.loadbalancer_bind()
        # Connect and authorize
        self.connect((self.control.destination, self.control.port))

    def loadbalancer_bind(self):
        """ bind to the interface and the specified port (or random) """

        try:
            self.bind(self._addr)
            logging.debug('Bound to {}:{}'.format(*self.addr))
        except IOError as e:
            logging.exception('Exception when binding loadbalancer to {}: |{}|'.format(repr(self._addr), e.strerror))
            return

    def handle_connect(self):
        """ Authorize afterwards"""
        self.authorize()


class LoadbalancerControl(asyncore.file_dispatcher):
    shutdown = False    # Loadbalancers shouldn't reconnect
    rr = 0              # RoundRobin iterator counter

    def __init__(self, options={}):
        self.secret = options.get('secret','')
        self.port = options.get('port',11111)
        self.buffer = []
        self.loadbalancer_pool = []

        _tap = options.get('tap', True)
        _name = options.get('name', '')
        self.dev = TapDevice(tap=_tap, name=_name)

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
            packet = self.buffer.pop()
            logging.debug('Writing {}byte packet to device'.format(len(packet)))
            self.dev.write(packet)
        except IndexError:
            pass
        except OSError as e:
            if e.errno == 22:
                # Invalid packet
                logging.debug('Failed to write invalid packet "{}"'.format(packet))
            else:
                logging.exception('Writing "{}" to device caused exception: {}'.format(packet, e.strerror))
        except Exception as e:
            logging.exception('Writing "{}" to device caused exception: {}'.format(packet, e.strerror))

    def write(self, packet):
        """ Forward data from loadbalancers to local buffer """
        if packet:
#            self.validate(packet)
            self.buffer.append(packet)

    def handle_read_event(self):
        """ Forward received packets to loadbalancers """
        packet = self.dev.read()
        self.balance_data_round_robin(packet)

    def balance_data_round_robin(self, packet):
        """ Use Round Robin to distribute each packet via revolving loadbalancers """
        if len(self.loadbalancer_pool) == 0:
            return
        
#        logging.debug('Sending {}byte packet via {}'.format(len(packet), repr(self.loadbalancer_pool[self.rr])))
        self.loadbalancer_pool[self.rr].send(packet)
        self.rr = self.rr+1 if self.rr < len(self.loadbalancer_pool)-1 else 0

    def quit(self):
        """ Gracefully close all loadbalancers and self """
        self.shutdown = True
        logging.debug('Closing loadbalancers...')
        # Loadbalancer modifies the pool in close, so make a static list
        for s in list(self.loadbalancer_pool):
            s.handle_close()

        if self.loadbalancer_pool:
            logging.debug('Waiting for loadbalancers to close...')
            for i in range(5):
                if len(self.loadbalancer_pool) == 0:
                    break
                time.sleep(1)
            else:
                for s in self.loadbalancer_pool:
                    s.close()
                    del s

        logging.debug('Closing self...')
        self.dev.close()

class LoadbalancerClientControl(LoadbalancerControl):

    def __init__(self, destination, interfaces, options):
        LoadbalancerControl.__init__(self, options)

        self.destination = destination
        for interface_specs in interfaces:
            self.assign_loadbalancer_to_interface(interface_specs)

    def assign_loadbalancer_to_interface(self, interface_specs):
        """ Build a loadbalancer, which binds to the specified interface address """
        logging.debug('Building Loadbalancer for {}'.format(interface_specs))
        balancer = LoadbalancerClient(self, interface_specs)
        self.loadbalancer_pool.append(balancer)

class LoadbalancerServerControlHelper(asyncore.dispatcher):
    """ Helper class to spawn server-loadbalancers for connecting client-loadbalancers """
    def __init__(self, control):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()

        self.bind(('0.0.0.0', control.port))
        self.listen(10)

        self.control = control
        logging.debug('Waiting for connections on {}:{}'.format(*self.socket.getsockname()))

    def readable(self): return True
    def writable(self): return True

    def handle_accept(self):
        """ Spawn a many loadbalancer as the client brings """
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            logging.info('Incoming connection from {}'.format(repr(addr)))

            handler = LoadbalancerServer(sock, self.control)
            self.control.loadbalancer_pool.append(handler)

class LoadbalancerServerControl(LoadbalancerControl):
    def __init__(self, options):
        LoadbalancerControl.__init__(self, options)
        
        self.helper = LoadbalancerServerControlHelper(self)
        


if __name__ == '__main__':
    import argparse
    argparser = argparse.ArgumentParser(description="Creates a tun/tap device, which sends packets via multiple interfaces to a corresponding server. This is an implementation of link aggregation / bonding, except with a dynamic distribution algorithm, allowing for example for weighted interfaces.", epilog="Created and Maintained by Kai Sisterhenn under GPLv3, sistason@sistason.de")
    argparser.add_argument('--remote', '-r', help='Run as client, connecting to specified destination IP')
    argparser.add_argument('interfaces', nargs='*', help='Set the outgoing interfaces[:port], which should be used to balance the traffic (client option).')
    argparser.add_argument('--port', '-p', type=int, default=11111, help='Set the port on which to connect to / listen on')
    # TODO: to two-factor-authentication
    argparser.add_argument('--secret','-s',  help='Set a passphrase to authenticate connecting clients. Will stop accidental usage by other programs, but is transmitted trivially in the clear, so don\'t think it does security.')
    argparser.add_argument('--name', '-n',  help='Name of the tap/tun device', default='')
    argparser.add_argument('--tun', '-t',  type=bool, help='Use a tun device instead of a tap device', default=False)
    argparser.add_argument('--address', '-a', help='Address of the tun/tap device')

    p=vars(argparser.parse_args())
    
    destination = p['remote']
    interfaces = p['interfaces']
    options = {'port':p['port'], 'secret':p['secret'], 'name':p['name'], 'tap':not p['tun'], 'tunnel_address':p['address']}

    logging.basicConfig(format='%(levelname)s:%(funcName)s\t\t%(message)s', level=logging.INFO)

    if destination:
        loadbalancer = LoadbalancerClientControl(destination, interfaces, options)
    else:
        loadbalancer = LoadbalancerServerControl(options)
    
    try:
        asyncore.loop()
    except Exception as e:
        logging.exception(e)
    finally:
        loadbalancer.quit()
