dmpt - dynamic multipath tunnel
=====================

Tunnels IP-traffic via multiple tcp-connections. The point is that the connections use different paths, so the bandwidth or stability of the paths gets combined. Unlike the bonding kernel module, the dmpt can do weighted link aggregation, so you can theoretically combine the bandwidth of all links linearly.

Practical Use: Combine your DSL and your LTE to get their combined speed, uplink and downlink!

Also, if you like where this is going, academically, check out [socket-intents](https://github.com/fg-inet/socket-intents).

Function
========
1. Creates a tun/tap-device
2. The client starts tcp-workers (asyncore.dispatcher_with_send), who bind and connect to the server
3. All traffic through the tun/tap-device will be distributed via the tcp-workers to a server running dmpt
4. On the server, the traffic will be collected and send via a tun/tap-device
5. And vice-versa



Dependencies
============
* Python 2.7
* Python-modules: [python-netifaces](https://pypi.python.org/pypi/netifaces), pytap (part of [ether2any](git://git.someserver.de/seba/ether2any)


Usage
=====
Start as server on your endpoint and as client on your startpoint, with as many paths as needed.
Paths can be specified on the client as interfaces/IP-addresses plus optionally ports, where the tcp-connections to the server bind to. That way, the routing will use different paths for the traffic.
The example shell script shows how to do that based on source-ports.
