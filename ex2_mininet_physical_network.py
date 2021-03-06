#!/usr/bin/python
#place this script under ~ (home folder) - run it whenever you want to test your pyretic code
#how to run: sudo python ex2_mininet_physical_network.py
from mininet.topo import SingleSwitchTopo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.node import RemoteController
from mininet.cli import CLI

#author: Vasileios Kotronis

def createEx2Network():
    '''Topology for exercise 2: two networks (one internal
    and one external), belonging to different IP subnets,
    connected over a physical OpenFlow switch. This switch
    is also connected to a black-hole host for DoS traffic offloading'''
   
    topo = SingleSwitchTopo(k=8) #one host at external, 6 hosts at internal
                                #(2 servers and 4 end-hosts), 1 black-hole host
    net = Mininet(topo, controller=lambda name: RemoteController('c0', "127.0.0.1"), autoSetMacs=True)
    net.start()
    hosts=net.hosts
    print "Configuring hosts (IPs, applications, etc.)"
    for host in hosts:
        if host.name == 'h1': #host 1 of internal network 
            host.cmd('ifconfig h1-eth0 10.1.1.2 netmask 255.255.255.0 up')
            host.cmd('route add default gw 10.1.1.1')
            print "Host 1 of internal network configured"
        if host.name == 'h2': #host 2 of internal network
            host.cmd('ifconfig h2-eth0 10.1.1.3 netmask 255.255.255.0 up')
            host.cmd('route add default gw 10.1.1.1')
            print "Host 2 of internal network configured"
        if host.name == 'h3': #host 3 of internal network
            host.cmd('ifconfig h3-eth0 10.1.1.4 netmask 255.255.255.0 up')
            host.cmd('route add default gw 10.1.1.1')
            print "Host 3 of internal network configured"
        if host.name == 'h4': #host 4 of internal network
           host.cmd('ifconfig h4-eth0 10.1.1.5 netmask 255.255.255.0 up')
           host.cmd('route add default gw 10.1.1.1')
           print "Host 4 of internal network configured"
        if host.name == 'h5': #ssh server (DMZ of internal network)
           host.cmd('ifconfig h5-eth0 10.1.1.6 netmask 255.255.255.0 up')
           host.cmd('route add default gw 10.1.1.1')
           host.cmd('/etc/init.d/ssh restart')
           print "SSH server of DMZ configured (host 5)"
        if host.name == 'h6': #http server (DMZ of internal network)
           host.cmd('ifconfig h6-eth0 10.1.1.7 netmask 255.255.255.0 up')
           host.cmd('route add default gw 10.1.1.1')
           host.cmd('/etc/init.d/apache2 restart')
           print "Apache HTTP server of DMZ configured (host 6)"
        if host.name == 'h7': #"Internet"
            host.cmd('ifconfig h7-eth0 10.1.2.2 netmask 255.255.255.0 up')
            for i in range(2,254):
                host.cmd('ifconfig h7-eth0:%s 10.1.2.%s netmask 255.255.255.0 up' % (str(i), str(i+1)))
            host.cmd('route add default gw 10.1.2.1')
            print 'Emulated "Internet" configured (host 7)'
        if host.name == 'h8': #black-hole host
            host.cmd('ifconfig h8-eth0 0.0.0.0 up')
            print 'Emulated "Black hole" configured (host 8)'
    CLI(net) #invoke CLI
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    createEx2Network()
