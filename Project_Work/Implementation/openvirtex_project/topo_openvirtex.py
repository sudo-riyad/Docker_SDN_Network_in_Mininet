#!/usr/bin/python


from mininet.net import Containernet
from mininet.node import Controller,Docker, OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
setLogLevel('info')

net = Containernet(controller=RemoteController)
info('*** Adding controller\n')
#please change the ip with the ip address of OpenVirtex of your machine
ip='192.168.1.125'
port=6633
c3=net.addController('c3', controller=RemoteController , ip =ip ,port=port)
c2=net.addController('c2', controller=RemoteController)
info('*** creating switchs\n')
s1 = net.addSwitch("s1",dpid='0000000000001000')
s2 = net.addSwitch("s2",dpid='0000000000002000')
s4 = net.addSwitch("s4",dpid='0000000000004000')
s5 = net.addSwitch("s5",dpid='0000000000005000')
s6 = net.addSwitch('s6',dpid='0000000000006000')
s7 = net.addSwitch('s7',dpid='0000000000007000')
s8 = net.addSwitch('s8',dpid='0000000000008000')
s9 = net.addSwitch('s9',dpid='0000000000009000')
s10 = net.addSwitch('s10',dpid='0000000000000001')
s11 = net.addSwitch('s11',dpid='0000000000000002')
s12 = net.addSwitch('s12',dpid='0000000000000003')



info('*** Adding docker containers Data center and Hosts \n')

#In containernet Run xterm h1(eg:host) or xterm d1 (eg:Data center)
# In server machine run command(python3 server.py 10.1.0.7(note: ip address of specific data center) )
# In client machine at first run command(python3 chat_client.py 10.1.0.7(note: ip address of specific data center) -p 1060 )
# as in client there is no display so there will be a known error while opening tkinter, please ignore that and type something and get chat in cli.
# Quit from chat write QUIT

client_image="client:latest"
server_image="server:latest"

h1 = net.addDocker('h1', ip='10.0.1.1',mac="00:00:00:00:00:11",dimage=client_image)
h3 = net.addDocker('h3', ip='10.0.3.3',mac="00:00:00:00:00:13", dimage=client_image)

h2 = net.addDocker('h2', ip='10.0.2.2',mac="00:00:00:00:00:12", dimage=client_image)
h4 = net.addDocker('h4', ip='10.0.4.4',mac="00:00:00:00:00:14", dimage=client_image)

d1 = net.addDocker('d1', ip='10.1.0.7',mac="00:00:00:00:00:01", dimage=server_image)
d2 = net.addDocker('d2', ip='10.2.0.7',mac="00:00:00:00:00:02", dimage=server_image)
d4 = net.addDocker('d4', ip='10.4.0.7',mac="00:00:00:00:00:04", dimage=server_image)
d5 = net.addDocker('d5', ip='10.5.0.7',mac="00:00:00:00:00:05", dimage=server_image)


info( '*** Add links\n')
net.addLink(s1, h1,1)
net.addLink(s1, h3,2)
net.addLink(h2, s2,1)
net.addLink(h4, s2,2)
net.addLink(s8, h3,1)


net.addLink(s4, d4,1)
net.addLink(d1, s9,1)
net.addLink(d2, s9,2)
net.addLink(d5, s5,1)


net.addLink(s10, s11)
net.addLink(s10, s5)
net.addLink(s5, s6)
net.addLink(s11, s6)
net.addLink(s11, s12)
net.addLink(s6, s12)
net.addLink(s12, s4)
net.addLink(s4, s8)
net.addLink(s8, s7)
net.addLink(s7, s9)
net.addLink(s7, s6)
net.addLink(s9, s5)
net.addLink(s1, s10)
net.addLink(s2, s11)



info('*** Starting network\n')
net.start()
info('*** Testing connectivity\n')
#net.ping([server, d2])
net.pingAll(timeout= 1)
info('*** Running CLI\n')
CLI(net)
info('*** Stopping network')
net.stop()
