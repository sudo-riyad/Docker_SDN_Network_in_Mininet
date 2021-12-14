#!/usr/bin/python

from mininet.net import Containernet
from mininet.node import Controller,Docker, OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
setLogLevel('info')

net = Containernet(controller=RemoteController)

info('*** Adding controller\n')
# c0=net.addController('c0', controller=RemoteController, port= 6660)
# c1=net.addController('c1', controller=RemoteController)
# c2=net.addController('c2', controller=RemoteController)
c3=net.addController('c3', controller=RemoteController)
info('*** Adding docker containers host and server\n')

#In containernet Run xterm h1(eg:host) or xterm d1 (eg:Data center)
# In server machine run command(python3 server.py 10.0.1.3(note: ip address of specific data center) )
# In client machine at first run command(python3 chat_client.py 10.1.0.7(note: ip address of specific data center) -p 1060 )
# as in client there is no display so there will be a known error while opening tkinter, please ignore that and type something and get chat in cli.
# Quit from chat write QUIT

client_image="client:latest"
server_image="server:latest"

h1 = net.addDocker('h1', ip='10.0.1.1/24',mac="00:00:00:00:00:11",dimage=client_image)
h2 = net.addDocker('h2', ip='10.0.1.2/24',mac="00:00:00:00:00:12", dimage=client_image)

d1 = net.addDocker('d1', ip='10.0.1.3/24',mac="00:00:00:00:00:13", dimage=server_image)
d1.cmd("sh /usr/sbin/entrypoint.sh")

h4 = net.addDocker('h4', ip='10.0.1.4/24', mac="00:00:00:00:00:14", dimage=client_image)
h5 = net.addDocker('h5', ip='10.0.1.5/24', mac="00:00:00:00:00:15", dimage=client_image)

d2 = net.addDocker('d2', ip='10.0.1.6/24', mac="00:00:00:00:00:16", dimage=server_image)
d2.cmd("sh /usr/sbin/entrypoint.sh")
info('*** run server \n')

info('*** Adding switches\n')
s1 = net.addSwitch("s1")
s2 = net.addSwitch("s2")
s3 = net.addSwitch("s3")
s4 = net.addSwitch("s4")
s5 = net.addSwitch("s5")
s6 = net.addSwitch('s6')
s7 = net.addSwitch('s7', cls=OVSSwitch)
s8 = net.addSwitch('s8', cls=OVSSwitch)
s9 = net.addSwitch('s9', cls=OVSSwitch)
info('*** Creating links\n')

net.addLink(s1,s7)
net.addLink(s2,s8)
net.addLink(s5,s9)



net.addLink(s1, s2, 2, 2)
net.addLink(s1, s3, 3, 1)
net.addLink(s2, s4, 4, 2)
net.addLink(s3, s5, 4, 3)
net.addLink(s2, s3, 3, 2)
net.addLink(s4, s5, 1, 4)
net.addLink(s6, s1, 1, 4)
net.addLink(s6, s2, 2, 5)
net.addLink(s6, s3, 3, 3)
net.addLink(s6, s4, 4, 3)
net.addLink(s6, s5, 5, 2)



net.addLink(h1,s7)
net.addLink(h2,s8)
net.addLink(d1,s9)

net.addLink(h4,s7)
net.addLink(h5,s8)
net.addLink(d2,s9)
# d1.cmd("python3 server.py 10.0.1.3 -p 1060")
# d2.cmd("python3 server.py 10.0.1.6 -p 1060")

info('*** Starting network\n')
net.start()


info('*** Testing connectivity\n')
net.pingAll(timeout= 1)
info('*** Running CLI\n')
CLI(net)

info('*** Stopping network')
net.stop()
