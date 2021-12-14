# Docker_implemented_Text-based Chats - SDN 

## This is the implemetation and documentation for implenemting Network Slicing through RYU SDN controller in SDN data plane in Containernet emulator for Mobile Computing project

### The followings is the architectural overview of SDN network implementation and Security Testing of Data Plane with SNORT IDs.

In this experiment, six Open vSwitch (OVS) is used to build the core network and three other switches used for
providing access network to the data centre and to host machines. The given figure is the network topology for slicing the network.


![ryu](https://user-images.githubusercontent.com/57096728/145975643-7b7f7a0c-4182-42b4-a3d4-18202eca5675.JPG)


DPID with 7, 8 is being used to provided access service to the different host machines and DPID with 9 is assumed as
Data centre. The core switches DPID with 1 and 2 is connect with switches DPID with 7 and 8 respectively. In the Data centre area core switch with DPID 5 is connected to the switch DPID 9.

The motive of this topology is to make two slices. In slice 1 consists of h1 (Host 1 where mac ends with 11), h2
(Host 2 where mac ends with 12) and d1(Data centre service 1 where mac ends with 13) and in slice 2 consists
of h3, h4, h5. Slice 1 devices or services can only communicate each other which is totally independent from
slice 2 devices or services. This method is also applicable for slice 2. All the host machines are in docker container with pre-installed client chat service and data centre machines which is also in docker container preinstalled text-based chat server for providing chat service to the clients.

***Two Extension of this project is measured.***
All the iplemented file will be found in **Project_work_extension** folder.

One extension is, before the improvement the slicing has been happened only on one application like for chatting only within the hosts. But after the improvement slicing now can be done service based. Both chatting application service and file server application service is in two different slices. For instance, now hosts
in slice 1 only can get the service of chatting and hosts in slice 2 can only reach for the
service of file server application. Moreover, experimental testing has been done for slicing on
the basis on ICMP protocol and TCP protocol. SDN Application for this case is in **'slicing_application_ryu_controller.py'** in **‘project_ryu’** folder.

Another extension is to implement security testing within this SDN network. To enhance the scenario,  an approach has been taken to detect and mitigate DDoS
attack with ping flooding and TCP syn-ack flooding. Here, an open source IDS called snort has
been used to detect the attack which then alert RYU controller. RYU controller then takes
necessary steps to drop all the packets from that specific attacker. For executing this scenario
slight change has been brought in the topology, where in access switch of data centre, a host
has been included as a snort IDS. The below figure presents the updated topology after using SNORT IDS.

![Presentation](https://user-images.githubusercontent.com/57096728/145975613-861789a0-2c36-448f-bf31-596b71078f55.jpg)

This topology file has been found named **‘topo_with_ryu_snort.py’** in **‘project_ryu’** folder. Moreover, RYU controller application is also updated to take care of this scenario. For designing RYU controller application for this scenario, all the traffic coming to data centre
access switch have been mirrored to snort IDS port for monitoring. So, whenever any alert
comes from snort IDS, RYU controller just drops all packet considering attacker’s source IP
address with much higher priority. This RYU application file has been found named
**‘slicing_application_ryu_controller_with_snort.py’** in **‘project_ryu’** folder. For the ruleset and
thresholding snort IDS, files can be found in **‘project_ryu/ snort_rules_thresold’** folder with the
name of **‘local.rules’** and **‘threshold.conf’** respectively. 



For the Implementation of the network check the documentation: [Project Documentation](https://github.com/sudo-riyad/RYU-SDN-contoller-in-CORE/blob/cc64d009d620c4626b2264d7d2c1c59770244a85/Documentation/IndividualProject_Islam_Riyad-Ul-_1324662.pdf)
