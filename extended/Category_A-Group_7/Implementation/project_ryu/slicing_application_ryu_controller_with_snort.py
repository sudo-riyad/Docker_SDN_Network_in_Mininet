# Copyright (C) 2016 Li Cheng BUPT www.muzixing.com.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author:muzixing
# Time:2016/04/13
#

from __future__ import print_function

import array
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import in_proto
from ryu.lib.packet import ether_types
from ryu import utils
from ryu.lib.packet import tcp
from ryu.lib import snortlib
from ryu.topology.api import get_switch
import ryu.app.ofctl.api as ofctl_api
from ryu.lib.packet import icmp



#      # Slices 100 and 200 with their respective MAC addresses for TCP
# slices_data = [(100,"00:00:00:00:00:11","00:00:00:00:00:12","00:00:00:00:00:13",), 
#                (200,"00:00:00:00:00:14","00:00:00:00:00:15","00:00:00:00:00:16",),
#              ]
# # Slices 300 and 400 with their respective MAC addresses for ICMP
# slices_data2 = [(300,"00:00:00:00:00:11","00:00:00:00:00:15","00:00:00:00:00:16",), 
#                (400,"00:00:00:00:00:14","00:00:00:00:00:12","00:00:00:00:00:13",),
               
            #   ]
        
slices_data3 = [(500,"00:00:00:00:00:11","00:00:00:00:00:15","00:00:00:00:00:16","00:00:00:00:00:14","00:00:00:00:00:12","00:00:00:00:00:13","00:00:00:00:00:01"), 
               
              ]

slices_data4 = [(600,"00:00:00:00:00:11","00:00:00:00:00:12","00:00:00:00:00:13",1060,"00:00:00:00:00:01"), 
               (700,"00:00:00:00:00:14","00:00:00:00:00:15","00:00:00:00:00:13",21,"00:00:00:00:00:01"),
             ]
               
# slice_100=slices_data[0][1:]
# slice_200=slices_data[1][1:]

# default table is = 0
filter_table_id = 1
forward_table_id = 2


class MULTIPATH_13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        
        super(MULTIPATH_13, self).__init__(*args, **kwargs)
        self.snort = kwargs['snortlib']
        self.snort_port = 4
        self.mac_to_port = {}
        self.datapaths = {}
        self.FLAGS = True
        socket_config = {'unixsock': True}
        self.topology_api_app = self
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()
#Drop ddos packet 
    def packet_print(self, pkt,datapath):
        pkt = packet.Packet(array.array('B', pkt))

        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)

        if _icmp:
            self.logger.info("%r", _icmp)

        if _ipv4:
            _ipv4 = pkt.get_protocol(ipv4.ipv4)
            srcip=_ipv4.src
            dstip=_ipv4.dst
            self.logger.info("%r", _ipv4)
            actions = []
            
            match = datapath.ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src= srcip, ipv4_dst=dstip)
            self.add_flow(datapath,0, 100, match, actions)

        if eth:
            self.logger.info("%r", eth)

        # for p in pkt.protocols:
        #     if hasattr(p, 'protocol_name') is False:
        #         break
        #     print('p: %s' % p.protocol_name)
# Snort Alert 
    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        msg = ev.msg
        
        switch_list = get_switch(self.topology_api_app, None)
        self.switches = [switch.dp.id for switch in switch_list]
        
            
        result = ofctl_api.get_datapath(self)
        datapath = ofctl_api.get_datapath(self, self.switches[8])
        
        print('alertmsg: %s' % ''.join(msg.alertmsg))

        self.packet_print(msg.pkt,datapath)

    @set_ev_cls(
        ofp_event.EventOFPErrorMsg,
        [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.debug('OFPErrorMsg received: type=0x%02x code=0x%02x '
                          'message=%s', msg.type, msg.code,
                          utils.hex_array(msg.data))

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, 0, match, actions)
        self.logger.info("switch:%s connected", dpid)

        self.add_default_table(datapath)
        self.add_filter_table_id(datapath)
        self.apply_filter_table_id_rules(datapath)

    def add_flow(self, datapath, hard_timeout, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

       
        mod = parser.OFPFlowMod(datapath=datapath, 
                                    priority=priority,
                                    hard_timeout=hard_timeout,
                                    match=match, 
                                    table_id=forward_table_id,
                                    instructions=inst
                                   )
        datapath.send_msg(mod)
    
    def add_default_table(self, datapath):
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionGotoTable(filter_table_id)]
        mod = parser.OFPFlowMod(datapath=datapath, 
                                table_id=0, 
                                instructions=inst
                               )
        datapath.send_msg(mod)

    def add_filter_table_id(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionGotoTable(forward_table_id)]
        mod = parser.OFPFlowMod(datapath=datapath, 
                                table_id=filter_table_id, 
                                priority=1, 
                                instructions=inst
                               )
        datapath.send_msg(mod)

    def apply_filter_table_id_rules(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, 
                                ip_proto=in_proto.IPPROTO_UDP
                               )
        mod = parser.OFPFlowMod(datapath=datapath, 
                                table_id=filter_table_id,                                
                                priority=10, 
                                match=match
                               )
        datapath.send_msg(mod)

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)

    def flood(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                     ofproto.OFPP_CONTROLLER,
                                     ofproto.OFPP_FLOOD, msg.data)
        datapath.send_msg(out)
        self.logger.debug("Flooding msg")

    def arp_forwarding(self, msg, src_ip, dst_ip, eth_pkt):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        out_port = self.mac_to_port[datapath.id].get(eth_pkt.dst)
        if out_port is not None:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_pkt.dst,
                                    eth_type=eth_pkt.ethertype)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 0, 1, match, actions)
            self.send_packet_out(datapath, msg.buffer_id, in_port,
                                 out_port, msg.data)
            self.logger.debug("Reply ARP to knew host")
        else:
            self.flood(msg)

    def mac_learning(self, dpid, src_mac, in_port):
        self.mac_to_port.setdefault(dpid, {})
        if src_mac in self.mac_to_port[dpid]:
            if in_port != self.mac_to_port[dpid][src_mac]:
                return False
        else:
            self.mac_to_port[dpid][src_mac] = in_port
            return True

  
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        ip_pkt_6 = pkt.get_protocol(ipv6.ipv6)
        if isinstance(ip_pkt_6, ipv6.ipv6):
            actions = []
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IPV6)
            self.add_flow(datapath, 0, 1, match, actions)
            return

        if isinstance(arp_pkt, arp.arp):
            self.logger.debug("ARP processing")
            if self.mac_learning(dpid, eth.src, in_port) is False:
                self.logger.debug("ARP packet enter in different ports")
                return

            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip, eth)

        if isinstance(ip_pkt, ipv4.ipv4):
            
            self.logger.debug("IPV4 processing")
            mac_to_port_table = self.mac_to_port.get(dpid)
            if mac_to_port_table is None:
                self.logger.info("Dpid is not in mac_to_port")
                return

            out_port = None
            if eth.dst in mac_to_port_table:
                
                src=eth.src
                dst=eth.dst
                
                protocol = ip_pkt.proto
                out_port = mac_to_port_table[eth.dst]
                actions = [parser.OFPActionOutput(out_port)]
                actions_snort = [parser.OFPActionOutput(out_port),
                   parser.OFPActionOutput(self.snort_port)]
                
                if out_port != ofproto.OFPP_FLOOD:
                    
                    if protocol == in_proto.IPPROTO_TCP:
                        if dpid == 9:

                            _tcp = pkt.get_protocol(tcp.tcp)
                            dst_port = _tcp.dst_port
                            src_port = _tcp.src_port
                            for net_slice in slices_data4:
                                slice_id = net_slice[0]     # extract the slice ID
                                net_slice = net_slice[1:]
                                
                                if src in net_slice and dst in net_slice and (dst_port in net_slice or src_port in net_slice):
                                    self.logger.info("dpid %s in eth%s out eth%s", dpid, in_port, out_port)
                                    self.logger.info("Slice pair [%s, %s] in slice %i protocol %s dst_port %s", src, dst, slice_id,protocol, dst_port)
                                    match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src,eth_type=ether_types.ETH_TYPE_IP, ip_proto=protocol,tcp_src= src_port, tcp_dst= dst_port )
                                    self.add_flow(datapath, 0, 5, match, actions_snort)
                                    self.send_packet_out(datapath, msg.buffer_id, in_port,
                                                        out_port, msg.data)
                            else: # pair of MAC addresses are not in a slice so skip 
                                return
                        else:
                
                            _tcp = pkt.get_protocol(tcp.tcp)
                            dst_port = _tcp.dst_port
                            src_port = _tcp.src_port
                            for net_slice in slices_data4:
                                slice_id = net_slice[0]     # extract the slice ID
                                net_slice = net_slice[1:]
                                
                                if src in net_slice and dst in net_slice and (dst_port in net_slice or src_port in net_slice):
                                    self.logger.info("dpid %s in eth%s out eth%s", dpid, in_port, out_port)
                                    self.logger.info("Slice pair [%s, %s] in slice %i protocol %s dst_port %s", src, dst, slice_id,protocol, dst_port)
                                    match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src,eth_type=ether_types.ETH_TYPE_IP, ip_proto=protocol,tcp_src= src_port, tcp_dst= dst_port )
                                    self.add_flow(datapath, 0, 5, match, actions)
                                    self.send_packet_out(datapath, msg.buffer_id, in_port,
                                                        out_port, msg.data)
                            else: # pair of MAC addresses are not in a slice so skip 
                                return
                    

                    elif protocol == in_proto.IPPROTO_ICMP:
                        if dpid == 9:

                            for net_slice in slices_data3:
                                slice_id = net_slice[0]     # extract the slice ID
                                net_slice = net_slice[1:]
                                if src in net_slice and dst in net_slice:
                                    self.logger.info("dpid %s in eth%s out eth%s", dpid, in_port, out_port)
                                    self.logger.info("Slice pair [%s, %s] in slice %i protocol %s", src, dst, slice_id,protocol)
                                    match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src,eth_type=eth.ethertype,ip_proto=protocol)
                                    self.add_flow(datapath, 0, 1, match, actions_snort)
                                    self.send_packet_out(datapath, msg.buffer_id, in_port,
                                                        out_port, msg.data)
                            else: # pair of MAC addresses are not in a slice so skip 
                                return
                        else:
                            for net_slice in slices_data3:
                                slice_id = net_slice[0]     # extract the slice ID
                                net_slice = net_slice[1:]
                                if src in net_slice and dst in net_slice:
                                    self.logger.info("dpid %s in eth%s out eth%s", dpid, in_port, out_port)
                                    self.logger.info("Slice pair [%s, %s] in slice %i protocol %s", src, dst, slice_id,protocol)
                                    match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src,eth_type=eth.ethertype,ip_proto=protocol)
                                    self.add_flow(datapath, 0, 1, match, actions)
                                    self.send_packet_out(datapath, msg.buffer_id, in_port,
                                                        out_port, msg.data)
                            else: # pair of MAC addresses are not in a slice so skip 
                                return
                    else:
                        if dpid == 9:

                            for net_slice in slices_data3:
                                slice_id = net_slice[0]     # extract the slice ID
                                net_slice = net_slice[1:]
                                if src in net_slice and dst in net_slice:
                                    self.logger.info("dpid %s in eth%s out eth%s", dpid, in_port, out_port)
                                    self.logger.info("Slice pair [%s, %s] in slice %i", src, dst, slice_id)
                                    match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src,eth_type=eth.ethertype)
                                    self.add_flow(datapath, 0, 1, match, actions_snort)
                                    self.send_packet_out(datapath, msg.buffer_id, in_port,
                                                        out_port, msg.data)
                            else: # pair of MAC addresses are not in a slice so skip 
                                return
                        else:
                            for net_slice in slices_data3:
                                slice_id = net_slice[0]     # extract the slice ID
                                net_slice = net_slice[1:]
                                if src in net_slice and dst in net_slice:
                                    self.logger.info("dpid %s in eth%s out eth%s", dpid, in_port, out_port)
                                    self.logger.info("Slice pair [%s, %s] in slice %i", src, dst, slice_id)
                                    match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src,eth_type=eth.ethertype)
                                    self.add_flow(datapath, 0, 1, match, actions)
                                    self.send_packet_out(datapath, msg.buffer_id, in_port,
                                                        out_port, msg.data)
                            else: # pair of MAC addresses are not in a slice so skip 
                                return
                    
            else:
                if self.mac_learning(dpid, eth.src, in_port) is False:
                    self.logger.debug("IPV4 packet enter in different ports")
                    return
                else:
                    self.flood(msg)