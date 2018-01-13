# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
import logging
import struct
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib import mac
from ryu.lib.packet import arp
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link


class SimpleSwitch14(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch14, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.switch_port_table = {}
        self.link_to_port = {} 
        self.interior_ports = {}
        self.access_ports = {}
        self.access_table={}
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        
    def create_port_map(self, switch_list):
        """
            Create interior_port table and access_port table. 
        """
        for sw in switch_list:
            dpid = sw.dp.id
            self.switch_port_table.setdefault(dpid, set())
            self.interior_ports.setdefault(dpid, set())
            self.access_ports.setdefault(dpid, set())

            for p in sw.ports:
                self.switch_port_table[dpid].add(p.port_no)
            self.logger.info(self.switch_port_table)
        		
    		
    def create_interior_links(self, link_list):
      """
          Get links`srouce port to dst port  from link_list,
          link_to_port:(src_dpid,dst_dpid)->(src_port,dst_port)
      """
      for link in link_list:
          src = link.src
          dst = link.dst
          self.link_to_port[(src.dpid, dst.dpid)] = (src.port_no, dst.port_no)
      
  
          # Find the access ports and interior ports
          if link.src.dpid in self.switches:
              self.interior_ports[link.src.dpid].add(link.src.port_no)
          if link.dst.dpid in self.switches:
              self.interior_ports[link.dst.dpid].add(link.dst.port_no)
          self.logger.info('Link_to_Port {}'.format(self.link_to_port))
          self.logger.info('Interior_Ports {}'.format(self.interior_ports))
          
    '''def create_access_ports(self):
      """
          Get ports without link into access_ports
      """
      for sw in self.switch_port_table:
          all_port_table = self.switch_port_table[sw]
          interior_port = self.interior_ports[sw]
          self.access_ports[sw] = all_port_table - interior_port
      self.logger.info('Interiors_ports : {}'.format(self.interior_ports))'''
          
      
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology(self, ev):
    	"""
    		Get topology info and store it.
    	"""
    	switch_list = get_switch(self, None)
    	self.create_port_map(switch_list)
    	self.switches=self.switch_port_table.keys()
    	links=get_link(self, None)
    	self.create_interior_links(links)
    	#self.create_access_ports()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        #self.logger.info('Datapath: {}'.format(datapath.id)
        ofproto = datapath.ofproto	
        
        parser = datapath.ofproto_parser
        #self.logger.info('Parser: {}'.format(parser))
        
        
        #if msg.reason == ofproto.OFPR_NO_MATCH:
        #reason = 'NO MATCH'
        #elif msg.reason == ofproto.OFPR_ACTION:
            #reason = 'ACTION'
        #elif msg.reason == ofproto.OFPR_INVALID_TTL:
            #reason = 'INVALID TTL'
        
        in_port = msg.match['in_port']
        
        #open flow headers are parsed already	
        
        pkt = packet.Packet(msg.data)
        #self.logger.info('Packet information {}'.format(pkt))
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst=eth.dst
        src = eth.src
        dpid = datapath.id
        arp_pkt=pkt.get_protocol(arp.arp)
      
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:  # ignore lldp packet
        #self.logger.info("LLDP packet in %s %s %s %s", dpid, src, dst, in_port)
            return           
  	
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
  
        if dst[:5] == "33:33":  # ignore IPV6 multicast packet
          match = parser.OFPMatch(in_port=in_port,eth_dst=dst)
          actions=[]
          self.add_flow(datapath, 1 , match, actions)
          return
  
        if  dst==mac.BROADCAST_STR: # Handle ARP broadcast 	
            self.logger.info('This is ARP broadcast received at port {} of switch {}'.format(in_port, datapath.id) )	
                    #self.send_arpproxy()

        return
        
        
   	

	
			
			
			
			
