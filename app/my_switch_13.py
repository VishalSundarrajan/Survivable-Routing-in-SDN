# Copyright (C) 2016 Li Cheng at Beijing University of Posts
# and Telecommunications. www.muzixing.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions an
# limitations under the License.

# conding=utf-8
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

class MySimpleSwitch13(app_manager.RyuApp):
    

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(MySimpleSwitch13, self).__init__(*args, **kwargs)
        self.switch_port_table = {}

def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
def switch_features_handler(self, ev):
    		datapath = ev.msg.datapath
    		ofproto = datapath.ofproto
    		parser = datapath.ofproto_parser
    		msg=ev.msg
    	
    
    		#self.logger.info("Packet data: {}".format(msg))
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
    		self.logger.info("Switch: {}".format(datapath.id)

@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

	
def create_port_map(self, switch_list):
    		"""
    		Create interior_port table and access_port table. 
    		"""
    		for sw in switch_list:
    			dpid = sw.dp.id
    			self.switch_port_table.setdefault(dpid, set())
    
    		for port in sw.ports:
    			self.switch_port_table[dpid].add(port.port_no)
    			print(self.switch_port_table)		

events = [event.EventSwitchEnter,
event.EventSwitchLeave, event.EventPortAdd,
event.EventPortDelete, event.EventPortModify,
event.EventLinkAdd, event.EventLinkDelete]	
	
@set_ev_cls(events)
def get_topology(self, ev):
			"""
				Get topology info and store it.
			"""
			switch_list = get_switch(self, None)
			self.create_port_map(switch_list)
       
	
	












     

    

	
		 
   
	

   

