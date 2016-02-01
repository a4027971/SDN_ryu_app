import logging
import struct

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib import hub
from ryu.lib.packet import ether_types

from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches 
import networkx as nx
from ryu.lib import addrconv
import struct
import socket

class FatTreeMultipath(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FatTreeMultipath, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.net=nx.DiGraph()
        self.nodes = {}
        self.links = {}
        self.no_of_nodes = 0
        self.no_of_links = 0
        self.i = 0
        self.datapath_registered = []
    
    # Event: new switch sends message to controller.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        self.datapath_registered.append(datapath)
        print "switch %d add in "%datapath.id

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        # add group table 3 to Core layer
        # group table 3: let switch let input packet send out to all ports.
        if list(str(dpid))[0] == '1':
            self.send_group_mod(datapath)
            # print "send_group_mod to %d"%tem_id
            actions = [parser.OFPActionGroup(group_id=3)]
            match = parser.OFPMatch() # all packet will match
            self.add_flow(datapath, 1, match, actions)

    # add a new flow(rule) to switch.
    #   priority : the packet will match the highest priority to match, then follw the action to deal with packet.
    #   match    : set the match condition, ex: 1 = msg.match['in_port']
    #                                           packet from port 1 will be match.
    #   actions  : the controller will take actions on packet when packet match.
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        #print mod.__dict__
        datapath.send_msg(mod)
    
    # send the packet back to the switch and we can set actions on it.
    def send_packet_out(self, msg, actions):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    # Event : switch send packet to controller will triger this event.
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # get information
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore IPV6 packet
            return
        if eth.dst == "ff:ff:ff:ff:ff:ff":
            # ignore broadcast packet
            return
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore LLDP packet
            return
        
        # DEBUG 
        # monitor the packet sent to the controller.
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("%s packet in %s %s %s %s", eth.ethertype, dpid, src, dst, in_port)
        
        
        # learn a mac address to avoid FLOOD next time.
        # self.mac_to_port[dpid][src] = in_port
        
        # DEBUG : for debug , not userd in this app
        # topo learning
        # if src not in self.net:
        #     self.net.add_node(src)
        #     self.net.add_edge(dpid,src,{'port':in_port})
        #     self.net.add_edge(src,dpid)
        """
        if dst in self.net:

            path=nx.shortest_path(self.net,src,dst)   
            next=path[path.index(dpid)+1]
            out_port=self.net[dpid][next]['port']
        
        else:
            out_port = ofproto.OFPP_FLOOD
        """
        
        # actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        
        for tem_datapath in self.datapath_registered:
            tem_id = tem_datapath.id
            # add flow and group table1, 2 to all Aggregations & Edge layer switches.
            
            if list(str(tem_id))[0] == '2' or list(str(tem_id))[0] == '3':
                self.send_group_mod(tem_datapath)
                # print "send_group_mod to %d"%tem_id
                actions = [parser.OFPActionGroup(group_id=1)]
                match = parser.OFPMatch(in_port=3, eth_dst=dst)
                self.add_flow(tem_datapath, 4, match, actions)
                match = parser.OFPMatch(in_port=4, eth_dst=dst)
                self.add_flow(tem_datapath, 4, match, actions)

                actions = [parser.OFPActionGroup(group_id=2)]
                match = parser.OFPMatch(in_port=1, eth_dst=dst)
                self.add_flow(tem_datapath, 1, match, actions)
                match = parser.OFPMatch(in_port=2, eth_dst=dst)
                self.add_flow(tem_datapath, 1, match, actions)

        # send packet back to what it come from
        actions = []
        self.send_packet_out(msg, actions)

    # Event : switch sending data to controller periodically will trigger this event. 
    # this app just use this event to debug.
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)   
        switches=[switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)
        
        print "*****switches"
        print self.net.nodes()

        links_list = get_link(self.topology_api_app, None)
        #print links_list
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        #print links
        self.net.add_edges_from(links)
        links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
        #print links
        self.net.add_edges_from(links)
        print "**********List of links"
        print self.net.edges(data=True)
    
    # send group table to switches according to its layer
    # group table 1 : send packet out by choosing one up_port(port1,2). 
    # group table 2 : send packet out to all down_port(port3,4). 
    # group table 3 : send packet out to all ports(including input_port).
    def send_group_mod(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        dpid = datapath.id
        
        # Aggregation, Edge layer
        if list(str(dpid))[0] == '2' or list(str(dpid))[0] == '3':
            port_1 = 1
            port_2 = 2
            actions_1 = [ofp_parser.OFPActionOutput(port_1)]
            actions_2 = [ofp_parser.OFPActionOutput(port_2)]
            
            weight_1 = 50
            weight_2 = 50
            watch_port = ofproto_v1_3.OFPP_ANY
            watch_group = ofproto_v1_3.OFPQ_ALL
            
            # port 1,2 are up forward ports
            buckets = [
                ofp_parser.OFPBucket(weight_1, watch_port, watch_group, actions_1),
                ofp_parser.OFPBucket(weight_2, watch_port, watch_group, actions_2)]
            
            group_id = 1
            # ues OFPGT_SELECT, we will select one action from buckets. 
            req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                 ofp.OFPGT_SELECT, group_id, buckets)
            datapath.send_msg(req)
            
            # port 3,4 are down forward ports
            port_1 = 3
            port_2 = 4
            actions_1 = [ofp_parser.OFPActionOutput(port_1)]
            actions_2 = [ofp_parser.OFPActionOutput(port_2)]
            buckets = [
                ofp_parser.OFPBucket(weight_1, watch_port, watch_group, actions_1),
                ofp_parser.OFPBucket(weight_2, watch_port, watch_group, actions_2)]

            group_id = 2
            req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                 ofp.OFPGT_ALL, group_id, buckets)
            datapath.send_msg(req)
        
        # Core layer
        elif list(str(dpid))[0] == '1':
            port_1 = 1
            port_2 = 2
            port_3 = 3
            port_4 = 4
            actions_1 = [ofp_parser.OFPActionOutput(port_1)]
            actions_2 = [ofp_parser.OFPActionOutput(port_2)]
            actions_3 = [ofp_parser.OFPActionOutput(port_3)]
            actions_4 = [ofp_parser.OFPActionOutput(port_4)]
            actions_5 = [ofp_parser.OFPActionOutput(ofproto_v1_3.OFPP_IN_PORT)]

            weight_1 = 50
            weight_2 = 50
            weight_3 = 50
            weight_4 = 50
            weight_5 = 50
            watch_port = ofproto_v1_3.OFPP_ANY
            watch_group = ofproto_v1_3.OFPQ_ALL

            buckets = [
                ofp_parser.OFPBucket(weight_1, watch_port, watch_group, actions_1),
                ofp_parser.OFPBucket(weight_2, watch_port, watch_group, actions_2),
                ofp_parser.OFPBucket(weight_3, watch_port, watch_group, actions_3),
                ofp_parser.OFPBucket(weight_4, watch_port, watch_group, actions_4),
                ofp_parser.OFPBucket(weight_5, watch_port, watch_group, actions_5)]

            group_id = 3
            # use OFPGT_ALL means we will do all the actions in buckets.
            req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                 ofp.OFPGT_ALL, group_id, buckets)
            datapath.send_msg(req)
