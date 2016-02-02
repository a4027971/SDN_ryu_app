import logging
import struct

from operator import itemgetter
from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
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
        self.GROUPTABLE_PRIOR = 3
        self.FLOW_PRIOR = 1
        self.flow_timeout = 15 # flow idle timeout secs
        self.temp_groupt_flow_timeout = 3
        self.mac_to_port = {}
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.datapath_registered = {}
        self.traffic = {}  # store switch's port tx_bytes by traffic monitor
        self.paths_upward = [] # paths from edge-layer to core-layer
        self.paths_downward = [] # paths from core-layer to edge-layer
        self.path_bottleneck = {}
        self.sorted_path_bottleneck = []
        self.optimal_path = {} # select packet path when packet-in
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapath_registered[datapath.id] = datapath

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
        self.add_flow(datapath, 0, match, actions, 0, 0)

    def add_flow(self, datapath, priority, match, actions, i_timeout, h_timeout):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                idle_timeout=i_timeout, hard_timeout=h_timeout)
        datapath.send_msg(mod)

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
        
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # topo learning
        if src not in self.net:
            self.net.add_node(src)
            self.net.add_edge(dpid,src,{'port':in_port})
            self.net.add_edge(src,dpid)

        # get optimal path
        if list(str(dpid))[0] != '3':
            # something go wrong # Debug
            return
        self.logger.info("%s packet in %s %s %s %s", eth.ethertype, dpid, src, dst, in_port)
        path_index = self.optimal_path[dpid]['path_index']
        path = self.paths_upward[path_index]
        self.logger.info("path: %d -> %d -> %d", path[0], path[1], path[2])
        edge_id = path[0]
        aggr_id = path[1]
        core_id = path[2]

        ### add_flow (upward)
        # edge to aggr
        datapath = self.datapath_registered[edge_id]
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_src=src, eth_dst=dst)
        out_port = self.net[edge_id][aggr_id]['port']
        actions = [parser.OFPActionOutput(out_port)]
        if dst not in self.net:
            self.add_flow(datapath, self.FLOW_PRIOR, match, actions, 0, 
                self.temp_groupt_flow_timeout)
        else:
            self.add_flow(datapath, self.FLOW_PRIOR, match, actions, self.flow_timeout, 0)
        # aggr to core
        datapath = self.datapath_registered[aggr_id]
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_src=src, eth_dst=dst)
        out_port = self.net[aggr_id][core_id]['port']
        actions = [parser.OFPActionOutput(out_port)]
        if dst not in self.net:
            self.add_flow(datapath, self.FLOW_PRIOR, match, actions, 0,
                self.temp_groupt_flow_timeout)
        else:
            self.add_flow(datapath, self.FLOW_PRIOR, match, actions, self.flow_timeout, 0)

        # whether known dst location (which switch connects dst)
        # if not, send_group_mod, else, add_flow
        if dst not in self.net:
            self.logger.info("find %s by using group_table", dst)
            for tem_id in self.datapath_registered:
                tem_datapath = self.datapath_registered[tem_id]
                parser = tem_datapath.ofproto_parser
                self.send_group_mod(tem_datapath)
                # add group table to all layer 1 switches
                if list(str(tem_id))[0] == '1':
                    actions = [parser.OFPActionGroup(group_id=3)]
                    match = parser.OFPMatch()
                    self.add_flow(tem_datapath, self.GROUPTABLE_PRIOR, match, actions, 0,
                        self.temp_groupt_flow_timeout)

                # add group table to all layer 2, 3 switches
                elif list(str(tem_id))[0] == '2' or list(str(tem_id))[0] == '3':
                    # downward group table
                    actions = [parser.OFPActionGroup(group_id=2)]
                    match = parser.OFPMatch(in_port=1, eth_dst=dst)
                    self.add_flow(tem_datapath, self.GROUPTABLE_PRIOR, match, actions, 0,
                        self.temp_groupt_flow_timeout)
                    match = parser.OFPMatch(in_port=2, eth_dst=dst)
                    self.add_flow(tem_datapath, self.GROUPTABLE_PRIOR, match, actions, 0,
                        self.temp_groupt_flow_timeout)
        else:
            edge_id = self.net[dst].keys()[0] # dst links to switch's dpid
            for temp_path in self.paths_downward:
                if temp_path[0] == core_id and temp_path[2] == edge_id:
                    path = temp_path
                    break
            self.logger.info(" -> %d -> %d", path[1], path[2])
            aggr_id = path[1]
            # core to aggr
            datapath = self.datapath_registered[core_id]
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_src=src, eth_dst=dst)
            out_port = self.net[core_id][aggr_id]['port']
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, self.FLOW_PRIOR, match, actions, self.flow_timeout, 0)
            # aggr to edge
            datapath = self.datapath_registered[aggr_id]
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_src=src, eth_dst=dst)
            out_port = self.net[aggr_id][edge_id]['port']
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, self.FLOW_PRIOR, match, actions, self.flow_timeout, 0)
            # edge to host
            datapath = self.datapath_registered[edge_id]
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_src=src, eth_dst=dst)
            out_port = self.net[edge_id][dst]['port']
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, self.FLOW_PRIOR, match, actions, self.flow_timeout, 0)

        # send packet back to where it come from
        actions = []
        self.send_packet_out(msg, actions)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)   
        switches=[switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)

        links_list = get_link(self.topology_api_app, None)
        #print links_list
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        #print links
        self.net.add_edges_from(links)
        links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
        #print links
        self.net.add_edges_from(links)

    def send_group_mod(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        dpid = datapath.id

        if list(str(dpid))[0] == '2' or list(str(dpid))[0] == '3':
            port_1 = 1
            port_2 = 2
            actions_1 = [ofp_parser.OFPActionOutput(port_1)]
            actions_2 = [ofp_parser.OFPActionOutput(port_2)]
            
            weight_1 = 50
            weight_2 = 50
            watch_port = ofproto_v1_3.OFPP_ANY
            watch_group = ofproto_v1_3.OFPQ_ALL

            buckets = [
                ofp_parser.OFPBucket(weight_1, watch_port, watch_group, actions_1),
                ofp_parser.OFPBucket(weight_2, watch_port, watch_group, actions_2)]

            group_id = 1
            req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                 ofp.OFPGT_SELECT, group_id, buckets)
            datapath.send_msg(req)

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
            req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                 ofp.OFPGT_ALL, group_id, buckets)
            datapath.send_msg(req)
    ###########################################
    #    Design optimal path for packet-in    #
    ###########################################
    def get_bottleneck(self):
        self.simple_path()
        for i in list(self.path_bottleneck):
            edge_id = self.paths_upward[i][0]
            aggr_id = self.paths_upward[i][1]
            port_edge2aggr = self.net[edge_id][aggr_id]['port']
            port_aggr2core = self.net[aggr_id][self.paths_upward[i][2]]['port']
            bottleneck = 0
            if edge_id in self.traffic and aggr_id in self.traffic:
                # Choose maximum number of bytes from edge-to-aggr path and aggr-to-core path as edge-to-core path's bottleneck
                bottleneck = max(self.traffic[edge_id][port_edge2aggr], self.traffic[aggr_id][port_aggr2core])
            if i not in self.path_bottleneck:
                self.path_bottleneck.setdefault(i,{})
            # Store bottleneck for each edge-to-core path
            self.path_bottleneck[i]['bottleneck'] = bottleneck
        # sort path by bottlenect
        self.sorted_path_bottleneck = [key[0] for key in sorted(self.path_bottleneck.iteritems(),
                                        key=itemgetter(1))]
        self.get_optimal_path()

    # prepare optimal_path for packet-in
    # For each edge-layer switch, choose a path having minimum bottleneck to core-layer as optimal path, and
    # don't care which core-layer switch is choosed to be the destination
    def get_optimal_path(self):
        optimal_path = {}
        i = 0
        for path_index in self.sorted_path_bottleneck:
            dpid = self.paths_upward[path_index][0] # edge-layer id
            if dpid not in optimal_path:
                optimal_path.setdefault(dpid,{})
                optimal_path[dpid]['path_index'] = path_index
                i = i + 1
            if i == 8: # hard-code: edge-layer num
                break
        self.optimal_path = optimal_path

    # Get all path from edge-layer to core-layer (as well as core to edge)
    def simple_path(self):
        for core_id in self.datapath_registered:
            core_datapath = self.datapath_registered[core_id]
            if list(str(core_id))[0] == '1':
                for edge_id in self.datapath_registered:
                    edge_datapath = self.datapath_registered[edge_id]
                    if list(str(edge_id))[0] == '3':
                        # core-layer -> aggregation-layer -> edge-layer
                        for path in nx.all_simple_paths(self.net, source=core_id, target=edge_id, cutoff=2):
                            if path not in self.paths_downward:
                                self.paths_downward.append(path)
                        # edge-layer -> aggregation-layer -> core-layer
                        for path in nx.all_simple_paths(self.net, source=edge_id, target=core_id, cutoff=2):
                            if path not in self.paths_upward:
                                self.paths_upward.append(path)
                                index = len(self.paths_upward) - 1
                                # For each path, initialize path_bottleneck
                                self.path_bottleneck.setdefault(index,{})
            
    #########################
    #    Traffic monitor    #
    #########################
    # Send traffic-monitor request to all switches periodically
    def _monitor(self):
        while True:
            # Send monitor request to all switches
            for dpid in self.datapath_registered:
                dp = self.datapath_registered[dpid]
                self._request_stats(dp)
            hub.sleep(1)
            # Use the latest traffic statistic to calculate the optimal path
            self.get_bottleneck()
            hub.sleep(1)

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Send request to switch
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    # Catch switch's response and execute following code 
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        # Initialize self.traffic
        if dpid not in self.traffic:
            self.traffic.setdefault(dpid,{})
        # Store number of bytes pass through each port as well as each switch
        for stat in body:
            if stat.port_no != 0xFFFFFFFE:
                self.traffic[dpid][stat.port_no] = stat.tx_bytes
        
