#Author: Tasos Anastasas - csd3166
#Year 2016-2017
#Software Defined from Network
#Exercise 1 - 4 client - 4 server - 1 switch and customed controller that proxie Server IP

from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr

log = core.getLogger()

import time
import random

IDLE_TIMEOUT = 10 #seconds
ETHER_BROADCAST = EthAddr("FF:FF:FF:FF:FF:FF") #broadcast mac address


class SimpleLoadBalancer(object):
    def __init__(self, service_ip, server_ips = []): #initialize
        core.openflow.addListeners(self)

        self.lb_ip = service_ip #loadbalancer ip
        self.flow_t_ip2mac = {} #keys are IP, values are mac
        self.flow_t_ip2port = {} #keys are IP, values are port
        self.all_server_ips = [] #keep all servers ips here
        self.all_client_ips = [] #keep all clients ips here

        #initialize dictionary and server list
        for x in server_ips:
            self.flow_t_ip2port[x] = " "
            self.flow_t_ip2mac[x]  = " "
            self.all_server_ips.append(x)
            log.debug(" [Added] \t <server IP> : <%s> " % self.all_server_ips[-1])

    def _handle_ConnectionUp(self, event): #new switch connection
        self.lb_mac = EthAddr("0A:00:00:00:00:01") #fake mac of load balancer
        self.connection = event.connection

        #for each server send arp request so we can learn mac-port
        for x in self.all_server_ips:
            self.send_proxied_arp_request(self.connection,x)
            log.debug(" \t \t <Server IP> : <%s>" % x)

    def update_lb_mapping(self, client_ip): #update load balancing mapping
        #if the ip isnt already on client
        if client_ip in self.all_client_ips:
            return
        else:#add client on tables
            self.all_client_ips.append(client_ip)
            log.debug(" [Added] \t <client IP> : <%s>" % client_ip)
        
    def send_proxied_arp_reply(self, packet, connection, outport, requested_mac):
        #get the arp request from packet that received
        arp_req = packet.next

        #create arp reply
        arp_rep = arp()
        arp_rep.opcode = arp.REPLY
        arp_rep.hwsrc = requested_mac #switch mac
        arp_rep.protosrc = arp_req.protodst #arp request dst IP = switch IP

        arp_rep.hwdst = arp_req.hwsrc #change mac dest on reply to the mac source of req
        arp_rep.protodst = arp_req.protosrc #change ip dest on reply to the ip source of req

        #create the ethernet packet
        eth = ethernet(type=ethernet.ARP_TYPE, src=self.lb_mac, dst=packet.src)
        eth.set_payload(arp_rep)

        #send the arp reply
        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        msg.in_port = outport

        self.connection.send(msg)
        log.debug(" [Sended] \t <Arp Reply>")

    def send_proxied_arp_request(self, connection, ip):

        #Create ARP request
        arp_req = arp()
        arp_req.opcode = arp.REQUEST

        #arp request from switch to server
        arp_req.hwsrc = self.lb_mac
        arp_req.protosrc = self.lb_ip

        #mac = ethernet broadcast mac
        arp_req.hwdst = ETHER_BROADCAST
        arp_req.protodst = ip

        # Create the Ethernet packet
        eth = ethernet(type=ethernet.ARP_TYPE, src=self.lb_mac , dst=ETHER_BROADCAST)
        eth.set_payload(arp_req)

        #send the ARP request
        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))

        self.connection.send(msg)

        log.debug(" [Sended] \t <Arp Request>")
    
    def install_flow_rule_client_to_server(self, connection, outport, client_ip,server_ip, buffer_id=of.NO_BUFFER):
        if buffer_id == None:
            return

        #Creating the flow mod with specified idle time and the buffer_id(that stored the packet)
        msg = of.ofp_flow_mod()
        msg.idle_timeout = IDLE_TIMEOUT
        msg.buffer_id = buffer_id

        #Matching rules
        msg.match.nw_src = client_ip
        msg.match.nw_dst = self.lb_ip
        msg.match.in_port = outport
        msg.match.dl_type = 0x800 #match if IP was IPv4
        
        msg.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac)) #source mac change to the switch mac
        #keep the same source IP (client)

        msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip)) #change the destination IP to the server
        msg.actions.append(of.ofp_action_dl_addr.set_dst(self.flow_t_ip2mac[server_ip])) #change the destination MAC to the server

        msg.actions.append(of.ofp_action_output(port = self.flow_t_ip2port[server_ip])) #change the dest port to the Server

        connection.send(msg)
        log.debug(" [Installed] \t [Flow Mod] \t <client IP: %s> : <server IP: %s>",client_ip , server_ip)

    def install_flow_rule_server_to_client(self, connection, outport, server_ip, client_ip, buffer_id=of.NO_BUFFER):
        if buffer_id == None:
            return

        #Creating the flow mod with specified idle time and the buffer_id(that stored the packet)
        msg = of.ofp_flow_mod()
        msg.idle_timeout = IDLE_TIMEOUT
        msg.buffer_id = buffer_id

        #Matching rules
        msg.match.nw_src = server_ip
        msg.match.nw_dst = client_ip
        msg.match.in_port = outport
        msg.match.dl_type = 0x800
        
        msg.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac))#source mac change to the switch mac
        #keep the same source IP (server)

        msg.actions.append(of.ofp_action_dl_addr.set_dst(self.flow_t_ip2mac[client_ip]))#change the destination MAC to the client
        msg.actions.append(of.ofp_action_nw_addr.set_dst(client_ip)) #change the destination IP to the client

        msg.actions.append(of.ofp_action_output(port = self.flow_t_ip2port[client_ip]))#change the dest port to the client

        connection.send(msg)

        log.debug(" [Installed] \t [Flow Mod] \t <server IP: %s> : <client IP: %s>",server_ip , client_ip)
        
    def install_address_info(self,arp_rep,in_port):
        
        #installing the arp reply data on tables
        #get dest ip if the source is switch (client->arp_request)
        if arp_rep.protosrc == self.lb_ip:
            new_ip   = IPAddr(arp_rep.protodst)
            new_mac  = arp_rep.hwdst
            new_port = in_port
        else:#get source ip (controller->arp_request)
            new_ip   = arp_rep.protosrc
            new_mac  = arp_rep.hwsrc
            new_port = in_port

        self.flow_t_ip2port[new_ip] = new_port
        log.debug(" [Updated] \t <on IP> : %s \t <added port> : <%s>" , new_ip ,  new_port)
        self.flow_t_ip2mac[new_ip] = new_mac
        log.debug(" [Updated] \t <on IP> : %s \t <added mac> : <%s>" , new_ip ,  new_mac)

        if new_ip in self.all_server_ips:
            return
        else:
            self.update_lb_mapping(new_ip)#update table with clients if the IP it's not from Server

    def _handle_PacketIn(self, event):
        packet = event.parsed
        connection = event.connection
        inport = event.port
        if packet.type == packet.ARP_TYPE:
            arp_p = packet.next
            if arp_p.opcode == arp.REPLY:#reply apo server
                log.debug(" [Received] \t <arp reply>")
                self.install_address_info(arp_p,inport)#installing the mac,port
            else:#received request so we handle reply
                log.debug(" [Received] \t <arp request>")
                self.install_address_info(arp_p,inport)#installing the the mac,port for clients
                self.send_proxied_arp_reply(packet, connection, inport , self.lb_mac)# send the arp reply
        elif packet.type == packet.IP_TYPE:
            mac_packet = packet 
            ip_packet = packet.next
            if ip_packet.srcip in self.all_server_ips:#echo reply
                log.debug(" [Received] \t <ICMP reply>")
                #installing flow rule for server-client and after installation the packet matched and sended
                self.install_flow_rule_server_to_client(connection, inport,  ip_packet.srcip , ip_packet.dstip, event.ofp.buffer_id)
            else:#echo request
                log.debug(" [Received] \t <ICMP request>")
                selected_server = random.choice(self.all_server_ips)
                log.debug(" [Selected] \t <server IP> : <%s>"% selected_server)
                #installing flow rule for client-server and after installation the packet matched and sended   
                self.install_flow_rule_client_to_server(connection, inport, ip_packet.srcip, selected_server, event.ofp.buffer_id) 
        else:
            log.info(" [Received] \t <Unknown Packet type> : <%s>" % packet.type)
            return
        return

#launch application with following arguments:   
#ip: public service ip, servers: ip addresses of servers (in string format)
def launch(ip, servers): 
    log.info(" Loading Simple Load Balancer module ")
    server_ips = servers.replace(","," ").split()
    server_ips = [IPAddr(x) for x in server_ips]
    service_ip = IPAddr(ip)
    core.registerNew(SimpleLoadBalancer, service_ip, server_ips)

#Author: Tasos Anastasas - csd3166
#Year 2016-2017
#Software Defined from Network
#Exercise 1 - 4 client - 4 server - 1 switch and customed controller that proxie Server IP