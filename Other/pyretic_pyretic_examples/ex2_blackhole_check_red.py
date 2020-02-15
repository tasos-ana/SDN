#place this script under ~/pyretic/pyretic/examples
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.examples.ex2_dumb_forwarding import dumb_forwarder

class BlackholeCheckerRedirector(DynamicPolicy):
    def __init__(self, threshold_rate, blackhole_port_dict, IPs_and_TCP_ports_to_protect):
        super(BlackholeCheckerRedirector, self).__init__()
        self.threshold_rate = threshold_rate
        self.port_dict = blackhole_port_dict
        self.ips_tcp_ports = IPs_and_TCP_ports_to_protect
        self.untrusted_incoming_traffic_to_check = union([match(inport=self.port_dict['untrusted'], dstip=i, protocol=6, dstport=p) for (i,p) in self.ips_tcp_ports])       
        self.forward = dumb_forwarder(self.port_dict['trusted'],self.port_dict['untrusted']) #initial forwarding scheme 
        #ATTENTION: other useful attributes???
        self.refresh()
        self.srcip_and_packet_cnt = {} #for each srcip that target apache server added here with pck cnt
        self.redirected_srcip = {} #for each scrip that target apache server add true or false if redirected to blackhole
        
    def update_policy(self):
        #ATTENTION: update the policy based on current forward and query policies 
        self.policy = self.forward + self.query

    def check_redirect(self,stats): #ATTENTION: other attributes?
         #ATTENTION: implement check and redirection
        for p in stats.keys(): #getting each match rule from stats
            srcip = str(p.map['srcip'].pattern)
            dstip = str(p.map['dstip'].pattern)
            if dstip != '10.1.1.4': # if the dst isnt the server skiping that src ip
                continue
            else:
                if srcip not in self.srcip_and_packet_cnt.keys(): # checkin if the srcip already addded
                    self.redirected_srcip[srcip] = False
                    self.srcip_and_packet_cnt[srcip] = 0 #how many packet we get from that IP
        for ip in self.srcip_and_packet_cnt.keys(): # for all IP that was on dict
            try:
                match_rule = match(srcip=ip,dstip='10.1.1.4',dstport=80) # creating the match rule
                packet_num = stats[match_rule] # getting the packet num if exist that matchrule
                server_p_cnt = self.srcip_and_packet_cnt[ip] # getting the previous packet number
                threshold_num = self.threshold_rate 
                #if the packet num - previous packet num < threshhold and we dont already redirect that IP 
                if packet_num > server_p_cnt + threshold_num and self.redirected_srcip[ip] == False: 
                    blackhole_redirection_pol = (match_rule >> modify(outport=3)) + self.query # create redirect policy
                    self.policy = if_(match_rule,blackhole_redirection_pol, self.policy) #add the policy
                    print 'Redirect to blackhole for IP:' + ip
                    self.redirected_srcip[ip] = True # enable that 'flag'
                elif self.redirected_srcip[ip] == False:
                    self.srcip_and_packet_cnt[ip] = packet_num
            except KeyError:
                pass
 
    def refresh_query(self):
        #ATTENTION: reset the query checking for suspicious traffic 
        #and 
        #register the callback function
        self.query = count_packets(1,['dstip','srcip','dstport'])
        self.query.register_callback(self.check_redirect)

    def refresh(self):
        #refresh query and policy
        self.refresh_query()
        self.update_policy()