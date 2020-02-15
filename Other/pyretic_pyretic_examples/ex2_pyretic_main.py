#place this script under ~/pyretic/pyretic/examples - run it as the main pyretic module
#pyretic.py pyretic.examples.ex2_pyretic_main.py
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.virt import *

#ATTENTION: CHECK THE IMPORTS!!!
from pyretic.modules.gateway_forwarder import gateway_forwarder
from pyretic.modules.mac_learner import mac_learner
from pyretic.modules.arp import ARP
from pyretic.examples.ex2_dumb_forwarding import dumb_forwarder
from pyretic.examples.ex2_blackhole_check_red import BlackholeCheckerRedirector
from pyretic.examples.ex2_firewall import fw
from pyretic.vdef.ex2_split_gateway import split_gateway

class vgateway(DynamicPolicy):
    def __init__(self,pol):
        super(vgateway,self).__init__(virtualize(pol, split_gateway(self)))

def setup(num_internet_hosts=253, num_dmz_servers=1, num_internal_hosts=2):
    #-----------------
    #Network breakdown (virtual components)
    internal_net_edge = [1000]
    gateway = [1001]
    blackhole_checker_redirector = [1002]
    firewall = [1003]
    internet_edge =  [1004] 
    
    #-----------------
    #IP subnets
    internal_prefix = '10.1.1.'
    internet_prefix = '10.1.2.'
    prefix_len = 24
    internal_cidr = internal_prefix + '0/' + str(prefix_len)
    internet_cidr = internet_prefix + '0/' + str(prefix_len)
    
    #-----------------
    #End hosts and servers
    internal_ip_to_macs = {IP(internal_prefix+str(i+1)) : MAC('00:00:00:00:00:0'+str(i)) for i in range(1,1+num_internal_hosts+num_dmz_servers)}
    internet_ip_to_macs = {IP(internet_prefix+str(i+1)) : MAC('00:00:00:00:00:04') for i in range(1,1+num_internet_hosts)}  
    host_ip_to_macs = dict(internal_ip_to_macs.items() + internet_ip_to_macs.items())
    
    #-----------------
    #params for blackhole checker/redirector
    
    #threshold rate of packets belonging to the same (srcip,dstip,dstport) flow (careful: TCP protocol!)
    #if this rate is surpassed, we conider this a possible DoS and redirect
    #the flow to the blackhole host for further examination
    threshold_rate = 5 #packets per sec (you can tune it if needed)
    blackhole_port_dict = {'untrusted' : 2, 'trusted' : 1, 'blackhole' : 3} #see exercise setup (figure 2)
    ips_and_tcp_ports_to_protect = [("10.1.1.4",80)] #protect apache server
    
    #-----------------
    #params for firewall
    firewall_port_dict = {'untrusted' : 2, 'trusted' : 1} #see exercise setup (ports of firewall, figure 2)
    whitelist = set([])
    for i in internal_ip_to_macs.keys():
        for j in internet_ip_to_macs.keys():
            internal_ip = str(i)
            internet_ip = str(j)
            #ATTENTION: Build whitelist!!! (see how firewall expects it)
            if internal_ip == "10.1.1.4":
                whitelist.add((internet_ip,internal_ip)) #add on whitelist a tuple with src-dist
            whitelist.add((internal_ip,internet_ip)) #add on whitelist a tuple with src-dist with acceptable ping IP
    #print "Firewall whitelist"
    #print whitelist
    
    #-----------------
    #policies
    #ATTENTION: internal network edge policy???
    internal_pol = mac_learner()

    #ATTENTION: gateway policy???
    gateway_pol = gateway_forwarder(internal_cidr,internet_cidr,host_ip_to_macs) #initialize the communication between subnets

    #ATTENTION: black-hole host policy??
    blackhole_pol = BlackholeCheckerRedirector(threshold_rate,blackhole_port_dict,ips_and_tcp_ports_to_protect)

    #ATTENTION: firewall policy???-->ATTENTION: besides the IP whitelist, the firewall policy should let ARP packets reach the gateway! (hint: use 'if_')
    firewall_pol = (if_(ARP,passthrough,fw(whitelist)) >> dumb_forwarder(1,2))

    #ATTENTION: internet edge policy???
    internet_pol = mac_learner()

    #initial test policies for firewall and blackhole
    #blackhole_pol = dumb_forwarder(1,2)
    #firewall_pol = dumb_forwarder(1,2)
    #-----------------

    #ATTENTION: return ??? --> Combine the policies! (hint: check gateway_3switch_example_basic.py)
    return ((switch_in(internal_net_edge) >> internal_pol) +
            (switch_in(gateway) >> gateway_pol) +
            (switch_in(blackhole_checker_redirector) >> blackhole_pol) +
            (switch_in(firewall) >> firewall_pol) +
            (switch_in(internet_edge) >> internet_pol)
        )
    
def main():
    return vgateway(setup())