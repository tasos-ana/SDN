#-----------------------------------------------------------#
# HY-436 / Execrise 2 / Data Center - Firewall - Migration  #
#         Anastasas Anastasios csd3166                      #
#                   2016-2017                               #
#-----------------------------------------------------------#

#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import irange,dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import RemoteController

import argparse
import sys
import time


class ClosTopo(Topo):

    def __init__(self, fanout, cores, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
       
        a_total = cores*fanout #total nodes of aggregation
        e_total = a_total*fanout #total nodes of edges
        h_total = e_total*fanout #total leaf of hosts

       	core_list = []
       	aggregation_list = []
       	edge_list = []
       	host_list = []


       	"Set up Core"
        for i in range(0,cores):
            c_index = i + 1
            c = "c" + str(c_index)
            core_list.append(self.addSwitch(c))
            "and Aggregate level"
            for j in range(0,fanout):
                a_index = (cores + 1) + fanout*i + j 
                a = "a" + str(a_index)
                aggregation_list.append(self.addSwitch(a))
                "Set up Edge level"
                for k in range(0,fanout):
                    e_index = (a_total+cores+1) + fanout*(fanout*i + j) + k
                    e = "e" + str(e_index)
                    edge_list.append(self.addSwitch(e))

        "Connection Core - Aggregation level"
        for core in core_list:
            for aggregation in aggregation_list:
                self.addLink( core , aggregation )
        
        "Connection Aggregation - Edge level "
        for aggregation in aggregation_list:
            for edge in edge_list:
                self.addLink( aggregation , edge )
 
        "Set up Host level, Connection Edge - Host level "
        for i in range(0,h_total):
            h_index = i + 1
            h = "h" + str(h_index)
            host_list.append(self.addHost(h))

        i = 0;
        for edge in edge_list:
            self.addLink(edge, host_list[i])
            i+=1
            self.addLink(edge, host_list[i])
            i+=1

def setup_clos_topo(fanout=2, cores=1):
    "Create and test a simple clos network"
    assert(fanout>0)
    assert(cores>0)
    topo = ClosTopo(fanout, cores)
    net = Mininet(topo=topo, controller=lambda name: RemoteController('c0', "127.0.0.1"), autoSetMacs=True, link=TCLink)
    net.start()
    time.sleep(20) #wait 20 sec for routing to converge
    net.pingAll()  #test all to all ping and learn the ARP info over this process
    CLI(net)       #invoke the mininet CLI to test your own commands
    net.stop()     #stop the emulation (in practice Ctrl-C from the CLI 
                   #and then sudo mn -c will be performed by programmer)

    
def main(argv):
    parser = argparse.ArgumentParser(description="Parse input information for mininet Clos network")
    parser.add_argument('--num_of_core_switches', '-c', dest='cores', type=int, help='number of core switches')
    parser.add_argument('--fanout', '-f', dest='fanout', type=int, help='network fanout')
    args = parser.parse_args(argv)
    setLogLevel('info')
    setup_clos_topo(args.fanout, args.cores)


if __name__ == '__main__':
    main(sys.argv[1:])


#-----------------------------------------------------------#
# HY-436 / Execrise 2 / Data Center - Firewall - Migration  #
#         Anastasas Anastasios csd3166                      #
#                   2016-2017                               #
#-----------------------------------------------------------#