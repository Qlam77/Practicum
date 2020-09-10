#!/usr/bin/env python2.7
# This program listens for packets using scapy
# The user can use options for the packet filter and choose a file to export sniffed pacjets
#
# Quincy Lam

import os
import sys
import getopt
import subprocess
from Resolve import *
from scapy.all import *

location = os.path.dirname(os.path.abspath(__file__)) # get the folder path
help_msg = 'Packet_listener.py -o <output file> -c <number of packets> -f <filter expression>' #error message
output_file = 'test.pcap' # saves to test.pcap
count_num = 0 # infinite scan
filt = '' # default filter is tcp
ip_count = 'ip_count.txt'

# packet resolution
def resolvePacket(packet):
    pktdump = PcapWriter(output_file, append=True, sync=True)
    pktdump.write(packet)
    resolveRule(packet)
    ip = open(ip_count, "a")
    if packet.haslayer(IP):
        ip.write("S: %s, D: %s\n" % (packet[IP].src, packet[IP].dst))
    ip.close()
    

# main
def main(argv):
    global output_file
    global count_num
    global filt
    # File opts
    try:
        opts, args = getopt.getopt(argv, "ho:c:f:",["output=", "count=", "filter="])
    except getopt.GetoptError:
        print(help_msg)
        sys.exit(2)
    
    # Gets File options for output
    for opt, arg in opts:
        if opt == '-h':
            print(help_msg)
            sys.exit()
        elif opt in ("-o", "--output"):
            output_file = arg
        elif opt in ("-c", "--count"):
            count_num = int(arg)
        elif opt in ("-f", "--filter"):
            filt = arg

    print 'Output file is: ', output_file
    print 'Filter is: ', filt
    
    f = open(output_file, "w") # clear the file
    f.close() # close the file
    
    setRules()
    
    print('Scanning')
    pkts = sniff(count=count_num, iface='wlan1', prn=resolvePacket)
    subprocess.call("sudo " + "/sbin/iptables -F", shell=True)
    subprocess.call("sudo " + "/sbin/iptables -X", shell=True)
    print('Finished Scanning')
    
if __name__ == "__main__":
    main(sys.argv[1:])