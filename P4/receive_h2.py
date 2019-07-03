#!/usr/bin/env python
import sys
import struct
import os
import argparse

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, UDP, ICMP, ARP

def handle_pkt(pkt, addr, interface):

    if (ICMP in pkt) or (ARP in pkt): 
	return
    print "got a packet"
    # adjust mac addresses here (src = virtualbox_mac, dst = host_mac )
    p=Ether(src="00:00:00:00:00:00",dst="00:00:00:00:00:00")/IP(src="10.0.2.15",dst=addr)/UDP(sport=2222,dport=9988)/struct.pack('I',2)/pkt
    sendp(p, iface=interface)
    pkt.show2()
    sys.stdout.flush()
    print(addr, interface)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('ip_addr', type=str, help="The IP address of the host to use")
    parser.add_argument('interface', type=str, help="The interface of the VM to use")
    args = parser.parse_args()
    addr = args.ip_addr
    interface = args.interface
    print "Interface: ", interface
    print "Addr: ", addr
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on s1-eth2"
    sys.stdout.flush()
    sniff(iface = 's1-eth2',
          prn = lambda x: handle_pkt(x, addr, interface))

if __name__ == '__main__':
    main()
