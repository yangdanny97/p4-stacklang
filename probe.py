#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
from headers import *
from test_programs import *

from scapy.all import srp1, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP


def get_if():
    ifs = get_if_list()
    iface = None  # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface



def get_program(pname):
    if pname not in programs:
        raise Exception("unknown program!")
    else:
        return programs[pname]

def handle_pkt(pkt):
    print "received response:"
    pkt[2].show()
    sys.stdout.flush()

def send_probe(addr, pname):   
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')

    pkt = pkt /IP(dst=addr)
    instrs = get_program(pname)
    pkt = build_packet(pkt, instrs)

    pkt[2].show()
    sys.stdout.flush() 
    pkt = srp1(pkt, iface=iface, verbose=False)
    handle_pkt(pkt)

def main():
    if len(sys.argv) < 2:
        print "usage: ./probe.py <source> <program name>"
        print ("valid program names: " + ", ".join(programs.keys()))

    addr = socket.gethostbyname(sys.argv[1])
    pname = sys.argv[2]
    send_probe(addr, pname)

if __name__ == '__main__':
    main()
