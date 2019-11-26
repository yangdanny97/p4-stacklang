#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
from headers import *
from test_programs import *

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
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

def send_pkt(addr, pname):
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')

    pkt = pkt /IP(dst=addr)
    instrs, stk = get_program(pname)
    pkt = build_packet(pkt, instrs, stk)

    pkt[2].show()
    sys.stdout.flush() 
    sendp(pkt, iface=iface, verbose=False)

def main():
    if len(sys.argv) < 2:
        print "usage: ./send.py <destination> <program name>"
        print ("valid program names: " + ", ".join(programs.keys()))
        return

    addr = socket.gethostbyname(sys.argv[1])
    pname = sys.argv[2]
    send_pkt(addr, pname)

if __name__ == '__main__':
    main()
