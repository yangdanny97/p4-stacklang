#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
from headers import *
from test_programs import *

from scapy.all import srp1, sendp, send, get_if_list, get_if_hwaddr
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

def handle_pkt(pkt):
    print "received response:"
    pkt[2].show()
    sys.stdout.flush()

def send_probe(addr, instrs, stk):   
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')

    pkt = pkt /IP(dst=addr)
    pkt = build_packet(pkt, instrs, stk)

    pkt[2].show()
    sys.stdout.flush() 
    pkt = srp1(pkt, iface=iface, verbose=False)
    handle_pkt(pkt)

def send_pkt(addr, instrs, stk):
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')

    pkt = pkt /IP(dst=addr)
    pkt = build_packet(pkt, instrs, stk)

    pkt[2].show()
    sys.stdout.flush() 
    sendp(pkt, iface=iface, verbose=False)

