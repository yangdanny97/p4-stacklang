#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
from headers import *

from scapy.all import srp1, sniff, sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
import threading


def send_probe(instrs, stk):   
    iface = get_if()

    print "sending on interface %s" % iface
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')

    pkt = pkt /IP()
    pkt = build_packet(pkt, instrs, stk)
    print pkt[3].show(True)
    print "awaiting response..."
    pkt = srp1(pkt, iface=iface, verbose=False)
    print "response:"
    print pkt[3].show(True)

def send_pkt(addr, instrs, stk, message = None):
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')

    pkt = pkt /IP(dst=addr)
    pkt = build_packet(pkt, instrs, stk)

    if message != None:
        pkt /= message

    print pkt[3].show(True)
    sendp(pkt, iface=iface, verbose=False)

