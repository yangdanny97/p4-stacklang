#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
from headers import *

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

def test_basic():
    return [
        PUSH(1),
        PUSH(2),
        DONE()
    ]

def test_error():
    return [
        PUSH(1),
        ERROR(),
        PUSH(2),
    ]

def test_swap():
    return [
        PUSH(1),
        PUSH(2),
        SWAP(),
        DONE()
    ]

def test_add():
    return [
        PUSH(1),
        PUSH(2),
        ADD(),
        DONE()
    ]

def get_program():
    return []


def main():

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')

    pkt = pkt /IP(dst=addr)
    instrs = get_program()
    build_packet(pkt, instrs)

    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
