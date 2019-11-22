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
        PUSH(10),
        DONE()
    ]

def test_error():
    return [
        PUSH(1),
        ERROR(),
        PUSH(2),
    ]

# should return 1
def test_swap():
    return [
        PUSH(1),
        PUSH(2),
        SWAP(),
        DONE()
    ]

# should return 3
def test_add():
    return [
        PUSH(1),
        PUSH(2),
        ADD(),
        DONE()
    ]

# should return 4
def test_load():
    return [
        PUSH(1),
        PUSH(2),
        PUSH(3),
        LOAD(1),
        LOAD(1),
        ADD(),
        DONE()
    ]

# should return 2
def test_load_store():
    return [
        PUSH(1),
        PUSH(0),
        PUSH(0),
        LOAD(0),
        DUP(),
        ADD(),
        STORE(1),
        LOAD(1),
        DONE()
    ]

# should return 5
def test_fib():
    return [
        PUSH(1),
        PUSH(1),
        SWAP(),
        OVER(),
        ADD(),
        SWAP(),
        OVER(),
        ADD(),
        SWAP(),
        OVER(),
        ADD(),
        DONE(),
    ]

# should return 5
def test_fib2():
    return [
        PUSH(1),
        PUSH(1),
        DUP(),
        ROT(),
        ADD(),
        DUP(),
        ROT(),
        ADD(),
        DUP(),
        ROT(),
        ADD(),
        DONE(),
    ]

# should return 1
def test_sub():
    return [
        PUSH(2),
        PUSH(3),
        SUB(),
        DONE(),
    ]

# should return 7
def test_if():
    return [
        PUSH(2),
        PUSH(3),
        GTE(),
        CJUMP(6),
        PUSH(5),
        JUMP(8),
        NOP(),
        PUSH(7),
        NOP(),
        DONE(),
    ]

# should return 5
def test_if2():
    return [
        PUSH(2),
        PUSH(1),
        GTE(),
        CJUMP(6),
        PUSH(5),
        JUMP(8),
        NOP(),
        PUSH(7),
        NOP(),
        DONE(),
    ]

def test_fib_n(n = 10):
    return [
        PUSH(n - 2), # space reserved for n
        PUSH(1),
        PUSH(1),
        NOP(),
        PUSH(0), # if n <= 0 then jump to end
        LOAD(0),
        LTE(),
        CJUMP(16),
        DUP(),
        ROT(),
        ADD(),
        PUSH(1), # subtract 1 from current number
        LOAD(0),
        SUB(),
        STORE(0),
        JUMP(3), # jump to the first NOP
        NOP(),
        DONE()
    ]

def test_fact(n = 5):
    return [
        PUSH(n), # current number
        PUSH(1), # result
        NOP(),
        PUSH(1), # if n <= 1 then jump to end
        LOAD(0),
        LTE(),
        CJUMP(16),
        LOAD(0), # multiply current number with result and store it
        LOAD(1),
        MUL(),
        STORE(1),
        PUSH(1), # subtract 1 from current number
        LOAD(0),
        SUB(),
        STORE(0),
        JUMP(2), # jump to first NOP
        NOP(),
        DONE()
    ]

def get_program():
    return test_fact()


def main():

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')

    pkt = pkt /IP(dst=addr)
    instrs = get_program()
    pkt = build_packet(pkt, instrs)

    pkt[2].show()
    sys.stdout.flush() 
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
