#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
from sendutils import *
from headers import *

def test_table_setup():
    prog = [
        STOREREG(1),
        STOREREG(2),
        STOREREG(3),
        SETEGRESS(),
    ]
    init_stack = [
        STACK(511), #s3 can drop
        STACK(1),
        STACK(3),
        STACK(2),
        STACK(3), #s2 to s3
        STACK(3),
        STACK(1),
        STACK(2),
        STACK(2), # s1 to s2
        STACK(3),
        STACK(2),
        STACK(1)
    ]
    return prog, init_stack

def main():
    print "set up registers in each switch for use as routing table"
    print "must be sent by h1"
    addr = socket.gethostbyname("10.0.9.99")
    instrs, stk = test_source_routing(args)
    send_pkt(addr, instrs, stk)

if __name__ == '__main__':
    main()
