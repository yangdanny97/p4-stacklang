#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
from sendutils import *
from headers import *

def test_source_routing(path):
    init_stack = [STACK(i) for i in path[::-1]]
    return ([SETEGRESS()], init_stack)

def main():
    if len(sys.argv) < 3:
        print "source routing"
        print "arguments: input the message and the desired route, separated by spaces"
        print "example (sending from h1 to h2): ./ex_source_routing.py hello 2 3 2 2 1"
        print "example 2 (sending from h1 to h2): ./ex_source_routing.py hello 2 1"
        return

    addr = socket.gethostbyname("10.0.9.99")
    message = sys.argv[1]
    args = [int(x) for x in sys.argv[2:]]
    instrs, stk = test_source_routing(args)
    send_pkt(addr, instrs, stk, message)

if __name__ == '__main__':
    main()
