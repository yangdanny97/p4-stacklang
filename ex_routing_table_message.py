#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
from sendutils import *
from headers import *

def test_message(dest):
    init_stk = [
        STACK(dest)
    ]
    prog = [
        LOAD(0), # load destination
        VARLOADREG(), # load egress port value corresponding to destination
        SETEGRESS()
    ]
    return prog, init_stk

addresses = {
    1: "10.0.1.11",
    2: "10.0.2.22",
    3: "10.0.3.33"
}

def main():
    if len(sys.argv) < 2:
        print "sends a message that is routed based on register values on the switch"
        print "the result field will be 999"
        print "arguments: <destination host>"
        print "example send to host h1: ./ex_routing_table_message.py 1"

    dest = int(sys.argv[1])
    addr = socket.gethostbyname(addresses[dest])
    instrs, stk = test_message(dest)
    send_pkt(addr, instrs, stk)

if __name__ == '__main__':
    main()
