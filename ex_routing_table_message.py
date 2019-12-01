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

def main():
    if len(sys.argv) < 3:
        print "sends a message that is routed based on register values on the switch"
        print "the result field will be 999"
        print "arguments: <destination host> <message>"
        print "example send to host h1: ./ex_routing_table_message.py 1 hello"
        return

    dest = int(sys.argv[1])
    message = sys.argv[2]
    addr = socket.gethostbyname("10.0.9.99") # dummy address
    instrs, stk = test_message(dest)
    send_pkt(addr, instrs, stk, message)

if __name__ == '__main__':
    main()
