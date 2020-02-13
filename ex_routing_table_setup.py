#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
from sendutils import *
from headers import *
from stitch import *

def main():
    print "set up registers in each switch for use as routing table"
    print "must be sent by h1"
    print "arguments: none"
    addr = socket.gethostbyname("10.0.9.99")
    instrs, stk = load_program("examples/routing_table_setup.json")
    send_pkt(addr, instrs, stk)

if __name__ == '__main__':
    main()
