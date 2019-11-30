#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
from sendutils import *
from headers import *

def test():
    prog = [
        SETEGRESS(),
    ]
    init_stack = [
        STACK(1),
        STACK(2),
        STACK(2),
    ]
    return prog, init_stack

def main():
    addr = socket.gethostbyname("10.0.9.99")
    instrs, stk = test()
    send_probe(addr, instrs, stk)

if __name__ == '__main__':
    main()
