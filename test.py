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
        PUSH(1),
        STOREREG(5),
        PUSH(5),
        VARLOADREG(),
        SETEGRESS(),
    ]
    init_stack = []
    return prog, init_stack

def main():
    instrs, stk = test()
    send_probe(instrs, stk)

if __name__ == '__main__':
    main()
