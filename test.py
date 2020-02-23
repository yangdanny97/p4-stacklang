#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import time
from sendutils import *
from headers import *
from stitch import *


def main():
    addr = socket.gethostbyname(sys.argv[1])
    instrs = []
    stack = []
    send_pkt(addr, instrs, stk)

if __name__ == '__main__':
    main()
