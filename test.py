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

# just a scratch file used for testing
def main():
    addr = socket.gethostbyname(sys.argv[1])
    # instrs = [PUSH(0), STOREREG(0), DONE()]
    #instrs = [LOADREG(0), DONE()]
   #  instrs = [METADATA(0), METADATA(0), METADATA(0), METADATA(0), DONE()]
    instrs = [
        PUSH(0),
        STOREREG(0)
    ]
    stack = []
    send_pkt(addr, instrs, stack)

if __name__ == '__main__':
    main()
