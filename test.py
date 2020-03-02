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
    # instrs = [PUSH(0), STOREREG(0), DONE()]
    #instrs = [LOADREG(0), DONE()]
   #  instrs = [METADATA(0), METADATA(0), METADATA(0), METADATA(0), DONE()]
    instrs = [
        RESET(),
        PUSH(5), # current number
        STOREREG(0),
        PUSH(1), # result
        STOREREG(1),
        NOP(),
        PUSH(1), # if n <= 1 then jump to end
        LOADREG(0),
        LTE(),
        CJUMP(19),
        LOADREG(0), # multiply current number with result and store it
        LOADREG(1),
        MUL(),
        STOREREG(1),
        PUSH(1), # subtract 1 from current number
        LOADREG(0),
        SUB(),
        STOREREG(0),
        JUMP(5), # jump to first NOP
        NOP(),
        LOADREG(1),
        SETRESULT(),
        METADATA(0),
        DONE()
    ]
    stack = []
    send_pkt(addr, instrs, stack)

if __name__ == '__main__':
    main()
