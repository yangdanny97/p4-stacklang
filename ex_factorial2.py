#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
from sendutils import *
from headers import *

def test_fact_regs(n):
    return ([
        RESET(),
        PUSH(n), # current number
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
        SETEGRESS(),
    ], [])

def main():
    if len(sys.argv) < 2:
        print "calculates factorial of <n> and returns result to sender"
        print "arguments: <n>"
        return

    addr = socket.gethostbyname("10.0.9.99")
    n = int(sys.argv[1])
    instrs, stk = test_fact_regs(n)
    send_probe(addr, instrs, stk)

if __name__ == '__main__':
    main()
