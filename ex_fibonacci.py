#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
from sendutils import *
from headers import *

def test_fib(n):
    return ([
        RESET(),
        PUSH(n - 2), # space reserved for n
        PUSH(1),
        PUSH(1),
        NOP(),
        PUSH(0), # if n <= 0 then jump to end
        LOAD(0),
        LTE(),
        CJUMP(17),
        DUP(),
        ROT(),
        ADD(),
        PUSH(1), # subtract 1 from current number
        LOAD(0),
        SUB(),
        STORE(0),
        JUMP(4), # jump to the first NOP
        NOP(),
        SETRESULT(),
        METADATA(0),
        SETEGRESS(),
    ], [])

def main():
    if len(sys.argv) < 2:
        print "calculates factorial of <n> and returns result to sender"
        print "arguments: <n>"

    addr = socket.gethostbyname("10.0.9.99")
    n = int(sys.argv[1])
    instrs, stk = test_fib(n)
    send_probe(addr, instrs, stk)

if __name__ == '__main__':
    main()
