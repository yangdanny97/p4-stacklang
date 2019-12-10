#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import time
from sendutils import *
from headers import *


# when switch receives packet, increment counter and drop
def test_drop():
    return ([
        PUSH(1),
        LOADREG(0),
        ADD(),
        STOREREG(0),
        SETEGRESS(),
    ], [
        STACK(511),
    ])

# when switch receives packet, increment counter
def test_counter():
    return ([
        PUSH(1),
        LOADREG(0),
        ADD(),
        STOREREG(0),
        DONE()
    ], [])

# return minimum counter value along path
def test_min_counter():
    return ([
        LOAD(0),
        LOADREG(0),
        GTE(),
        CJUMP(6),
        LOADREG(0), # if counter < min, set min
        STORE(0),
        NOP(),
        LOAD(0),
        SETRESULT(),
        DONE()
    ], [
        STACK(100),
    ])

def main():
    if len(sys.argv) < 4:
        print "dropped packets detector test"
        print "send n_total packets to the destination, of which n_dropped will be dropped after the first hop"
        print "then, send a program to the destination whose result field should be how many packets made it to the destination n_total - n_dropped"
        print "arguments: <destination addr> <n_total> <n_dropped>"
        print "requirements: n_total > n_dropped"
        return

    addr = socket.gethostbyname(sys.argv[1])
    n_total = int(sys.argv[2])
    n_dropped = int(sys.argv[3])
    programs = ([0] * (n_total - n_dropped) + ([1] * n_dropped))
    random.shuffle(programs)
    for i in programs:
        if i == 0:
            instrs, stk = test_counter()
            send_pkt(addr, instrs, stk)
        else:
            instrs, stk = test_drop()
            send_pkt(addr, instrs, stk)
        time.sleep(1)

    instrs, stk = test_min_counter()
    send_pkt(addr, instrs, stk)


if __name__ == '__main__':
    main()
