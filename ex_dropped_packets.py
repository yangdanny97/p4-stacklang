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
            # when switch receives packet, increment counter and drop
            instrs, stk = load_program("examples/msg_incr_counter.json")
            send_pkt(addr, instrs, stk)
        else:
            # when switch receives packet, increment counter
            instrs, stk = load_program("examples/msg_dropped.json")
            send_pkt(addr, instrs, stk)
        time.sleep(1)

    # return minimum counter value along path
    instrs, stk = load_program("examples/test_min_counter.json")
    send_pkt(addr, instrs, stk)


if __name__ == '__main__':
    main()
