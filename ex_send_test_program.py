from headers import *
from sendutils import *

# miscellaneous test programs

"""
BASIC TESTS
"""
def test_basic():
    return ([
        PUSH(10),
        SETRESULT(),
        DONE()
    ], [])

def test_error():
    return ([
        PUSH(1),
        ERROR(),
        PUSH(2),
    ], [])

# should return 1
def test_swap():
    return ([
        RESET(),
        PUSH(1),
        PUSH(2),
        SWAP(),
        SETRESULT(),
        DONE()
    ], [])

# should return 3
def test_add():
    return ([
        RESET(),
        PUSH(1),
        PUSH(2),
        ADD(),
        SETRESULT(),
        DONE()
    ], [])

# should return 4
def test_load():
    return ([
        RESET(),
        PUSH(1),
        PUSH(2),
        PUSH(3),
        LOAD(1),
        LOAD(1),
        ADD(),
        SETRESULT(),
        DONE()
    ], [])

# should return 2
def test_load_store():
    return ([
        RESET(),
        PUSH(1),
        PUSH(0),
        PUSH(0),
        LOAD(0),
        DUP(),
        ADD(),
        STORE(1),
        LOAD(1),
        SETRESULT(),
        DONE()
    ], [])
# should return 1
def test_sub():
    return ([
        RESET(),
        PUSH(2),
        PUSH(3),
        SUB(),
        SETRESULT(),
        DONE(),
    ], [])

# should return 7
def test_if():
    return ([
        RESET(),
        PUSH(2),
        PUSH(3),
        GTE(),
        CJUMP(7),
        PUSH(5),
        JUMP(9),
        NOP(),
        PUSH(7),
        NOP(),
        SETRESULT(),
        DONE(),
    ], [])

# should return 5
def test_if2():
    return ([
        RESET(),
        PUSH(2),
        PUSH(1),
        GTE(),
        CJUMP(7),
        PUSH(5),
        JUMP(9),
        NOP(),
        PUSH(7),
        NOP(),
        SETRESULT(),
        DONE(),
    ], [])

"""
HARDCODED FIBONACCI
"""

# should return 5
def test_fib():
    return ([
        RESET(),
        PUSH(1),
        PUSH(1),
        SWAP(),
        OVER(),
        ADD(),
        SWAP(),
        OVER(),
        ADD(),
        SWAP(),
        OVER(),
        ADD(),
        SETRESULT(),
        DONE(),
    ], [])

# should return 5
def test_fib2():
    return ([
        RESET(),
        PUSH(1),
        PUSH(1),
        DUP(),
        ROT(),
        ADD(),
        DUP(),
        ROT(),
        ADD(),
        DUP(),
        ROT(),
        ADD(),
        SETRESULT(),
        DONE(),
    ], [])

"""
HARDCODED SOURCE ROUTING TESTS
"""

# this test needs to be sent from h1, ends up at h2
def test_source_routing():
    return ([
        SETEGRESS(),
    ], [
        STACK(1),
        STACK(2),
    ])

# this test needs to be sent from h1, ends up at h2
def test_source_routing2():
    return ([
        SETEGRESS(),
    ], [
        STACK(1),
        STACK(2),
        STACK(2),
        STACK(3),
        STACK(2),
    ])

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

# return maximum counter value along path
def test_max_counter():
    return ([
        LOAD(0),
        LOADREG(0),
        LTE(),
        CJUMP(6),
        LOADREG(0), # if counter > max, set max
        STORE(0),
        NOP(),
        LOAD(0),
        SETRESULT(),
        DONE()
    ], [
        STACK(0),
    ])

# read the packets-received counter for switches along the path
# return difference between minimum and maximum counter values
def test_counter_diffs():
    return ([
        LOAD(0),
        LOADREG(0),
        LTE(),
        CJUMP(6),
        LOADREG(0), # if counter > max, set max
        STORE(1),
        NOP(),
        LOAD(1),
        LOADREG(0),
        GTE(),
        CJUMP(13),
        LOADREG(0), # if counter < min, set min
        STORE(0),
        NOP(),
        LOAD(0),
        LOAD(1),
        SUB(),
        STORE(2),
        LOAD(2),
        DONE() # done pops the top value so we have to dup
    ], [
        STACK(100), # min count
        STACK(0), # max count
        STACK(0) # diff
    ])

programs = {
    "basic": test_basic(),
    "error": test_error(),
    "add": test_add(),
    "load": test_load(),
    "load_store": test_load_store(),
    "sub": test_sub(),
    "if": test_if(),
    "if2": test_if2(),
    "fib": test_fib(),
    "fib2": test_fib2(),
    "source_routing": test_source_routing(),
    "source_routing2": test_source_routing2(),
    "drop": test_drop(),
    "counter": test_counter(),
    "min_counter": test_min_counter(),
    "max_counter": test_max_counter(),
    "diff_counter": test_counter_diffs(),
}

def main():
    if len(sys.argv) < 3:
        print "send some test program"
        print "arguments: <destination> <program name>"
        print "valid program names: " + ", ".join(programs.keys())

    addr = socket.gethostbyname(sys.argv[1])
    program_name = sys.argv[2]
    instrs, stk = programs[program_name]
    send_pkt(addr, instrs, stk)

if __name__ == '__main__':
    main()