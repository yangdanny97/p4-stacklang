from headers import *

def test_basic():
    return ([
        PUSH(10),
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
        PUSH(1),
        PUSH(2),
        SWAP(),
        DONE()
    ], [])

# should return 3
def test_add():
    return ([
        PUSH(1),
        PUSH(2),
        ADD(),
        DONE()
    ], [])

# should return 4
def test_load():
    return ([
        PUSH(1),
        PUSH(2),
        PUSH(3),
        LOAD(1),
        LOAD(1),
        ADD(),
        DONE()
    ], [])

# should return 2
def test_load_store():
    return ([
        PUSH(1),
        PUSH(0),
        PUSH(0),
        LOAD(0),
        DUP(),
        ADD(),
        STORE(1),
        LOAD(1),
        DONE()
    ], [])

# should return 5
def test_fib():
    return ([
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
        DONE(),
    ], [])

# should return 5
def test_fib2():
    return ([
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
        DONE(),
    ], [])

# should return 1
def test_sub():
    return ([
        PUSH(2),
        PUSH(3),
        SUB(),
        DONE(),
    ], [])

# should return 7
def test_if():
    return ([
        PUSH(2),
        PUSH(3),
        GTE(),
        CJUMP(6),
        PUSH(5),
        JUMP(8),
        NOP(),
        PUSH(7),
        NOP(),
        DONE(),
    ], [])

# should return 5
def test_if2():
    return ([
        PUSH(2),
        PUSH(1),
        GTE(),
        CJUMP(6),
        PUSH(5),
        JUMP(8),
        NOP(),
        PUSH(7),
        NOP(),
        DONE(),
    ], [])

def test_fib_n(n = 10):
    return ([
        PUSH(n - 2), # space reserved for n
        PUSH(1),
        PUSH(1),
        NOP(),
        PUSH(0), # if n <= 0 then jump to end
        LOAD(0),
        LTE(),
        CJUMP(16),
        DUP(),
        ROT(),
        ADD(),
        PUSH(1), # subtract 1 from current number
        LOAD(0),
        SUB(),
        STORE(0),
        JUMP(3), # jump to the first NOP
        NOP(),
        DONE()
    ], [])

def test_fact(n = 5):
    return ([
        PUSH(n), # current number
        PUSH(1), # result
        NOP(),
        PUSH(1), # if n <= 1 then jump to end
        LOAD(0),
        LTE(),
        CJUMP(16),
        LOAD(0), # multiply current number with result and store it
        LOAD(1),
        MUL(),
        STORE(1),
        PUSH(1), # subtract 1 from current number
        LOAD(0),
        SUB(),
        STORE(0),
        JUMP(2), # jump to first NOP
        NOP(),
        DONE()
    ], [])

def test_fact_regs(n = 5):
    return ([
        PUSH(n), # current number
        STOREREG(0),
        PUSH(1), # result
        STOREREG(1),
        NOP(),
        PUSH(1), # if n <= 1 then jump to end
        LOADREG(0),
        LTE(),
        CJUMP(18),
        LOADREG(0), # multiply current number with result and store it
        LOADREG(1),
        MUL(),
        STOREREG(1),
        PUSH(1), # subtract 1 from current number
        LOADREG(0),
        SUB(),
        STOREREG(0),
        JUMP(4), # jump to first NOP
        NOP(),
        DONE()
    ], [])

programs = {
    "basic": test_basic(),
    "error": test_error(),
    "add": test_add(),
    "load": test_load(),
    "load_store": test_load_store(),
    "fib": test_fib(),
    "fib2": test_fib2(),
    "fibn": test_fib_n(),
    "sub": test_sub(),
    "if": test_if(),
    "if2": test_if2(),
    "fact": test_fact()
}