from scapy.all import get_if_list, bind_layers
from scapy.all import Packet, Raw
from scapy.all import IP
from scapy.fields import *

# keep consistent with headers.p4
i_load = 0x00
i_store = 0x01
i_push = 0x02
i_drop = 0x03
i_add = 0x04
i_mul = 0x05
i_sub = 0x06
i_neg = 0x07
i_reset = 0x08
i_and = 0x09
i_or = 0x0A
i_gt = 0x0B
i_lt = 0x0C
i_lte = 0x0D
i_gte = 0x0E
i_eq = 0x0F
i_neq = 0x10
i_dup = 0x11
i_swap = 0x12
i_over = 0x13
i_rot = 0x14
i_jump = 0x15
i_cjump = 0x16
i_done = 0x17
i_error = 0x18
i_nop = 0x19
i_loadreg = 0x1A
i_storereg = 0x1B
i_metadata = 0x1C
i_sal = 0x1D
i_sar = 0x1E

PROTOCOL_NUM = 0x8F
MAX_STEPS = 250
STACK_SIZE = 32
MAX_INSTRS = 32

class Pdata(Packet):
    name = 'pdata'
    fields_desc = [
        IntField('pc', 0),
        IntField('sp', 0),
        BitField('steps', 0, 32),
        BitField('done_flg', 0, 1),
        BitField('err_flg', 0, 1),
        BitField('padding', 0, 6),
        IntField('result', 0),
        BitField('curr_instr_opcode', 0, 8),
        IntField('curr_instr_arg', 0),
    ]

class Instruction(Packet):
    name = 'Instruction'
    fields_desc = [
        BitField('opcode', 100, 8),
        IntField('arg', 0),
    ]

class Stack(Packet):
    name = 'stack'
    fields_desc = [
        IntField('i0', 0),
        IntField('i1', 0),
        IntField('i2', 0),
        IntField('i3', 0),
        IntField('i4', 0),
        IntField('i5', 0),
        IntField('i6', 0),
        IntField('i7', 0),
        IntField('i8', 0),
        IntField('i9', 0),
        IntField('i10', 0),
        IntField('i11', 0),
        IntField('i12', 0),
        IntField('i13', 0),
        IntField('i14', 0),
        IntField('i15', 0),
        IntField('i16', 0),
        IntField('i17', 0),
        IntField('i18', 0),
        IntField('i19', 0),
        IntField('i20', 0),
        IntField('i21', 0),
        IntField('i22', 0),
        IntField('i23', 0),
        IntField('i24', 0),
        IntField('i25', 0),
        IntField('i26', 0),
        IntField('i27', 0),
        IntField('i28', 0),
        IntField('i29', 0),
        IntField('i30', 0),
        IntField('i31', 0),
        IntField('i32', 0),
    ]

# instruction factories

# load value from offset [pos] from bottom of stack
def LOAD(pos):
    return Instruction(opcode = i_load, arg = pos)

# copy top of stack to offset [pos] from bottom of stack
def STORE(pos):
    return Instruction(opcode = i_store, arg = pos)

# push a value to top of stack
def PUSH(val):
    return Instruction(opcode = i_push, arg = val)

# pop
def DROP():
    return Instruction(opcode = i_drop, arg = 0)

# arith ops on top 2 things on stack; topmost == LHS, second == RHS
def ADD():
    return Instruction(opcode = i_add, arg = 0)

def MUL():
    return Instruction(opcode = i_mul, arg = 0)

def SUB():
    return Instruction(opcode = i_sub, arg = 0)

def SAL():
    return Instruction(opcode = i_sal, arg = 0)

def SAR():
    return Instruction(opcode = i_sar, arg = 0)

# negate top of stack
def NEG():
    return Instruction(opcode = i_neg, arg = 0)

# resets SP to 0
def RESET():
    return Instruction(opcode = i_reset, arg = 0)

# boolean ops on top of stack; topmost == LHS, second == RHS
# pushes 0 if false, 1 if true
def AND():
    return Instruction(opcode = i_and, arg = 0)

def OR():
    return Instruction(opcode = i_or, arg = 0)

def GT():
    return Instruction(opcode = i_gt, arg = 0)

def GTE():
    return Instruction(opcode = i_gte, arg = 0)

def LT():
    return Instruction(opcode = i_lt, arg = 0)

def LTE():
    return Instruction(opcode = i_lte, arg = 0)

def EQ():
    return Instruction(opcode = i_eq, arg = 0)

def NEQ():
    return Instruction(opcode = i_neq, arg = 0)

# stack ops

# duplicate top of stack
def DUP():
    return Instruction(opcode = i_dup, arg = 0)

# swap top 2 of stack
def SWAP():
    return Instruction(opcode = i_swap, arg = 0)

# push a copy of 2nd element from top
def OVER():
    return Instruction(opcode = i_over, arg = 0)

# rotate top 3 elements of stack, s.t. top becomes 3rd, and 3rd/2nd move one closer to top
def ROT():
    return Instruction(opcode = i_rot, arg = 0)

# set PC to [pc]
def JUMP(pc):
    return Instruction(opcode = i_jump, arg = pc)

# set PC to [pc] if top of stack > 0
def CJUMP(pc):
    return Instruction(opcode = i_cjump, arg = pc)

# mark done and return top of stack
def DONE():
    return Instruction(opcode = i_done, arg = 0)

# no-op
def NOP():
    return Instruction(opcode = i_nop, arg = 0)

# mark error
def ERROR():
    return Instruction(opcode = i_error, arg = 0)

# load value from register [r] to top of stack
def LOADREG(r):
    return Instruction(opcode = i_loadreg, arg = r)

# store top of stack to register [r]
def STOREREG(r):
    return Instruction(opcode = i_storereg, arg = r)

# push some standard metadata to top of stack (which one determined arg and hardware)
# values are extended or truncated to fit int<32>
'''
v1model:
0 ingress_port;
1 egress_spec;
2 egress_port;
3 instance_type;
4 packet_length;
5 enq_timestamp;
6 enq_qdepth;
7 deq_timedelta;
8 deq_qdepth;
9 ingress_global_timestamp;
10 egress_global_timestamp;
'''
def METADATA(r):
    return Instruction(opcode = i_metadata, arg = r)

# building a packet by putting the headers in the right order
def build_packet(pkt, instrs):
    pkt /= Pdata()
    assert len(instrs) < MAX_INSTRS
    for insn in instrs:
        pkt /= insn
    # pad all programs to the desired number of instrs
    padding = MAX_INSTRS - len(instrs)
    while padding > 0:
        pkt /= ERROR()
        padding -=1
    pkt /= Stack()
    return pkt

bind_layers(IP, Pdata, proto=PROTOCOL_NUM)
sys.setrecursionlimit(30000)