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

PROTOCOL_NUM = 0x8F
MAX_STEPS = 250
STACK_SIZE = 128
MAX_INSTRS = 128

class Pdata(Packet):
    name = 'pdata'
    fields_desc = [
        BitField('pc', 0, 8),
        BitField('sp', 0, 8),
        BitField('steps', 0, 8),
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
        BitField('opcode', 0, 8),
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
        IntField('i33', 0),
        IntField('i34', 0),
        IntField('i35', 0),
        IntField('i36', 0),
        IntField('i37', 0),
        IntField('i38', 0),
        IntField('i39', 0),
        IntField('i40', 0),
        IntField('i41', 0),
        IntField('i42', 0),
        IntField('i43', 0),
        IntField('i44', 0),
        IntField('i45', 0),
        IntField('i46', 0),
        IntField('i47', 0),
        IntField('i48', 0),
        IntField('i49', 0),
        IntField('i50', 0),
        IntField('i51', 0),
        IntField('i52', 0),
        IntField('i53', 0),
        IntField('i54', 0),
        IntField('i55', 0),
        IntField('i56', 0),
        IntField('i57', 0),
        IntField('i58', 0),
        IntField('i59', 0),
        IntField('i60', 0),
        IntField('i61', 0),
        IntField('i62', 0),
        IntField('i63', 0),
        IntField('i64', 0),
        IntField('i65', 0),
        IntField('i66', 0),
        IntField('i67', 0),
        IntField('i68', 0),
        IntField('i69', 0),
        IntField('i70', 0),
        IntField('i71', 0),
        IntField('i72', 0),
        IntField('i73', 0),
        IntField('i74', 0),
        IntField('i75', 0),
        IntField('i76', 0),
        IntField('i77', 0),
        IntField('i78', 0),
        IntField('i79', 0),
        IntField('i80', 0),
        IntField('i81', 0),
        IntField('i82', 0),
        IntField('i83', 0),
        IntField('i84', 0),
        IntField('i85', 0),
        IntField('i86', 0),
        IntField('i87', 0),
        IntField('i88', 0),
        IntField('i89', 0),
        IntField('i90', 0),
        IntField('i91', 0),
        IntField('i92', 0),
        IntField('i93', 0),
        IntField('i94', 0),
        IntField('i95', 0),
        IntField('i96', 0),
        IntField('i97', 0),
        IntField('i98', 0),
        IntField('i99', 0),
        IntField('i100', 0),
        IntField('i101', 0),
        IntField('i102', 0),
        IntField('i103', 0),
        IntField('i104', 0),
        IntField('i105', 0),
        IntField('i106', 0),
        IntField('i107', 0),
        IntField('i108', 0),
        IntField('i109', 0),
        IntField('i110', 0),
        IntField('i111', 0),
        IntField('i112', 0),
        IntField('i113', 0),
        IntField('i114', 0),
        IntField('i115', 0),
        IntField('i116', 0),
        IntField('i117', 0),
        IntField('i118', 0),
        IntField('i119', 0),
        IntField('i120', 0),
        IntField('i121', 0),
        IntField('i122', 0),
        IntField('i123', 0),
        IntField('i124', 0),
        IntField('i125', 0),
        IntField('i126', 0),
        IntField('i127', 0),
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


# building a packet by putting the headers in the right order
def build_packet(pkt, instrs):
    pkt /= Pdata()
    assert len(instrs) < MAX_INSTRS
    for insn in instrs:
        pkt /= insn
    # pad all programs to 128 instrs
    padding = MAX_INSTRS - len(instrs)
    while padding > 0:
        pkt /= ERROR()
        padding -=1
    pkt /= Stack()
    return pkt

bind_layers(IP, Pdata, proto=PROTOCOL_NUM)
sys.setrecursionlimit(30000)