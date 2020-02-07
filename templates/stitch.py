import json
import sys
from headers import *

# stack header factory 

def STACK(val = 0):
    return StackVal(value = val)

# instruction header factories

# load value from offset [pos] from bottom of stack
def LOAD(pos):
    return Instruction(opcode = i_load, arg = pos)

# copy top of stack to offset [pos] from bottom of stack
def STORE(pos):
    return Instruction(opcode = i_store, arg = pos)

def VARLOAD():
    return Instruction(opcode = i_varload, arg = 0)

def VARSTORE():
    return Instruction(opcode = i_varstore, arg = 0)

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

# unary not
def NOT():
    return Instruction(opcode = i_not, arg = 0)

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

# mark done
def DONE():
    return Instruction(opcode = i_done, arg = 0)

# return top of stack
def SETRESULT():
    return Instruction(opcode = i_setresult, arg = 0)

# no-op
def NOP():
    return Instruction(opcode = i_nop, arg = 0)

# mark error
def ERROR():
    return Instruction(opcode = i_error, arg = 0)

def LAST():
    return Instruction(opcode = i_last, arg = 0)

# load value from register [r] to top of stack
def LOADREG(r):
    return Instruction(opcode = i_loadreg, arg = r)

# store top of stack to register [r]
def STOREREG(r):
    return Instruction(opcode = i_storereg, arg = r)

def VARLOADREG():
    return Instruction(opcode = i_varloadreg, arg = 0)

def VARSTOREREG():
    return Instruction(opcode = i_varstorereg, arg = 0)

# push some standard metadata to top of stack (which one determined arg and hardware)
# values are extended or truncated (keeping the LSB) to fit int<32>
'''
v1model:
0 ingress_port;
1 packet_length;
2 enq_qdepth;
3 deq_qdepth;
4 egresss_spec;
'''
def METADATA(r):
    return Instruction(opcode = i_metadata, arg = r)

# write top of stack to egress port, this is also v1model-specific
def SETEGRESS():
    return Instruction(opcode = i_setegress)

# building a packet by putting the headers in the right order
def build_packet(pkt, instrs, init_stack = []):
    pkt /= Metadata()
    pkt /= Pdata(sp = len(init_stack))
    assert len(instrs) < MAX_INSTRS
    for insn in instrs:
        pkt /= insn
    # pad all programs to the desired number of instrs
    padding = MAX_INSTRS - len(instrs)
    while padding > 0:
        pkt /= ERROR()
        padding -=1
    pkt /= LAST()
    # initialize the stack
    for stk in init_stack:
        pkt /= stk
    padding = STACK_SIZE - len(init_stack)
    while padding > 0:
        pkt /= STACK()
        padding -=1
    return pkt

#helper function: checks that val >= 0 and val <= config[key]
def checkval(config, key, val):
    if val < 0 or val > config[key]:
        raise Exception("instruction argument out of bounds")

# config is a config object (dictionary representation of config.json)
# performs some basic sanity checks on the program
def parsefile(filename, config):
    instructions = []
    stack = []
    linecount = 0
    with open(filename, "r") as f:
        try:
            for line in f:
                linecount += 1
                line = line.strip()
                line = line.replace("//", " //")
                if line == "" or line.startswith("//"):
                    continue
                l = line.split()
                instr = l[0].lower()
                if instr == "load":
                    checkval(config, "stack-size", int(l[1]))
                    instructions.append(LOAD(int(l[1])))
                elif instr == "store":
                    checkval(config, "stack-size", int(l[1]))
                    instructions.append(STORE(int(l[1])))
                elif instr == "varload":
                    instructions.append(VARLOAD())
                elif instr == "varstore":
                    instructions,aooend(VARSTORE())
                elif instr == "push":
                    instructions.append(PUSH(int(l[1])))
                elif instr == "drop":
                    instructions.append(DROP())
                elif instr == "add":
                    instructions.append(ADD())
                elif instr == "mul":
                    instructions.append(MUL())
                elif instr == "sub":
                    instructions.append(SUB())
                elif instr == "sal":
                    instructions.append(SAL())
                elif instr == "sar":
                    instructions.append(SAR())
                elif instr == "neg":
                    instructions.append(NEG())
                elif instr == "not":
                    instructions.append(NOT())
                elif instr == "reset":
                    instructions.append(RESET())
                elif instr == "and":
                    instructions.append(AND())
                elif instr == "or":
                    instructions.append(OR())
                elif instr == "gt":
                    instructions.append(GT())
                elif instr == "gte":
                    instructions.append(GTE())
                elif instr == "lt":
                    instructions.append(LT())
                elif instr == "lte":
                    instructions.append(LTE())
                elif instr == "eq":
                    instructions.append(EQ())
                elif instr == "neq":
                    instructions.append(NEQ())
                elif instr == "dup":
                    instructions.append(DUP())
                elif instr == "swap":
                    instructions.append(SWAP())
                elif instr == "over":
                    instructions.append(OVER())
                elif instr == "rot":
                    instructions.append(ROT())
                elif instr == "jump":
                    checkval(config, "n-instrs", int(l[1]))
                    instructions.append(JUMP(int(l[1])))
                elif instr == "cjump":
                    checkval(config, "n-instrs", int(l[1]))
                    instructions.append(CJUMP(int(l[1])))
                elif instr == "done":
                    instructions.append(DONE())
                elif instr == "setresult":
                    instructions.append(SETRESULT())
                elif instr == "nop":
                    instructions.append(NOP())
                elif instr == "error":
                    instructions.append(ERROR())
                elif instr == "loadreg":
                    checkval(config, "n-registers", int(l[1]))
                    instructions.append(LOADREG(int(l[1])))
                elif instr == "storereg":
                    checkval(config, "n-registers", int(l[1]))
                    instructions.append(STOREREG(int(l[1])))
                elif instr == "varloadreg":
                    instructions.append(VARLOADREG())
                elif instr == "varstorereg":
                    instructions.append(VARSTOREREG())
                elif instr == "metadata":
                    if l[1] not in config["switch-metadata"]:
                        raise Exception("unknown metadata field!")
                    else:
                        instructions.append(METADATA(config["switch-metadata"][l[1]]))
                else:
                    raise Exception("no such instruction")
                elif instr == "setegress":
                    instructions.append(SETEGRESS())
                elif instr == "stack":
                    for i in l[1:]:
                        if i.startswith("//"):
                            break
                        stack.append(STACK(int(i)))
        except:
            print "error processing line %s" % str(linecount)
            print sys.exc_info()[0]
    if len(instructions) > config["n-instrs"]:
        raise Exception("maximum instruction count exceeded!")
    if len(stack) > config["stack-size"]:
        raise Exception("maximum stack size exceeded!")
    return instructions, stack

# input: program source file name, config object, packet to attach program to
# output: packet with attached program
def stitch_program(f, config, packet):
    instructions, stack = parsefile(f, config)
    return build_packet(packet, instructions, stack)


    
