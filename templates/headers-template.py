from scapy.all import get_if_list, bind_layers
from scapy.all import Packet, Raw
from scapy.all import IP
from scapy.fields import *

def get_if():
    ifs = get_if_list()
    iface = None  # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

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
i_not = 0x1F
i_setegress = 0x20
i_setresult = 0x21
i_varload = 0x22
i_varstore = 0x23
i_varloadreg = 0x24
i_varstorereg = 0x25
i_last = 0x26

# used by the controller to add rules
instrs = [
(i_load, "instr_load"),
(i_store, "instr_store"),
(i_push, "instr_push"),
(i_drop, "instr_drop"),
(i_add, "instr_add"),
(i_mul, "instr_mul"),
(i_sub, "instr_sub"),
(i_neg, "instr_sub"),
(i_reset, "instr_reset"),
(i_and, "instr_and"),
(i_or, "instr_or"),
(i_gt, "instr_gt"),
(i_lt, "instr_lt"),
(i_lte, "instr_lte"),
(i_gte, "instr_gte"),
(i_eq, "instr_eq"),
(i_neq, "instr_neq"),
(i_dup, "instr_dup"),
(i_swap, "instr_swap"),
(i_over, "instr_over"),
(i_rot, "instr_rot"),
(i_jump, "instr_jump"),
(i_cjump, "instr_cjump"),
(i_done, "instr_done"),
(i_error, "instr_error"),
(i_nop, "instr_nop"),
(i_loadreg, "instr_loadreg"),
(i_storereg, "instr_storereg"),
(i_metadata, "instr_metadata"),
(i_sal, "instr_sal"),
(i_sar, "instr_sar"),
(i_not, "instr_not"),
(i_setegress, "instr_setegress"),
(i_setresult, "instr_setresult"),
(i_varload, "instr_varload"),
(i_varstore, "instr_varstore"),
(i_varloadreg, "instr_varloadreg"),
(i_varstorereg, "instr_varstorereg"),
(i_last, "instr_error"),
]

PROTOCOL_NUM = 0x8F
MAX_STEPS = 250
STACK_SIZE = 32
MAX_INSTRS = 32

class Metadata(Packet):
    name = 'metadata'
    fields_desc = [
        BitField('ingress_port', 0, 9),
        BitField('packet_length', 0, 32),
        BitField('enq_qdepth', 0, 19),
        BitField('deq_qdepth', 0, 19),
        BitField('egress_spec', 0, 9),
        BitField('enq_timestamp', 0, 32),
        BitField('enq_timedelta', 0, 32),
        BitField('switch_id', 0, 32),
        BitField('ingress_timestamp', 0, 48),
        BitField('egress_timestamp', 0, 48)
    ]  

    def answers(self, other):
        return True

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

    def answers(self, other):
        return True

class Instruction(Packet):
    name = 'Instruction'
    fields_desc = [
        BitField('opcode', 100, 8),
        IntField('arg', 0),
    ]

    def answers(self, other):
        return True

class StackVal(Packet):
    name = 'StackVal'
    fields_desc = [
        IntField('value', 0),
    ]

    def answers(self, other):
        return True

# purely exists for pretty-printing
class Stack(Packet):
    name = 'Stack'
    fields_desc = [
<< stack_fields >>
    ]

    def answers(self, other):
        return True

bind_layers(IP, Metadata, proto=PROTOCOL_NUM)
bind_layers(Metadata, Pdata)
bind_layers(Pdata, Instruction)
bind_layers(Instruction, Stack, opcode=i_last)
bind_layers(Instruction, Instruction)

sys.setrecursionlimit(30000)