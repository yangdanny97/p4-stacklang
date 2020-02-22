/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
***********************  INSTRUCTIONS  ***********************************
*************************************************************************/

// use an unassigned protocol number
const bit<8> PROTOCOL_NUM = 0x8F;
const bit<32> MAX_STEPS = 250;
const bit<32> STACK_SIZE = 64;
const bit<32> MAX_INSTRS = 65; //extra for special last instruction
const bit<32> NUM_REGISTERS = 32;

header instr_t {
    bit<8> opcode;
    int<32> arg;
}

header stack_t {
    int<32> value;
}

header my_metadata_t {
    bit<9> ingress_port;
    bit<32> packet_length;
    bit<19> enq_qdepth;
    bit<19> deq_qdepth;
    bit<9> egress_spec;
    bit<32> enq_timestamp;
    bit<32> deq_timedelta;
    bit<32> switch_id;
}

header pdata_t {
    bit<32> pc; // program counter
    bit<32> sp; // stack pointer to next EMPTY slot
    bit<32> steps;
    bit<1> done_flg; // flag set when execution ends
    bit<1> err_flg; // flag set if there is an error
    bit<6> padding;
    int<32> result;
    bit<8> curr_instr_opcode;
    int<32> curr_instr_arg;
}

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    my_metadata_t my_metadata;
    pdata_t pdata;
    instr_t[MAX_INSTRS] instructions;
    stack_t[STACK_SIZE] stack;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    bit<32> n = STACK_SIZE;
    bit<32> m = MAX_INSTRS;

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTOCOL_NUM: parse_metadata;
            default: accept;
        }
    }

    state parse_metadata {
        packet.extract(hdr.my_metadata);
        transition parse_pdata;
    }

    state parse_pdata {
        packet.extract(hdr.pdata);
        transition parse_instructions;
    }

    state parse_instructions {
        packet.extract(hdr.instructions.next);
        m = m - 1;
        transition select(m) {
            0: parse_stack;
            default: parse_instructions;
        }
    }

    state parse_stack {
        packet.extract(hdr.stack.next);
        n = n - 1;
        transition select(n) {
            0: accept;
            default: parse_stack;
        }
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply { }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    register<int<32>>(STACK_SIZE) stack;
    register<bit<8>>(MAX_INSTRS) opcodes;
    register<int<32>>(MAX_INSTRS) args;
    register<int<32>>(NUM_REGISTERS) swregs;

    action parse_instructions() {
        opcodes.write(0, hdr.instructions[0].opcode);
        opcodes.write(1, hdr.instructions[1].opcode);
        opcodes.write(2, hdr.instructions[2].opcode);
        opcodes.write(3, hdr.instructions[3].opcode);
        opcodes.write(4, hdr.instructions[4].opcode);
        opcodes.write(5, hdr.instructions[5].opcode);
        opcodes.write(6, hdr.instructions[6].opcode);
        opcodes.write(7, hdr.instructions[7].opcode);
        opcodes.write(8, hdr.instructions[8].opcode);
        opcodes.write(9, hdr.instructions[9].opcode);
        opcodes.write(10, hdr.instructions[10].opcode);
        opcodes.write(11, hdr.instructions[11].opcode);
        opcodes.write(12, hdr.instructions[12].opcode);
        opcodes.write(13, hdr.instructions[13].opcode);
        opcodes.write(14, hdr.instructions[14].opcode);
        opcodes.write(15, hdr.instructions[15].opcode);
        opcodes.write(16, hdr.instructions[16].opcode);
        opcodes.write(17, hdr.instructions[17].opcode);
        opcodes.write(18, hdr.instructions[18].opcode);
        opcodes.write(19, hdr.instructions[19].opcode);
        opcodes.write(20, hdr.instructions[20].opcode);
        opcodes.write(21, hdr.instructions[21].opcode);
        opcodes.write(22, hdr.instructions[22].opcode);
        opcodes.write(23, hdr.instructions[23].opcode);
        opcodes.write(24, hdr.instructions[24].opcode);
        opcodes.write(25, hdr.instructions[25].opcode);
        opcodes.write(26, hdr.instructions[26].opcode);
        opcodes.write(27, hdr.instructions[27].opcode);
        opcodes.write(28, hdr.instructions[28].opcode);
        opcodes.write(29, hdr.instructions[29].opcode);
        opcodes.write(30, hdr.instructions[30].opcode);
        opcodes.write(31, hdr.instructions[31].opcode);
        opcodes.write(32, hdr.instructions[32].opcode);
        opcodes.write(33, hdr.instructions[33].opcode);
        opcodes.write(34, hdr.instructions[34].opcode);
        opcodes.write(35, hdr.instructions[35].opcode);
        opcodes.write(36, hdr.instructions[36].opcode);
        opcodes.write(37, hdr.instructions[37].opcode);
        opcodes.write(38, hdr.instructions[38].opcode);
        opcodes.write(39, hdr.instructions[39].opcode);
        opcodes.write(40, hdr.instructions[40].opcode);
        opcodes.write(41, hdr.instructions[41].opcode);
        opcodes.write(42, hdr.instructions[42].opcode);
        opcodes.write(43, hdr.instructions[43].opcode);
        opcodes.write(44, hdr.instructions[44].opcode);
        opcodes.write(45, hdr.instructions[45].opcode);
        opcodes.write(46, hdr.instructions[46].opcode);
        opcodes.write(47, hdr.instructions[47].opcode);
        opcodes.write(48, hdr.instructions[48].opcode);
        opcodes.write(49, hdr.instructions[49].opcode);
        opcodes.write(50, hdr.instructions[50].opcode);
        opcodes.write(51, hdr.instructions[51].opcode);
        opcodes.write(52, hdr.instructions[52].opcode);
        opcodes.write(53, hdr.instructions[53].opcode);
        opcodes.write(54, hdr.instructions[54].opcode);
        opcodes.write(55, hdr.instructions[55].opcode);
        opcodes.write(56, hdr.instructions[56].opcode);
        opcodes.write(57, hdr.instructions[57].opcode);
        opcodes.write(58, hdr.instructions[58].opcode);
        opcodes.write(59, hdr.instructions[59].opcode);
        opcodes.write(60, hdr.instructions[60].opcode);
        opcodes.write(61, hdr.instructions[61].opcode);
        opcodes.write(62, hdr.instructions[62].opcode);
        opcodes.write(63, hdr.instructions[63].opcode);

        args.write(0, hdr.instructions[0].arg);
        args.write(1, hdr.instructions[1].arg);
        args.write(2, hdr.instructions[2].arg);
        args.write(3, hdr.instructions[3].arg);
        args.write(4, hdr.instructions[4].arg);
        args.write(5, hdr.instructions[5].arg);
        args.write(6, hdr.instructions[6].arg);
        args.write(7, hdr.instructions[7].arg);
        args.write(8, hdr.instructions[8].arg);
        args.write(9, hdr.instructions[9].arg);
        args.write(10, hdr.instructions[10].arg);
        args.write(11, hdr.instructions[11].arg);
        args.write(12, hdr.instructions[12].arg);
        args.write(13, hdr.instructions[13].arg);
        args.write(14, hdr.instructions[14].arg);
        args.write(15, hdr.instructions[15].arg);
        args.write(16, hdr.instructions[16].arg);
        args.write(17, hdr.instructions[17].arg);
        args.write(18, hdr.instructions[18].arg);
        args.write(19, hdr.instructions[19].arg);
        args.write(20, hdr.instructions[20].arg);
        args.write(21, hdr.instructions[21].arg);
        args.write(22, hdr.instructions[22].arg);
        args.write(23, hdr.instructions[23].arg);
        args.write(24, hdr.instructions[24].arg);
        args.write(25, hdr.instructions[25].arg);
        args.write(26, hdr.instructions[26].arg);
        args.write(27, hdr.instructions[27].arg);
        args.write(28, hdr.instructions[28].arg);
        args.write(29, hdr.instructions[29].arg);
        args.write(30, hdr.instructions[30].arg);
        args.write(31, hdr.instructions[31].arg);
        args.write(32, hdr.instructions[32].arg);
        args.write(33, hdr.instructions[33].arg);
        args.write(34, hdr.instructions[34].arg);
        args.write(35, hdr.instructions[35].arg);
        args.write(36, hdr.instructions[36].arg);
        args.write(37, hdr.instructions[37].arg);
        args.write(38, hdr.instructions[38].arg);
        args.write(39, hdr.instructions[39].arg);
        args.write(40, hdr.instructions[40].arg);
        args.write(41, hdr.instructions[41].arg);
        args.write(42, hdr.instructions[42].arg);
        args.write(43, hdr.instructions[43].arg);
        args.write(44, hdr.instructions[44].arg);
        args.write(45, hdr.instructions[45].arg);
        args.write(46, hdr.instructions[46].arg);
        args.write(47, hdr.instructions[47].arg);
        args.write(48, hdr.instructions[48].arg);
        args.write(49, hdr.instructions[49].arg);
        args.write(50, hdr.instructions[50].arg);
        args.write(51, hdr.instructions[51].arg);
        args.write(52, hdr.instructions[52].arg);
        args.write(53, hdr.instructions[53].arg);
        args.write(54, hdr.instructions[54].arg);
        args.write(55, hdr.instructions[55].arg);
        args.write(56, hdr.instructions[56].arg);
        args.write(57, hdr.instructions[57].arg);
        args.write(58, hdr.instructions[58].arg);
        args.write(59, hdr.instructions[59].arg);
        args.write(60, hdr.instructions[60].arg);
        args.write(61, hdr.instructions[61].arg);
        args.write(62, hdr.instructions[62].arg);
        args.write(63, hdr.instructions[63].arg);

    }

    action parse_stack() {
        stack.write(0, hdr.stack[0].value);
        stack.write(1, hdr.stack[1].value);
        stack.write(2, hdr.stack[2].value);
        stack.write(3, hdr.stack[3].value);
        stack.write(4, hdr.stack[4].value);
        stack.write(5, hdr.stack[5].value);
        stack.write(6, hdr.stack[6].value);
        stack.write(7, hdr.stack[7].value);
        stack.write(8, hdr.stack[8].value);
        stack.write(9, hdr.stack[9].value);
        stack.write(10, hdr.stack[10].value);
        stack.write(11, hdr.stack[11].value);
        stack.write(12, hdr.stack[12].value);
        stack.write(13, hdr.stack[13].value);
        stack.write(14, hdr.stack[14].value);
        stack.write(15, hdr.stack[15].value);
        stack.write(16, hdr.stack[16].value);
        stack.write(17, hdr.stack[17].value);
        stack.write(18, hdr.stack[18].value);
        stack.write(19, hdr.stack[19].value);
        stack.write(20, hdr.stack[20].value);
        stack.write(21, hdr.stack[21].value);
        stack.write(22, hdr.stack[22].value);
        stack.write(23, hdr.stack[23].value);
        stack.write(24, hdr.stack[24].value);
        stack.write(25, hdr.stack[25].value);
        stack.write(26, hdr.stack[26].value);
        stack.write(27, hdr.stack[27].value);
        stack.write(28, hdr.stack[28].value);
        stack.write(29, hdr.stack[29].value);
        stack.write(30, hdr.stack[30].value);
        stack.write(31, hdr.stack[31].value);
        stack.write(32, hdr.stack[32].value);
        stack.write(33, hdr.stack[33].value);
        stack.write(34, hdr.stack[34].value);
        stack.write(35, hdr.stack[35].value);
        stack.write(36, hdr.stack[36].value);
        stack.write(37, hdr.stack[37].value);
        stack.write(38, hdr.stack[38].value);
        stack.write(39, hdr.stack[39].value);
        stack.write(40, hdr.stack[40].value);
        stack.write(41, hdr.stack[41].value);
        stack.write(42, hdr.stack[42].value);
        stack.write(43, hdr.stack[43].value);
        stack.write(44, hdr.stack[44].value);
        stack.write(45, hdr.stack[45].value);
        stack.write(46, hdr.stack[46].value);
        stack.write(47, hdr.stack[47].value);
        stack.write(48, hdr.stack[48].value);
        stack.write(49, hdr.stack[49].value);
        stack.write(50, hdr.stack[50].value);
        stack.write(51, hdr.stack[51].value);
        stack.write(52, hdr.stack[52].value);
        stack.write(53, hdr.stack[53].value);
        stack.write(54, hdr.stack[54].value);
        stack.write(55, hdr.stack[55].value);
        stack.write(56, hdr.stack[56].value);
        stack.write(57, hdr.stack[57].value);
        stack.write(58, hdr.stack[58].value);
        stack.write(59, hdr.stack[59].value);
        stack.write(60, hdr.stack[60].value);
        stack.write(61, hdr.stack[61].value);
        stack.write(62, hdr.stack[62].value);
        stack.write(63, hdr.stack[63].value);

    }

    action deparse_stack() {
        stack.read(hdr.stack[0].value, 0);
        stack.read(hdr.stack[1].value, 1);
        stack.read(hdr.stack[2].value, 2);
        stack.read(hdr.stack[3].value, 3);
        stack.read(hdr.stack[4].value, 4);
        stack.read(hdr.stack[5].value, 5);
        stack.read(hdr.stack[6].value, 6);
        stack.read(hdr.stack[7].value, 7);
        stack.read(hdr.stack[8].value, 8);
        stack.read(hdr.stack[9].value, 9);
        stack.read(hdr.stack[10].value, 10);
        stack.read(hdr.stack[11].value, 11);
        stack.read(hdr.stack[12].value, 12);
        stack.read(hdr.stack[13].value, 13);
        stack.read(hdr.stack[14].value, 14);
        stack.read(hdr.stack[15].value, 15);
        stack.read(hdr.stack[16].value, 16);
        stack.read(hdr.stack[17].value, 17);
        stack.read(hdr.stack[18].value, 18);
        stack.read(hdr.stack[19].value, 19);
        stack.read(hdr.stack[20].value, 20);
        stack.read(hdr.stack[21].value, 21);
        stack.read(hdr.stack[22].value, 22);
        stack.read(hdr.stack[23].value, 23);
        stack.read(hdr.stack[24].value, 24);
        stack.read(hdr.stack[25].value, 25);
        stack.read(hdr.stack[26].value, 26);
        stack.read(hdr.stack[27].value, 27);
        stack.read(hdr.stack[28].value, 28);
        stack.read(hdr.stack[29].value, 29);
        stack.read(hdr.stack[30].value, 30);
        stack.read(hdr.stack[31].value, 31);
        stack.read(hdr.stack[32].value, 32);
        stack.read(hdr.stack[33].value, 33);
        stack.read(hdr.stack[34].value, 34);
        stack.read(hdr.stack[35].value, 35);
        stack.read(hdr.stack[36].value, 36);
        stack.read(hdr.stack[37].value, 37);
        stack.read(hdr.stack[38].value, 38);
        stack.read(hdr.stack[39].value, 39);
        stack.read(hdr.stack[40].value, 40);
        stack.read(hdr.stack[41].value, 41);
        stack.read(hdr.stack[42].value, 42);
        stack.read(hdr.stack[43].value, 43);
        stack.read(hdr.stack[44].value, 44);
        stack.read(hdr.stack[45].value, 45);
        stack.read(hdr.stack[46].value, 46);
        stack.read(hdr.stack[47].value, 47);
        stack.read(hdr.stack[48].value, 48);
        stack.read(hdr.stack[49].value, 49);
        stack.read(hdr.stack[50].value, 50);
        stack.read(hdr.stack[51].value, 51);
        stack.read(hdr.stack[52].value, 52);
        stack.read(hdr.stack[53].value, 53);
        stack.read(hdr.stack[54].value, 54);
        stack.read(hdr.stack[55].value, 55);
        stack.read(hdr.stack[56].value, 56);
        stack.read(hdr.stack[57].value, 57);
        stack.read(hdr.stack[58].value, 58);
        stack.read(hdr.stack[59].value, 59);
        stack.read(hdr.stack[60].value, 60);
        stack.read(hdr.stack[61].value, 61);
        stack.read(hdr.stack[62].value, 62);
        stack.read(hdr.stack[63].value, 63);

    }

    action read_current_instr() {
        opcodes.read(hdr.pdata.curr_instr_opcode, hdr.pdata.pc);
        args.read(hdr.pdata.curr_instr_arg, hdr.pdata.pc);
    }

    action increment_pc() {
        hdr.pdata.pc = hdr.pdata.pc + 32w1;
    }

    action increment_steps() {
        hdr.pdata.steps = hdr.pdata.steps + 32w1;
    }

    action ipush() {
        stack.write(hdr.pdata.sp, hdr.pdata.curr_instr_arg);
        hdr.pdata.sp = hdr.pdata.sp + 32w1;
    }

    action idrop() {
        //overwrite dropped stack value with 0
        hdr.pdata.sp = hdr.pdata.sp - 32w1;
        stack.write(hdr.pdata.sp, 0);
    }


    action instr_push() {
        ipush();
        increment_pc();
    }

    action instr_drop() {
        idrop();
        increment_pc();
    }

    action instr_load() {
        bit<32> offset = (bit<32>) hdr.pdata.curr_instr_arg;
        stack.read(hdr.pdata.curr_instr_arg, offset);
        ipush();
        increment_pc();
    }

    action instr_store() {
        int<32> top;
        stack.read(top, hdr.pdata.sp - 32w1);
        bit<32> offset = (bit<32>) hdr.pdata.curr_instr_arg;
        stack.write(offset, top);
        idrop();
        increment_pc();
    }

    action instr_add() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.sp - 32w1);
        stack.read(r, hdr.pdata.sp - 32w2);
        idrop();
        idrop();
        hdr.pdata.curr_instr_arg = l + r;
        ipush();
        increment_pc();
    }

    action instr_mul() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.sp - 32w1);
        stack.read(r, hdr.pdata.sp - 32w2);
        idrop();
        idrop();
        hdr.pdata.curr_instr_arg = l * r;
        ipush();
        increment_pc();
    }

    action instr_sub() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.sp - 32w1);
        stack.read(r, hdr.pdata.sp - 32w2);
        idrop();
        idrop();
        hdr.pdata.curr_instr_arg = l - r;
        ipush();
        increment_pc();
    }

    action instr_neg() {
        int<32> top;
        stack.read(top, hdr.pdata.sp - 32w1);
        idrop();
        hdr.pdata.curr_instr_arg = -top;
        ipush();
        increment_pc();
    }

    action instr_not() {
        int<32> top;
        stack.read(top, hdr.pdata.sp - 1);
        idrop();
        if (top > 0) {
            hdr.pdata.curr_instr_arg = 0;
        } else {
            hdr.pdata.curr_instr_arg = 1;
        }
        ipush();
        increment_pc();
    }

    action instr_sal() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.sp - 32w1);
        stack.read(r, hdr.pdata.sp - 32w2);
        idrop();
        idrop();
        hdr.pdata.curr_instr_arg = l << (bit<8>) (bit<32>) r;
        ipush();
        increment_pc();
    }

    action instr_sar() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.sp - 32w1);
        stack.read(r, hdr.pdata.sp - 32w2);
        idrop();
        idrop();
        hdr.pdata.curr_instr_arg = l >> (bit<8>) (bit<32>) r;
        ipush();
        increment_pc();
    }

    action instr_reset() {
        hdr.pdata.sp = 32w0;
        increment_pc();
    }

    action instr_and() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.sp - 32w1);
        stack.read(r, hdr.pdata.sp - 32w2);
        idrop();
        idrop();
        if (l > 0 && r > 0) {
            hdr.pdata.curr_instr_arg = 1;
        } else {
            hdr.pdata.curr_instr_arg = 0;
        }
        ipush();
        increment_pc();
    }

    action instr_or() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.sp - 32w1);
        stack.read(r, hdr.pdata.sp - 32w2);
        idrop();
        idrop();
        if (l > 0 || r > 0) {
            hdr.pdata.curr_instr_arg = 1;
        } else {
            hdr.pdata.curr_instr_arg = 0;
        }
        ipush();
        increment_pc();
    }

    action instr_gt() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.sp - 32w1);
        stack.read(r, hdr.pdata.sp - 32w2);
        idrop();
        idrop();
        if (l > r) {
            hdr.pdata.curr_instr_arg = 1;
        } else {
            hdr.pdata.curr_instr_arg = 0;
        }
        ipush();
        increment_pc();
    }

    action instr_lt() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.sp - 32w1);
        stack.read(r, hdr.pdata.sp - 32w2);
        idrop();
        idrop();
        if (l < r) {
            hdr.pdata.curr_instr_arg = 1;
        } else {
            hdr.pdata.curr_instr_arg = 0;
        }
        ipush();
        increment_pc();
    }

    action instr_gte() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.sp - 32w1);
        stack.read(r, hdr.pdata.sp - 32w2);
        idrop();
        idrop();
        if (l >= r) {
            hdr.pdata.curr_instr_arg = 1;
        } else {
            hdr.pdata.curr_instr_arg = 0;
        }
        ipush();
        increment_pc();
    }

    action instr_lte() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.sp - 32w1);
        stack.read(r, hdr.pdata.sp - 32w2);
        idrop();
        idrop();
        if (l <= r) {
            hdr.pdata.curr_instr_arg = 1;
        } else {
            hdr.pdata.curr_instr_arg = 0;
        }
        ipush();
        increment_pc();
    }

    action instr_eq() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.sp - 32w1);
        stack.read(r, hdr.pdata.sp - 32w2);
        idrop();
        idrop();
        if (l == r) {
            hdr.pdata.curr_instr_arg = 1;
        } else {
            hdr.pdata.curr_instr_arg = 0;
        }
        ipush();
        increment_pc();
    }

    action instr_neq() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.sp - 32w1);
        stack.read(r, hdr.pdata.sp - 32w2);
        idrop();
        idrop();
        if (l != r) {
            hdr.pdata.curr_instr_arg = 1;
        } else {
            hdr.pdata.curr_instr_arg = 0;
        }
        ipush();
        increment_pc();
    }

    action instr_dup() {
        int<32> top;
        stack.read(top, hdr.pdata.sp - 32w1);
        hdr.pdata.curr_instr_arg = top;
        ipush();
        increment_pc();
    }

    action instr_swap() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.sp - 32w1);
        stack.read(r, hdr.pdata.sp - 32w2);
        stack.write(hdr.pdata.sp - 32w2, l);
        stack.write(hdr.pdata.sp - 32w1, r);
        increment_pc();
    }

    action instr_over() {
        int<32> second;
        stack.read(second, hdr.pdata.sp - 32w2);
        hdr.pdata.curr_instr_arg = second;
        ipush();
        increment_pc();
    }

    action instr_rot() {
        int<32> a;
        int<32> b;
        int<32> c;
        stack.read(c, hdr.pdata.sp - 32w1);
        stack.read(b, hdr.pdata.sp - 32w2);
        stack.read(a, hdr.pdata.sp - 32w3);
        stack.write(hdr.pdata.sp - 32w1, b);
        stack.write(hdr.pdata.sp - 32w2, a);
        stack.write(hdr.pdata.sp - 32w3, c);
        increment_pc();
    }

    action instr_jump() {
        bit<32> pc = (bit<32>) hdr.pdata.curr_instr_arg;
        hdr.pdata.pc = pc;
    }

    action instr_cjump() {
        bit<32> pc = (bit<32>) hdr.pdata.curr_instr_arg;
        int<32> top;
        stack.read(top, hdr.pdata.sp - 32w1);
        idrop();
        if (top > 0) {
            hdr.pdata.pc = pc;
        } else {
            hdr.pdata.pc = hdr.pdata.pc + 32w1;
        }
    }

    action instr_done() {
        hdr.pdata.done_flg = 1w1;
    }

    action instr_setresult() {
        stack.read(hdr.pdata.result, hdr.pdata.sp - 32w1);
        idrop();
        increment_pc();
    }

    action instr_error() {
        hdr.pdata.err_flg = 1w1;
    }

    action instr_nop() {
        increment_pc();
     }

    action instr_loadreg() {
        bit<32> reg = (bit<32>) hdr.pdata.curr_instr_arg;
        swregs.read(hdr.pdata.curr_instr_arg, reg);
        ipush();
        increment_pc();
    }

    action instr_storereg() {
        int<32> top;
        stack.read(top, hdr.pdata.sp - 32w1);
        bit<32> reg = (bit<32>) hdr.pdata.curr_instr_arg;
        swregs.write(reg, top);
        idrop();
        increment_pc();
    }

    action instr_varload() {
        int<32> offset;
        stack.read(offset, hdr.pdata.sp - 32w1);
        idrop();
        stack.read(hdr.pdata.curr_instr_arg, (bit<32>) offset);
        ipush();
        increment_pc();
    }

    action instr_varloadreg() {
        int<32> reg;
        stack.read(reg, hdr.pdata.sp - 32w1);
        idrop();
        swregs.read(hdr.pdata.curr_instr_arg, (bit<32>) reg);
        ipush();
        increment_pc();
    }

    action instr_varstorereg() {
        int<32> reg;
        int<32> val;
        stack.read(reg, hdr.pdata.sp - 32w1);
        stack.read(val, hdr.pdata.sp - 32w2);
        idrop();
        idrop();
        swregs.write((bit<32>) reg, val);
        increment_pc();
    }

    action instr_varstore() {
        int<32> offset;
        int<32> val;
        stack.read(offset, hdr.pdata.sp - 32w1);
        stack.read(val, hdr.pdata.sp - 32w2);
        idrop();
        idrop();
        stack.write((bit<32>) offset, val);
        increment_pc();
    }

    action instr_metadata_ingress() {
        // TARGET-SPECIFIC
        int<32> code = hdr.pdata.curr_instr_arg;
        if (code == 0) {
            hdr.pdata.curr_instr_arg = (int<32>) (bit<32>) hdr.my_metadata.ingress_port;
        } else
        if (code == 1) {
            hdr.pdata.curr_instr_arg = (int<32>) hdr.my_metadata.packet_length;
        } else 
        if (code == 2) { // egress
            hdr.pdata.curr_instr_arg = 0;
        } else
        if (code == 3) { // egress
            hdr.pdata.curr_instr_arg = 0;
        } else
        if (code == 4) {
            hdr.pdata.curr_instr_arg = (int<32>) (bit<32>) hdr.my_metadata.egress_spec;
        } else
        if (code == 5) { // egress
            hdr.pdata.curr_instr_arg = 0;
        } else
        if (code == 6) { // egress
            hdr.pdata.curr_instr_arg = 0;
        } else
        if (code == 7) {
            hdr.pdata.curr_instr_arg = (int<32>) (bit<32>) hdr.my_metadata.switch_id;
        }
        ipush();
        // push a placeholder 0 for egress-fields, don't increment PC until egress
    }

    action instr_setegress() {
        // TARGET-SPECIFIC
        int<32> top;
        stack.read(top, hdr.pdata.sp - 32w1);
        idrop();
        standard_metadata.egress_spec = (bit<9>) (bit<32>) top;
        hdr.pdata.done_flg = 1w1;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table instruction_table_ingress {
        key = {
            hdr.pdata.curr_instr_opcode: exact;
        }
        actions = {
            instr_load;
            instr_store;
            instr_push;
            instr_drop;
            instr_add;
            instr_mul;
            instr_sub;
            instr_neg;
            instr_reset;
            instr_and;
            instr_or;
            instr_gt;
            instr_lt;
            instr_lte;
            instr_gte;
            instr_eq;
            instr_neq;
            instr_dup;
            instr_swap;
            instr_over;
            instr_rot;
            instr_jump;
            instr_cjump;
            instr_done;
            instr_error;
            instr_nop;
            instr_loadreg;
            instr_storereg;
            instr_metadata_ingress;
            instr_sal;
            instr_sar;
            instr_not;
            instr_setegress;
            instr_setresult;
            instr_varload;
            instr_varstore;
            instr_varloadreg;
            instr_varstorereg;
        }
        default_action = instr_error();
        const entries = {
            0x00 : instr_load();
            0x01 : instr_store();
            0x02 : instr_push();
            0x03 : instr_drop();
            0x04 : instr_add();
            0x05 : instr_mul();
            0x06 : instr_sub();
            0x07 : instr_sub();
            0x08 : instr_reset();
            0x09 : instr_and();
            0x0A : instr_or();
            0x0B : instr_gt();
            0x0C : instr_lt();
            0x0D : instr_lte();
            0x0E : instr_gte();
            0x0F : instr_eq();
            0x10 : instr_neq();
            0x11 : instr_dup();
            0x12 : instr_swap();
            0x13 : instr_over();
            0x14 : instr_rot();
            0x15 : instr_jump();
            0x16 : instr_cjump();
            0x17 : instr_done();
            0x18 : instr_error();
            0x19 : instr_nop();
            0x1A : instr_loadreg();
            0x1B : instr_storereg();
            0x1C : instr_metadata_ingress();
            0x1D : instr_sal();
            0x1E : instr_sar();
            0x1F : instr_not();
            0x20 : instr_setegress();
            0x21 : instr_setresult();
            0x22 : instr_varload();
            0x23 : instr_varstore();
            0x24 : instr_varloadreg();
            0x25 : instr_varstorereg();
            0x26 : instr_error(); // last is treated as error
        } 
    }

    action set_switch_id(int<32> switch_id) {
        hdr.my_metadata.switch_id = (bit<32>) switch_id;
    }

    table switch_id {
        key = {
            hdr.ipv4.protocol: exact;
        }

        actions = {
            set_switch_id;
            NoAction;
        }

        default_action = NoAction();
    }

    apply {
        switch_id.apply();
        ipv4_lpm.apply();

        // if not recirculated then write metadata fields
        if (standard_metadata.ingress_port != 9w7) {
            hdr.my_metadata.ingress_port = standard_metadata.ingress_port;
            hdr.my_metadata.packet_length = standard_metadata.packet_length;
            hdr.my_metadata.egress_spec = standard_metadata.egress_spec;
        }

        // done flag set -> continue to next hop
        if (hdr.pdata.done_flg == 1w1) { } 
        // error flag set -> continue to next hop
        else if (hdr.pdata.err_flg == 1w1) { } 
        // max steps reached -> set error flag
        else if (hdr.pdata.steps > MAX_STEPS) {
            hdr.pdata.err_flg = 1w1;
        }
        // regular instruction: run instruction and recirculate
        // (unless egress port is over-ridden by circulation)
        else {
            // atomic to prevent races when stack/instrs are temporarily moved to registers
            @atomic {
                // don't decrement ttl for self-forwarding
                hdr.ipv4.ttl = hdr.ipv4.ttl + 1;
                parse_instructions();
                parse_stack();
                read_current_instr();
                instruction_table_ingress.apply();
                increment_steps();
                deparse_stack();
                standard_metadata.egress_spec = 9w6;
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    register<int<32>>(STACK_SIZE) stack;
    register<bit<8>>(MAX_INSTRS) opcodes;
    register<int<32>>(MAX_INSTRS) args;

    action parse_instructions() {
        opcodes.write(0, hdr.instructions[0].opcode);
        opcodes.write(1, hdr.instructions[1].opcode);
        opcodes.write(2, hdr.instructions[2].opcode);
        opcodes.write(3, hdr.instructions[3].opcode);
        opcodes.write(4, hdr.instructions[4].opcode);
        opcodes.write(5, hdr.instructions[5].opcode);
        opcodes.write(6, hdr.instructions[6].opcode);
        opcodes.write(7, hdr.instructions[7].opcode);
        opcodes.write(8, hdr.instructions[8].opcode);
        opcodes.write(9, hdr.instructions[9].opcode);
        opcodes.write(10, hdr.instructions[10].opcode);
        opcodes.write(11, hdr.instructions[11].opcode);
        opcodes.write(12, hdr.instructions[12].opcode);
        opcodes.write(13, hdr.instructions[13].opcode);
        opcodes.write(14, hdr.instructions[14].opcode);
        opcodes.write(15, hdr.instructions[15].opcode);
        opcodes.write(16, hdr.instructions[16].opcode);
        opcodes.write(17, hdr.instructions[17].opcode);
        opcodes.write(18, hdr.instructions[18].opcode);
        opcodes.write(19, hdr.instructions[19].opcode);
        opcodes.write(20, hdr.instructions[20].opcode);
        opcodes.write(21, hdr.instructions[21].opcode);
        opcodes.write(22, hdr.instructions[22].opcode);
        opcodes.write(23, hdr.instructions[23].opcode);
        opcodes.write(24, hdr.instructions[24].opcode);
        opcodes.write(25, hdr.instructions[25].opcode);
        opcodes.write(26, hdr.instructions[26].opcode);
        opcodes.write(27, hdr.instructions[27].opcode);
        opcodes.write(28, hdr.instructions[28].opcode);
        opcodes.write(29, hdr.instructions[29].opcode);
        opcodes.write(30, hdr.instructions[30].opcode);
        opcodes.write(31, hdr.instructions[31].opcode);
        opcodes.write(32, hdr.instructions[32].opcode);
        opcodes.write(33, hdr.instructions[33].opcode);
        opcodes.write(34, hdr.instructions[34].opcode);
        opcodes.write(35, hdr.instructions[35].opcode);
        opcodes.write(36, hdr.instructions[36].opcode);
        opcodes.write(37, hdr.instructions[37].opcode);
        opcodes.write(38, hdr.instructions[38].opcode);
        opcodes.write(39, hdr.instructions[39].opcode);
        opcodes.write(40, hdr.instructions[40].opcode);
        opcodes.write(41, hdr.instructions[41].opcode);
        opcodes.write(42, hdr.instructions[42].opcode);
        opcodes.write(43, hdr.instructions[43].opcode);
        opcodes.write(44, hdr.instructions[44].opcode);
        opcodes.write(45, hdr.instructions[45].opcode);
        opcodes.write(46, hdr.instructions[46].opcode);
        opcodes.write(47, hdr.instructions[47].opcode);
        opcodes.write(48, hdr.instructions[48].opcode);
        opcodes.write(49, hdr.instructions[49].opcode);
        opcodes.write(50, hdr.instructions[50].opcode);
        opcodes.write(51, hdr.instructions[51].opcode);
        opcodes.write(52, hdr.instructions[52].opcode);
        opcodes.write(53, hdr.instructions[53].opcode);
        opcodes.write(54, hdr.instructions[54].opcode);
        opcodes.write(55, hdr.instructions[55].opcode);
        opcodes.write(56, hdr.instructions[56].opcode);
        opcodes.write(57, hdr.instructions[57].opcode);
        opcodes.write(58, hdr.instructions[58].opcode);
        opcodes.write(59, hdr.instructions[59].opcode);
        opcodes.write(60, hdr.instructions[60].opcode);
        opcodes.write(61, hdr.instructions[61].opcode);
        opcodes.write(62, hdr.instructions[62].opcode);
        opcodes.write(63, hdr.instructions[63].opcode);

        args.write(0, hdr.instructions[0].arg);
        args.write(1, hdr.instructions[1].arg);
        args.write(2, hdr.instructions[2].arg);
        args.write(3, hdr.instructions[3].arg);
        args.write(4, hdr.instructions[4].arg);
        args.write(5, hdr.instructions[5].arg);
        args.write(6, hdr.instructions[6].arg);
        args.write(7, hdr.instructions[7].arg);
        args.write(8, hdr.instructions[8].arg);
        args.write(9, hdr.instructions[9].arg);
        args.write(10, hdr.instructions[10].arg);
        args.write(11, hdr.instructions[11].arg);
        args.write(12, hdr.instructions[12].arg);
        args.write(13, hdr.instructions[13].arg);
        args.write(14, hdr.instructions[14].arg);
        args.write(15, hdr.instructions[15].arg);
        args.write(16, hdr.instructions[16].arg);
        args.write(17, hdr.instructions[17].arg);
        args.write(18, hdr.instructions[18].arg);
        args.write(19, hdr.instructions[19].arg);
        args.write(20, hdr.instructions[20].arg);
        args.write(21, hdr.instructions[21].arg);
        args.write(22, hdr.instructions[22].arg);
        args.write(23, hdr.instructions[23].arg);
        args.write(24, hdr.instructions[24].arg);
        args.write(25, hdr.instructions[25].arg);
        args.write(26, hdr.instructions[26].arg);
        args.write(27, hdr.instructions[27].arg);
        args.write(28, hdr.instructions[28].arg);
        args.write(29, hdr.instructions[29].arg);
        args.write(30, hdr.instructions[30].arg);
        args.write(31, hdr.instructions[31].arg);
        args.write(32, hdr.instructions[32].arg);
        args.write(33, hdr.instructions[33].arg);
        args.write(34, hdr.instructions[34].arg);
        args.write(35, hdr.instructions[35].arg);
        args.write(36, hdr.instructions[36].arg);
        args.write(37, hdr.instructions[37].arg);
        args.write(38, hdr.instructions[38].arg);
        args.write(39, hdr.instructions[39].arg);
        args.write(40, hdr.instructions[40].arg);
        args.write(41, hdr.instructions[41].arg);
        args.write(42, hdr.instructions[42].arg);
        args.write(43, hdr.instructions[43].arg);
        args.write(44, hdr.instructions[44].arg);
        args.write(45, hdr.instructions[45].arg);
        args.write(46, hdr.instructions[46].arg);
        args.write(47, hdr.instructions[47].arg);
        args.write(48, hdr.instructions[48].arg);
        args.write(49, hdr.instructions[49].arg);
        args.write(50, hdr.instructions[50].arg);
        args.write(51, hdr.instructions[51].arg);
        args.write(52, hdr.instructions[52].arg);
        args.write(53, hdr.instructions[53].arg);
        args.write(54, hdr.instructions[54].arg);
        args.write(55, hdr.instructions[55].arg);
        args.write(56, hdr.instructions[56].arg);
        args.write(57, hdr.instructions[57].arg);
        args.write(58, hdr.instructions[58].arg);
        args.write(59, hdr.instructions[59].arg);
        args.write(60, hdr.instructions[60].arg);
        args.write(61, hdr.instructions[61].arg);
        args.write(62, hdr.instructions[62].arg);
        args.write(63, hdr.instructions[63].arg);

    }

    action parse_stack() {
        stack.write(0, hdr.stack[0].value);
        stack.write(1, hdr.stack[1].value);
        stack.write(2, hdr.stack[2].value);
        stack.write(3, hdr.stack[3].value);
        stack.write(4, hdr.stack[4].value);
        stack.write(5, hdr.stack[5].value);
        stack.write(6, hdr.stack[6].value);
        stack.write(7, hdr.stack[7].value);
        stack.write(8, hdr.stack[8].value);
        stack.write(9, hdr.stack[9].value);
        stack.write(10, hdr.stack[10].value);
        stack.write(11, hdr.stack[11].value);
        stack.write(12, hdr.stack[12].value);
        stack.write(13, hdr.stack[13].value);
        stack.write(14, hdr.stack[14].value);
        stack.write(15, hdr.stack[15].value);
        stack.write(16, hdr.stack[16].value);
        stack.write(17, hdr.stack[17].value);
        stack.write(18, hdr.stack[18].value);
        stack.write(19, hdr.stack[19].value);
        stack.write(20, hdr.stack[20].value);
        stack.write(21, hdr.stack[21].value);
        stack.write(22, hdr.stack[22].value);
        stack.write(23, hdr.stack[23].value);
        stack.write(24, hdr.stack[24].value);
        stack.write(25, hdr.stack[25].value);
        stack.write(26, hdr.stack[26].value);
        stack.write(27, hdr.stack[27].value);
        stack.write(28, hdr.stack[28].value);
        stack.write(29, hdr.stack[29].value);
        stack.write(30, hdr.stack[30].value);
        stack.write(31, hdr.stack[31].value);
        stack.write(32, hdr.stack[32].value);
        stack.write(33, hdr.stack[33].value);
        stack.write(34, hdr.stack[34].value);
        stack.write(35, hdr.stack[35].value);
        stack.write(36, hdr.stack[36].value);
        stack.write(37, hdr.stack[37].value);
        stack.write(38, hdr.stack[38].value);
        stack.write(39, hdr.stack[39].value);
        stack.write(40, hdr.stack[40].value);
        stack.write(41, hdr.stack[41].value);
        stack.write(42, hdr.stack[42].value);
        stack.write(43, hdr.stack[43].value);
        stack.write(44, hdr.stack[44].value);
        stack.write(45, hdr.stack[45].value);
        stack.write(46, hdr.stack[46].value);
        stack.write(47, hdr.stack[47].value);
        stack.write(48, hdr.stack[48].value);
        stack.write(49, hdr.stack[49].value);
        stack.write(50, hdr.stack[50].value);
        stack.write(51, hdr.stack[51].value);
        stack.write(52, hdr.stack[52].value);
        stack.write(53, hdr.stack[53].value);
        stack.write(54, hdr.stack[54].value);
        stack.write(55, hdr.stack[55].value);
        stack.write(56, hdr.stack[56].value);
        stack.write(57, hdr.stack[57].value);
        stack.write(58, hdr.stack[58].value);
        stack.write(59, hdr.stack[59].value);
        stack.write(60, hdr.stack[60].value);
        stack.write(61, hdr.stack[61].value);
        stack.write(62, hdr.stack[62].value);
        stack.write(63, hdr.stack[63].value);

    }

    action deparse_stack() {
        stack.read(hdr.stack[0].value, 0);
        stack.read(hdr.stack[1].value, 1);
        stack.read(hdr.stack[2].value, 2);
        stack.read(hdr.stack[3].value, 3);
        stack.read(hdr.stack[4].value, 4);
        stack.read(hdr.stack[5].value, 5);
        stack.read(hdr.stack[6].value, 6);
        stack.read(hdr.stack[7].value, 7);
        stack.read(hdr.stack[8].value, 8);
        stack.read(hdr.stack[9].value, 9);
        stack.read(hdr.stack[10].value, 10);
        stack.read(hdr.stack[11].value, 11);
        stack.read(hdr.stack[12].value, 12);
        stack.read(hdr.stack[13].value, 13);
        stack.read(hdr.stack[14].value, 14);
        stack.read(hdr.stack[15].value, 15);
        stack.read(hdr.stack[16].value, 16);
        stack.read(hdr.stack[17].value, 17);
        stack.read(hdr.stack[18].value, 18);
        stack.read(hdr.stack[19].value, 19);
        stack.read(hdr.stack[20].value, 20);
        stack.read(hdr.stack[21].value, 21);
        stack.read(hdr.stack[22].value, 22);
        stack.read(hdr.stack[23].value, 23);
        stack.read(hdr.stack[24].value, 24);
        stack.read(hdr.stack[25].value, 25);
        stack.read(hdr.stack[26].value, 26);
        stack.read(hdr.stack[27].value, 27);
        stack.read(hdr.stack[28].value, 28);
        stack.read(hdr.stack[29].value, 29);
        stack.read(hdr.stack[30].value, 30);
        stack.read(hdr.stack[31].value, 31);
        stack.read(hdr.stack[32].value, 32);
        stack.read(hdr.stack[33].value, 33);
        stack.read(hdr.stack[34].value, 34);
        stack.read(hdr.stack[35].value, 35);
        stack.read(hdr.stack[36].value, 36);
        stack.read(hdr.stack[37].value, 37);
        stack.read(hdr.stack[38].value, 38);
        stack.read(hdr.stack[39].value, 39);
        stack.read(hdr.stack[40].value, 40);
        stack.read(hdr.stack[41].value, 41);
        stack.read(hdr.stack[42].value, 42);
        stack.read(hdr.stack[43].value, 43);
        stack.read(hdr.stack[44].value, 44);
        stack.read(hdr.stack[45].value, 45);
        stack.read(hdr.stack[46].value, 46);
        stack.read(hdr.stack[47].value, 47);
        stack.read(hdr.stack[48].value, 48);
        stack.read(hdr.stack[49].value, 49);
        stack.read(hdr.stack[50].value, 50);
        stack.read(hdr.stack[51].value, 51);
        stack.read(hdr.stack[52].value, 52);
        stack.read(hdr.stack[53].value, 53);
        stack.read(hdr.stack[54].value, 54);
        stack.read(hdr.stack[55].value, 55);
        stack.read(hdr.stack[56].value, 56);
        stack.read(hdr.stack[57].value, 57);
        stack.read(hdr.stack[58].value, 58);
        stack.read(hdr.stack[59].value, 59);
        stack.read(hdr.stack[60].value, 60);
        stack.read(hdr.stack[61].value, 61);
        stack.read(hdr.stack[62].value, 62);
        stack.read(hdr.stack[63].value, 63);

    }

    action read_current_instr() {
        opcodes.read(hdr.pdata.curr_instr_opcode, hdr.pdata.pc);
        args.read(hdr.pdata.curr_instr_arg, hdr.pdata.pc);
    }

    action increment_pc() {
        hdr.pdata.pc = hdr.pdata.pc + 32w1;
    }

    action ipush() {
        stack.write(hdr.pdata.sp, hdr.pdata.curr_instr_arg);
        hdr.pdata.sp = hdr.pdata.sp + 32w1;
    }

    action instr_metadata_egress() {
        // TARGET-SPECIFIC
        int<32> code = hdr.pdata.curr_instr_arg;
        // for metadata read during egress, ingress pushed a 0, so we will drop it here
        if (code == 2 || code == 3 || code == 5 || code == 6) {
            hdr.pdata.sp = hdr.pdata.sp - 32w1;
        }
        if (code == 0) { // ingress 
            hdr.pdata.curr_instr_arg = 0;
        } else 
        if (code == 1) { // ingress 
            hdr.pdata.curr_instr_arg = 0;
        } else 
        if (code == 2) {
            hdr.pdata.curr_instr_arg = (int<32>) (bit<32>) hdr.my_metadata.enq_qdepth;
        } else 
        if (code == 3) {
            hdr.pdata.curr_instr_arg = (int<32>) (bit<32>) hdr.my_metadata.deq_qdepth;
        } else 
        if (code == 4) { // ingress 
            hdr.pdata.curr_instr_arg = 0;
        } else 
        if (code == 5) {
            hdr.pdata.curr_instr_arg = (int<32>) (bit<32>) hdr.my_metadata.enq_timestamp;
        } else 
        if (code == 6) {
            hdr.pdata.curr_instr_arg = (int<32>) (bit<32>) hdr.my_metadata.deq_timedelta;
        } else
        if (code == 7) { // ingress 
            hdr.pdata.curr_instr_arg = 0;
        }
        ipush();
        // for metadata already pushed during ingress, egress pushed a 0
        if (code == 0 || code == 1 || code == 4 || code == 7) {
            hdr.pdata.sp = hdr.pdata.sp - 32w1;
        }
        increment_pc();
    }

    table instruction_table_egress {
        key = {
            hdr.pdata.curr_instr_opcode: exact;
        }
        actions = {
            instr_metadata_egress;
            NoAction;
        }
        default_action = NoAction();
        const entries = {
            0x1C : instr_metadata_egress();
        } 
    }
            
    apply {
        @atomic {
            hdr.my_metadata.enq_timestamp = standard_metadata.enq_timestamp;
            hdr.my_metadata.deq_timedelta = standard_metadata.deq_timedelta;
            hdr.my_metadata.enq_qdepth = standard_metadata.enq_qdepth;
            hdr.my_metadata.deq_qdepth = standard_metadata.deq_qdepth;

            if (hdr.pdata.done_flg == 1w1) {
                hdr.pdata.done_flg = 1w0;
                hdr.pdata.steps = 32w0;
                hdr.pdata.pc = 32w0;
            }
            parse_stack();
            read_current_instr();
            instruction_table_egress.apply();
            deparse_stack();
        }  
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply { }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.my_metadata);
        packet.emit(hdr.pdata);
        packet.emit(hdr.instructions);
        packet.emit(hdr.stack);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
