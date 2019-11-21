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
const bit<32> STACK_SIZE = 32;
const bit<32> MAX_INSTRS = 32;

const bit<8> i_load = 0x00;
const bit<8> i_store = 0x01;
const bit<8> i_push = 0x02;
const bit<8> i_drop = 0x03;
const bit<8> i_add = 0x04;
const bit<8> i_mul = 0x05;
const bit<8> i_sub = 0x06;
const bit<8> i_neg = 0x07;
const bit<8> i_reset = 0x08;
const bit<8> i_and = 0x09;
const bit<8> i_or = 0x0A;
const bit<8> i_gt = 0x0B;
const bit<8> i_lt = 0x0C;
const bit<8> i_lte = 0x0D;
const bit<8> i_gte = 0x0E;
const bit<8> i_eq = 0x0F;
const bit<8> i_neq = 0x10;
const bit<8> i_dup = 0x11;
const bit<8> i_swap = 0x12;
const bit<8> i_over = 0x13;
const bit<8> i_rot = 0x14;
const bit<8> i_jump = 0x15;
const bit<8> i_cjump = 0x16;
const bit<8> i_done = 0x17;
const bit<8> i_error = 0x18;
const bit<8> i_nop = 0x19;

header instr_t {
    bit<8> opcode;
    int<32> arg;
}

header stack_t {
    int<32> value;
}

header pdata_t {
    bit<32> PC; // program counter
    bit<32> SP; // stack pointer to next EMPTY slot
    bit<32> steps;
    bit<1> done_flg; // flag set when execution ends
    bit<1> err_flg; // flag set if there is an error
    bit<6> padding;
    int<32> result;
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
    instr_t current_instr;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
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
    bit<32> instrs_to_parse;
    bit<32> total_instrs;
    bit<32> n = STACK_SIZE;
    bit<32> m = MAX_INSTRS;

    state start {
        instrs_to_parse = 32w0;
        total_instrs = MAX_INSTRS;
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
            PROTOCOL_NUM: parse_pdata;
            default: accept;
        }
    }

    state parse_pdata {
        packet.extract(hdr.pdata);
        instrs_to_parse = hdr.pdata.PC;
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
    
    instr_t curr_instr;
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
    }

    action read_current_instr() {
        opcodes.read(curr_instr.opcode, hdr.pdata.PC);
        args.read(curr_instr.arg, hdr.pdata.PC);
    }

    action increment_pc() {
        hdr.pdata.PC = hdr.pdata.PC + 32w1;
    }

    action increment_steps() {
        hdr.pdata.steps = hdr.pdata.steps + 32w1;
    }

    action ipush() {
        stack.write(hdr.pdata.SP, curr_instr.arg);
        hdr.pdata.SP = hdr.pdata.SP + 32w1;
    }

    action idrop() {
        hdr.pdata.SP = hdr.pdata.SP - 32w1;
    }


    action instr_push() {
        ipush();
        increment_pc();
        hdr.pdata.result = curr_instr.arg;
    }

    action instr_drop() {
        idrop();
        increment_pc();
    }

    action instr_load() {
        bit<32> offset = (bit<32>) curr_instr.arg;
        stack.read(curr_instr.arg, offset);
        ipush();
        increment_pc();
    }

    action instr_store() {
        int<32> top;
        stack.read(top, hdr.pdata.SP - 32w1);
        bit<32> offset = (bit<32>) curr_instr.arg;
        stack.read(curr_instr.arg, offset);
        increment_pc();
    }

    action instr_add() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.SP - 32w1);
        stack.read(r, hdr.pdata.SP - 32w2);
        idrop();
        idrop();
        curr_instr.arg = l + r;
        ipush();
        increment_pc();
    }

    action instr_mul() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.SP - 32w1);
        stack.read(r, hdr.pdata.SP - 32w2);
        idrop();
        idrop();
        curr_instr.arg = l * r;
        ipush();
        increment_pc();
    }

    action instr_sub() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.SP - 32w1);
        stack.read(r, hdr.pdata.SP - 32w2);
        idrop();
        idrop();
        curr_instr.arg = l - r;
        ipush();
        increment_pc();
    }

    action instr_neg() {
        int<32> top;
        stack.read(top, hdr.pdata.SP - 32w1);
        idrop();
        curr_instr.arg = -top;
        ipush();
        increment_pc();
    }

    action instr_reset() {
        hdr.pdata.SP = 32w0;
        increment_pc();
    }

    action instr_and() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.SP - 32w1);
        stack.read(r, hdr.pdata.SP - 32w2);
        idrop();
        idrop();
        if (l > 0 && r > 0) {
            curr_instr.arg = 1;
        } else {
            curr_instr.arg = 0;
        }
        ipush();
        increment_pc();
    }

    action instr_or() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.SP - 32w1);
        stack.read(r, hdr.pdata.SP - 32w2);
        idrop();
        idrop();
        if (l > 0 || r > 0) {
            curr_instr.arg = 1;
        } else {
            curr_instr.arg = 0;
        }
        ipush();
        increment_pc();
    }

    action instr_gt() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.SP - 32w1);
        stack.read(r, hdr.pdata.SP - 32w2);
        idrop();
        idrop();
        if (l > r) {
            curr_instr.arg = 1;
        } else {
            curr_instr.arg = 0;
        }
        ipush();
        increment_pc();
    }

    action instr_lt() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.SP - 32w1);
        stack.read(r, hdr.pdata.SP - 32w2);
        idrop();
        idrop();
        if (l < r) {
            curr_instr.arg = 1;
        } else {
            curr_instr.arg = 0;
        }
        ipush();
        increment_pc();
    }

    action instr_gte() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.SP - 32w1);
        stack.read(r, hdr.pdata.SP - 32w2);
        idrop();
        idrop();
        if (l >= r) {
            curr_instr.arg = 1;
        } else {
            curr_instr.arg = 0;
        }
        ipush();
        increment_pc();
    }

    action instr_lte() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.SP - 32w1);
        stack.read(r, hdr.pdata.SP - 32w2);
        idrop();
        idrop();
        if (l <= r) {
            curr_instr.arg = 1;
        } else {
            curr_instr.arg = 0;
        }
        ipush();
        increment_pc();
    }

    action instr_eq() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.SP - 32w1);
        stack.read(r, hdr.pdata.SP - 32w2);
        idrop();
        idrop();
        if (l == r) {
            curr_instr.arg = 1;
        } else {
            curr_instr.arg = 0;
        }
        ipush();
        increment_pc();
    }

    action instr_neq() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.SP - 32w1);
        stack.read(r, hdr.pdata.SP - 32w2);
        idrop();
        idrop();
        if (l != r) {
            curr_instr.arg = 1;
        } else {
            curr_instr.arg = 0;
        }
        ipush();
        increment_pc();
    }

    action instr_dup() {
        int<32> top;
        stack.read(top, hdr.pdata.SP - 32w1);
        curr_instr.arg = top;
        ipush();
        increment_pc();
    }

    action instr_swap() {
        int<32> l;
        int<32> r;
        stack.read(l, hdr.pdata.SP - 32w1);
        stack.read(r, hdr.pdata.SP - 32w2);
        stack.write(hdr.pdata.SP - 32w2, l);
        stack.write(hdr.pdata.SP - 32w1, r);
        increment_pc();
    }

    action instr_over() {
        int<32> second;
        stack.read(second, hdr.pdata.SP - 32w2);
        curr_instr.arg = second;
        ipush();
        increment_pc();
    }

    action instr_rot() {
        int<32> a;
        int<32> b;
        int<32> c;
        stack.read(c, hdr.pdata.SP - 32w1);
        stack.read(b, hdr.pdata.SP - 32w2);
        stack.read(a, hdr.pdata.SP - 32w3);
        stack.write(hdr.pdata.SP - 32w1, b);
        stack.write(hdr.pdata.SP - 32w2, a);
        stack.write(hdr.pdata.SP - 32w3, c);
        increment_pc();
    }

    action instr_jump() {
        bit<32> pc = (bit<32>) curr_instr.arg;
        hdr.pdata.PC = pc;
    }

    action instr_cjump() {
        bit<32> pc = (bit<32>) curr_instr.arg;
        int<32> top;
        stack.read(top, hdr.pdata.SP - 32w1);
        idrop();
        if (top > 0) {
            hdr.pdata.PC = pc;
        } else {
            hdr.pdata.PC = hdr.pdata.PC + 32w1;
        }
    }

    action instr_done() {
        hdr.pdata.done_flg = 1w1;
        stack.read(hdr.pdata.result, hdr.pdata.SP - 32w1);
    }

    action instr_error() {
        hdr.pdata.err_flg = 1w1;
    }

    action instr_nop() {
        increment_pc();
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

    table ipv4_self_fwd {
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

    table instruction_table {
        key = {
            curr_instr.opcode: exact;
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
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.pdata.done_flg == 1w1 || hdr.pdata.err_flg == 1w1 || hdr.pdata.steps > MAX_STEPS) {
            ipv4_lpm.apply();
        } else {
            parse_instructions();
            parse_stack();
            read_current_instr();
            instruction_table.apply();
            increment_steps();
            // instr_done();
            deparse_stack();
            ipv4_self_fwd.apply();
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
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
