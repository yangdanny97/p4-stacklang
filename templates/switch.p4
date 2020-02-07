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
const bit<32> MAX_INSTRS = 33; //extra for special last instruction
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
        {% parse_opcodes %}
        {% parse_args %}
    }

    action parse_stack() {
        {% parse_stack %}
    }

    action deparse_stack() {
        {% deparse_stack %}
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

    action instr_metadata() {
        // TARGET-SPECIFIC
        int<32> code = hdr.pdata.curr_instr_arg;
        if (code == 0) {
            hdr.pdata.curr_instr_arg = (int<32>) (bit<32>) hdr.my_metadata.ingress_port;
        } else
        if (code == 1) {
            hdr.pdata.curr_instr_arg = (int<32>) hdr.my_metadata.packet_length;
        } else 
        if (code == 2) {
            hdr.pdata.curr_instr_arg = (int<32>) (bit<32>) hdr.my_metadata.enq_qdepth;
        } else 
        if (code == 3) {
            hdr.pdata.curr_instr_arg = (int<32>) (bit<32>) hdr.my_metadata.deq_qdepth;
        } else 
        if (code == 4) {
            hdr.pdata.curr_instr_arg = (int<32>) (bit<32>) hdr.my_metadata.egress_spec;
        } else {
            hdr.pdata.curr_instr_arg = 0;
        }
        ipush();
        increment_pc();
    }

    action instr_setegress() {
        // TARGET-SPECIFIC
        int<32> top;
        stack.read(top, hdr.pdata.sp - 32w1);
        idrop();
        standard_metadata.egress_spec = (bit<9>) (bit<32>) top;
        hdr.pdata.steps = 32w0;
        hdr.pdata.pc = 32w0;
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

    table instruction_table {
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
            instr_metadata;
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
            0x1C : instr_metadata();
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

    apply {
        ipv4_lpm.apply();
        // if ingress is not self-fwd then write metadata fields
        if (standard_metadata.ingress_port != 9w5) {
            hdr.my_metadata.ingress_port = standard_metadata.ingress_port;
            hdr.my_metadata.packet_length = standard_metadata.packet_length;
            hdr.my_metadata.enq_qdepth = standard_metadata.enq_qdepth;
            hdr.my_metadata.deq_qdepth = standard_metadata.deq_qdepth;
            hdr.my_metadata.egress_spec = standard_metadata.egress_spec;
        }
        if (hdr.pdata.done_flg == 1w1) {
            hdr.pdata.done_flg = 1w0;
            hdr.pdata.pc = 32w0;
            hdr.pdata.steps = 32w0;
        } 
        else if (hdr.pdata.err_flg == 1w1) { } 
        else if (hdr.pdata.steps > MAX_STEPS) {
            hdr.pdata.err_flg = 1w1;
        } 
        else {
            // forward to self
            standard_metadata.egress_spec = 9w4;
            // don't decrement ttl for self-forwarding
            hdr.ipv4.ttl = hdr.ipv4.ttl + 1;
            parse_instructions();
            parse_stack();
            read_current_instr();
            instruction_table.apply();
            increment_steps();
            deparse_stack();
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
