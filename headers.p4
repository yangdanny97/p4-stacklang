/*************************************************************************
***********************  INSTRUCTIONS  ***********************************
*************************************************************************/

const bit<32> STACK_SIZE = 128;
const bit<32> MAX_INSTRS = 128;

const bit<8> i_load = 0x00
const bit<8> i_store = 0x01
const bit<8> i_push = 0x02
const bit<8> i_drop = 0x03
const bit<8> i_add = 0x04
const bit<8> i_mul = 0x05
const bit<8> i_sub = 0x06
const bit<8> i_neg = 0x07
const bit<8> i_reset = 0x08
const bit<8> i_and = 0x09
const bit<8> i_or = 0x0A
const bit<8> i_gt = 0x0B
const bit<8> i_lt = 0x0C
const bit<8> i_lte = 0x0D
const bit<8> i_gte = 0x0E
const bit<8> i_eq = 0x0F
const bit<8> i_neq = 0x10
const bit<8> i_dup = 0x11
const bit<8> i_swap = 0x12
const bit<8> i_over = 0x13
const bit<8> i_rot = 0x14
const bit<8> i_jump = 0x15
const bit<8> i_cjump = 0x16
const bit<8> i_done = 0x17

// use an unassigned protocol number
const bit<8> PROTOCOL_NUM = 0x8F

header instr_t {
    bit<8> opcode;
    bit<32> arg;
}

header stack_t {
    bit<32> contents
}

header pdata_t {
    bit<8> PC; // program counter
    bit<8> SP; // stack pointer
    bit<1> done; // flag set when execution ends
    bit<1> error; // flag set if there is an error
    bit<6> padding;
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
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    pdata_t pdata;
    instr_t[MAX_INSTRS] instructions;
    stack_t[STACK_SIZE] stack;
}