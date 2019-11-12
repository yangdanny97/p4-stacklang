/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<32> H1_ADDR = 0x0A00010B;
const bit<32> H2_ADDR = 0x0A000216;

/*************************************************************************
***********************  INSTRUCTIONS  ***********************************
*************************************************************************/

// use an unassigned protocol number
const bit<8> PROTOCOL_NUM = 0x8F;
const bit<8> MAX_STEPS = 250;
const bit<32> STACK_SIZE = 128;
const bit<32> MAX_INSTRS = 128;

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
    bit<8> PC; // program counter
    bit<8> SP; // stack pointer to next EMPTY slot
    bit<8> steps;
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
    bit<8> instrs_to_parse;
    bit<8> total_instrs;

    state start {
        instrs_to_parse = 8w0;
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

    parse_all_instructions {
        transition select(total_instrs) {
            0: parse_stack;
            default: parse_instruction;
        }
    }

    state parse_instruction {
        total_instrs = total_instrs - 8w1;
        transition select(instrs_to_parse) {
            0: parse_current_instruction;
            default: next_instruction;
        }
    }

    state next_instruction {
        packet.extract(hdr.instructions.next);
        instrs_to_current = instrs_to_current - 8w1;
        transition parse_all_instructions;
    }

    state parse_current_instruction {
        meta.current_instr.setValid();
        meta.current_instr = packet.lookahead<instr_t>();
        transition next_instruction;
    }

    state parse_stack {
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        packet.extract(hdr.stack.next);
        transition accept;
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
        stack.write(64, hdr.stack[64].value);
        stack.write(65, hdr.stack[65].value);
        stack.write(66, hdr.stack[66].value);
        stack.write(67, hdr.stack[67].value);
        stack.write(68, hdr.stack[68].value);
        stack.write(69, hdr.stack[69].value);
        stack.write(70, hdr.stack[70].value);
        stack.write(71, hdr.stack[71].value);
        stack.write(72, hdr.stack[72].value);
        stack.write(73, hdr.stack[73].value);
        stack.write(74, hdr.stack[74].value);
        stack.write(75, hdr.stack[75].value);
        stack.write(76, hdr.stack[76].value);
        stack.write(77, hdr.stack[77].value);
        stack.write(78, hdr.stack[78].value);
        stack.write(79, hdr.stack[79].value);
        stack.write(80, hdr.stack[80].value);
        stack.write(81, hdr.stack[81].value);
        stack.write(82, hdr.stack[82].value);
        stack.write(83, hdr.stack[83].value);
        stack.write(84, hdr.stack[84].value);
        stack.write(85, hdr.stack[85].value);
        stack.write(86, hdr.stack[86].value);
        stack.write(87, hdr.stack[87].value);
        stack.write(88, hdr.stack[88].value);
        stack.write(89, hdr.stack[89].value);
        stack.write(90, hdr.stack[90].value);
        stack.write(91, hdr.stack[91].value);
        stack.write(92, hdr.stack[92].value);
        stack.write(93, hdr.stack[93].value);
        stack.write(94, hdr.stack[94].value);
        stack.write(95, hdr.stack[95].value);
        stack.write(96, hdr.stack[96].value);
        stack.write(97, hdr.stack[97].value);
        stack.write(98, hdr.stack[98].value);
        stack.write(99, hdr.stack[99].value);
        stack.write(100, hdr.stack[100].value);
        stack.write(101, hdr.stack[101].value);
        stack.write(102, hdr.stack[102].value);
        stack.write(103, hdr.stack[103].value);
        stack.write(104, hdr.stack[104].value);
        stack.write(105, hdr.stack[105].value);
        stack.write(106, hdr.stack[106].value);
        stack.write(107, hdr.stack[107].value);
        stack.write(108, hdr.stack[108].value);
        stack.write(109, hdr.stack[109].value);
        stack.write(110, hdr.stack[110].value);
        stack.write(111, hdr.stack[111].value);
        stack.write(112, hdr.stack[112].value);
        stack.write(113, hdr.stack[113].value);
        stack.write(114, hdr.stack[114].value);
        stack.write(115, hdr.stack[115].value);
        stack.write(116, hdr.stack[116].value);
        stack.write(117, hdr.stack[117].value);
        stack.write(118, hdr.stack[118].value);
        stack.write(119, hdr.stack[119].value);
        stack.write(120, hdr.stack[120].value);
        stack.write(121, hdr.stack[121].value);
        stack.write(122, hdr.stack[122].value);
        stack.write(123, hdr.stack[123].value);
        stack.write(124, hdr.stack[124].value);
        stack.write(125, hdr.stack[125].value);
        stack.write(126, hdr.stack[126].value);
        stack.write(127, hdr.stack[127].value);
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
        stack.read(hdr.stack[64].value, 64);
        stack.read(hdr.stack[65].value, 65);
        stack.read(hdr.stack[66].value, 66);
        stack.read(hdr.stack[67].value, 67);
        stack.read(hdr.stack[68].value, 68);
        stack.read(hdr.stack[69].value, 69);
        stack.read(hdr.stack[70].value, 70);
        stack.read(hdr.stack[71].value, 71);
        stack.read(hdr.stack[72].value, 72);
        stack.read(hdr.stack[73].value, 73);
        stack.read(hdr.stack[74].value, 74);
        stack.read(hdr.stack[75].value, 75);
        stack.read(hdr.stack[76].value, 76);
        stack.read(hdr.stack[77].value, 77);
        stack.read(hdr.stack[78].value, 78);
        stack.read(hdr.stack[79].value, 79);
        stack.read(hdr.stack[80].value, 80);
        stack.read(hdr.stack[81].value, 81);
        stack.read(hdr.stack[82].value, 82);
        stack.read(hdr.stack[83].value, 83);
        stack.read(hdr.stack[84].value, 84);
        stack.read(hdr.stack[85].value, 85);
        stack.read(hdr.stack[86].value, 86);
        stack.read(hdr.stack[87].value, 87);
        stack.read(hdr.stack[88].value, 88);
        stack.read(hdr.stack[89].value, 89);
        stack.read(hdr.stack[90].value, 90);
        stack.read(hdr.stack[91].value, 91);
        stack.read(hdr.stack[92].value, 92);
        stack.read(hdr.stack[93].value, 93);
        stack.read(hdr.stack[94].value, 94);
        stack.read(hdr.stack[95].value, 95);
        stack.read(hdr.stack[96].value, 96);
        stack.read(hdr.stack[97].value, 97);
        stack.read(hdr.stack[98].value, 98);
        stack.read(hdr.stack[99].value, 99);
        stack.read(hdr.stack[100].value, 100);
        stack.read(hdr.stack[101].value, 101);
        stack.read(hdr.stack[102].value, 102);
        stack.read(hdr.stack[103].value, 103);
        stack.read(hdr.stack[104].value, 104);
        stack.read(hdr.stack[105].value, 105);
        stack.read(hdr.stack[106].value, 106);
        stack.read(hdr.stack[107].value, 107);
        stack.read(hdr.stack[108].value, 108);
        stack.read(hdr.stack[109].value, 109);
        stack.read(hdr.stack[110].value, 110);
        stack.read(hdr.stack[111].value, 111);
        stack.read(hdr.stack[112].value, 112);
        stack.read(hdr.stack[113].value, 113);
        stack.read(hdr.stack[114].value, 114);
        stack.read(hdr.stack[115].value, 115);
        stack.read(hdr.stack[116].value, 116);
        stack.read(hdr.stack[117].value, 117);
        stack.read(hdr.stack[118].value, 118);
        stack.read(hdr.stack[119].value, 119);
        stack.read(hdr.stack[120].value, 120);
        stack.read(hdr.stack[121].value, 121);
        stack.read(hdr.stack[122].value, 122);
        stack.read(hdr.stack[123].value, 123);
        stack.read(hdr.stack[124].value, 124);
        stack.read(hdr.stack[125].value, 125);
        stack.read(hdr.stack[126].value, 126);
        stack.read(hdr.stack[127].value, 127);
    }

    action read_stack(out int<32> value, in bit<8> offset) {
        stack.read(value, (bit<32>) offset);
    }

    action write_stack(in bit<8> offset, in int<32> value) {
        stack.write((bit<32>) offset, value);
    }

    action read_current_instr() {
        curr_instr = meta.current_instr;
    }

    action increment_pc() {
        hdr.pdata.PC = hdr.pdata.PC + 8w1;
    }

    action increment_steps() {
        hdr.pdata.steps = hdr.pdata.steps + 8w1;
    }


    action instr_push() {
        write_stack(hdr.pdata.SP, curr_instr.arg);
        hdr.pdata.SP = hdr.pdata.SP + 8w1;
    }

    action instr_drop() {
        hdr.pdata.SP = hdr.pdata.SP - 8w1;
    }

    action instr_load() {
        bit<8> offset = (bit<8>) (bit<32>) curr_instr.arg;
        read_stack(curr_instr.arg, offset);
        instr_push();
        increment_pc();
    }

    action instr_store() {
        int<32> top;
        read_stack(top, hdr.pdata.SP - 8w1);
        bit<8> offset = (bit<8>) (bit<32>) curr_instr.arg;
        read_stack(curr_instr.arg, offset);
        increment_pc();
    }

    action instr_add() {
        int<32> l;
        int<32> r;
        read_stack(l, hdr.pdata.SP - 8w1);
        read_stack(r, hdr.pdata.SP - 8w2);
        instr_drop();
        instr_drop();
        curr_instr.arg = l + r;
        instr_push();
        increment_pc();
    }

    action instr_mul() {
        int<32> l;
        int<32> r;
        read_stack(l, hdr.pdata.SP - 8w1);
        read_stack(r, hdr.pdata.SP - 8w2);
        instr_drop();
        instr_drop();
        curr_instr.arg = l * r;
        instr_push();
        increment_pc();
    }

    action instr_sub() {
        int<32> l;
        int<32> r;
        read_stack(l, hdr.pdata.SP - 8w1);
        read_stack(r, hdr.pdata.SP - 8w2);
        instr_drop();
        instr_drop();
        curr_instr.arg = l - r;
        instr_push();
        increment_pc();
    }

    action instr_neg() {
        int<32> top;
        read_stack(top, hdr.pdata.SP - 8w1);
        instr_drop();
        curr_instr.arg = -top;
        instr_push();
        increment_pc();
    }

    action instr_reset() {
        hdr.pdata.SP = 8w0;
        increment_pc();
    }

    action instr_and() {
        int<32> l;
        int<32> r;
        read_stack(l, hdr.pdata.SP - 8w1);
        read_stack(r, hdr.pdata.SP - 8w2);
        instr_drop();
        instr_drop();
        if (l > 0 && r > 0) {
            curr_instr.arg = 1;
        } else {
            curr_instr.arg = 0;
        }
        instr_push();
        increment_pc();
    }

    action instr_or() {
        int<32> l;
        int<32> r;
        read_stack(l, hdr.pdata.SP - 8w1);
        read_stack(r, hdr.pdata.SP - 8w2);
        instr_drop();
        instr_drop();
        if (l > 0 || r > 0) {
            curr_instr.arg = 1;
        } else {
            curr_instr.arg = 0;
        }
        instr_push();
        increment_pc();
    }

    action instr_gt() {
        int<32> l;
        int<32> r;
        read_stack(l, hdr.pdata.SP - 8w1);
        read_stack(r, hdr.pdata.SP - 8w2);
        instr_drop();
        instr_drop();
        if (l > r) {
            curr_instr.arg = 1;
        } else {
            curr_instr.arg = 0;
        }
        instr_push();
        increment_pc();
    }

    action instr_lt() {
        int<32> l;
        int<32> r;
        read_stack(l, hdr.pdata.SP - 8w1);
        read_stack(r, hdr.pdata.SP - 8w2);
        instr_drop();
        instr_drop();
        if (l < r) {
            curr_instr.arg = 1;
        } else {
            curr_instr.arg = 0;
        }
        instr_push();
        increment_pc();
    }

    action instr_gte() {
        int<32> l;
        int<32> r;
        read_stack(l, hdr.pdata.SP - 8w1);
        read_stack(r, hdr.pdata.SP - 8w2);
        instr_drop();
        instr_drop();
        if (l >= r) {
            curr_instr.arg = 1;
        } else {
            curr_instr.arg = 0;
        }
        instr_push();
        increment_pc();
    }

    action instr_lte() {
        int<32> l;
        int<32> r;
        read_stack(l, hdr.pdata.SP - 8w1);
        read_stack(r, hdr.pdata.SP - 8w2);
        instr_drop();
        instr_drop();
        if (l <= r) {
            curr_instr.arg = 1;
        } else {
            curr_instr.arg = 0;
        }
        instr_push();
        increment_pc();
    }

    action instr_eq() {
        int<32> l;
        int<32> r;
        read_stack(l, hdr.pdata.SP - 8w1);
        read_stack(r, hdr.pdata.SP - 8w2);
        instr_drop();
        instr_drop();
        if (l == r) {
            curr_instr.arg = 1;
        } else {
            curr_instr.arg = 0;
        }
        instr_push();
        increment_pc();
    }

    action instr_neq() {
        int<32> l;
        int<32> r;
        read_stack(l, hdr.pdata.SP - 8w1);
        read_stack(r, hdr.pdata.SP - 8w2);
        instr_drop();
        instr_drop();
        if (l != r) {
            curr_instr.arg = 1;
        } else {
            curr_instr.arg = 0;
        }
        instr_push();
        increment_pc();
    }

    action instr_dup() {
        int<32> top;
        read_stack(top, hdr.pdata.SP - 8w1);
        curr_instr.arg = top;
        instr_push();
        increment_pc();
    }

    action instr_swap() {
        int<32> l;
        int<32> r;
        read_stack(l, hdr.pdata.SP - 8w1);
        read_stack(r, hdr.pdata.SP - 8w2);
        write_stack(hdr.pdata.SP - 8w2, l);
        write_stack(hdr.pdata.SP - 8w1, r);
        increment_pc();
    }

    action instr_over() {
        int<32> second;
        read_stack(second, hdr.pdata.SP - 8w2);
        curr_instr.arg = second;
        instr_push();
        increment_pc();
    }

    action instr_rot() {
        int<32> a;
        int<32> b;
        int<32> c;
        read_stack(c, hdr.pdata.SP - 8w1);
        read_stack(b, hdr.pdata.SP - 8w2);
        read_stack(a, hdr.pdata.SP - 8w3);
        write_stack(hdr.pdata.SP - 8w1, b);
        write_stack(hdr.pdata.SP - 8w2, a);
        write_stack(hdr.pdata.SP - 8w3, c);
        increment_pc();
    }

    action instr_jump() {
        bit<8> pc = (bit<8>) (bit<32>) curr_instr.arg;
        hdr.pdata.PC = pc;
    }

    action instr_cjump() {
        bit<8> pc = (bit<8>) (bit<32>) curr_instr.arg;
        int<32> top;
        read_stack(top, hdr.pdata.SP - 8w1);
        instr_drop();
        if (top > 0) {
            hdr.pdata.PC = pc;
        } else {
            hdr.pdata.PC = hdr.pdata.PC;
        }
    }

    action instr_done() {
        hdr.pdata.done_flg = 1w1;
        read_stack(hdr.pdata.result, hdr.pdata.SP - 8w1);
    }

    action instr_error() {
        hdr.pdata.err_flg = 1w1;
    }

    action instr_nop() {
        increment_pc();
     }

    action apply_instr() {
        if (curr_instr.opcode == i_load) { instr_load(); }
        else if (curr_instr.opcode == i_store) { instr_store(); }
        else if (curr_instr.opcode == i_push) { instr_push(); }
        else if (curr_instr.opcode == i_drop) { instr_drop(); }
        else if (curr_instr.opcode == i_add) { instr_add(); }
        else if (curr_instr.opcode == i_mul) { instr_mul(); }
        else if (curr_instr.opcode == i_sub) { instr_sub(); }
        else if (curr_instr.opcode == i_neg) { instr_neg(); }
        else if (curr_instr.opcode == i_reset) { instr_reset(); }
        else if (curr_instr.opcode == i_and) { instr_and(); }
        else if (curr_instr.opcode == i_or) { instr_or(); }
        else if (curr_instr.opcode == i_gt) { instr_gt(); }
        else if (curr_instr.opcode == i_lt) { instr_lt(); }
        else if (curr_instr.opcode == i_lte) { instr_lte(); }
        else if (curr_instr.opcode == i_gte) { instr_gte(); }
        else if (curr_instr.opcode == i_eq) { instr_eq(); }
        else if (curr_instr.opcode == i_neq) { instr_neq(); }
        else if (curr_instr.opcode == i_dup) { instr_dup(); }
        else if (curr_instr.opcode == i_swap) { instr_swap(); }
        else if (curr_instr.opcode == i_over) { instr_over(); }
        else if (curr_instr.opcode == i_rot) { instr_rot(); }
        else if (curr_instr.opcode == i_jump) { instr_jump(); }
        else if (curr_instr.opcode == i_cjump) { instr_cjump(); }
        else if (curr_instr.opcode == i_done) { instr_done(); }
        else if (curr_instr.opcode == i_error) { instr_error(); }
        else if (curr_instr.opcode == i_nop) { instr_nop(); }
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

    apply {
        if (hdr.pdata.done_flg == 1w1 || hdr.pdata.err_flg == 1w1 || hdr.pdata.steps > MAX_STEPS) {
            ipv4_lpm.apply();
        } else {
            parse_stack();
            read_current_instr();
            apply_instr();
            deparse_stack();
            increment_steps();
            ipv4_self_fwd.apply();
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
