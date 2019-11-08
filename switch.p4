/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "headers.p4"

const bit<16> TYPE_IPV4 = 0x800;
const bit<32> H1_ADDR = 0x0A00010B;
const bit<32> H2_ADDR = 0x0A000216;

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

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
            PROTOCOL_NUM: parse_pdata;
            default: accept;
        }
    }

    state parse_pdata {
        packet.extract(hdr.pdata);
        transition parse_instructions;
    }

    state parse_instructions {
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        packet.extract(hdr.instructions.next);
        transition parse_stack;
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

    action read_stack(out bit<32> value, in bit<8> offset) {
        if (offset == 8w0) { value = hdr.stack[0].value; }
        else if (offset == 8w1) { value = hdr.stack[1].value; }
        else if (offset == 8w2) { value = hdr.stack[2].value; }
        else if (offset == 8w3) { value = hdr.stack[3].value; }
        else if (offset == 8w4) { value = hdr.stack[4].value; }
        else if (offset == 8w5) { value = hdr.stack[5].value; }
        else if (offset == 8w6) { value = hdr.stack[6].value; }
        else if (offset == 8w7) { value = hdr.stack[7].value; }
        else if (offset == 8w8) { value = hdr.stack[8].value; }
        else if (offset == 8w9) { value = hdr.stack[9].value; }
        else if (offset == 8w10) { value = hdr.stack[10].value; }
        else if (offset == 8w11) { value = hdr.stack[11].value; }
        else if (offset == 8w12) { value = hdr.stack[12].value; }
        else if (offset == 8w13) { value = hdr.stack[13].value; }
        else if (offset == 8w14) { value = hdr.stack[14].value; }
        else if (offset == 8w15) { value = hdr.stack[15].value; }
        else if (offset == 8w16) { value = hdr.stack[16].value; }
        else if (offset == 8w17) { value = hdr.stack[17].value; }
        else if (offset == 8w18) { value = hdr.stack[18].value; }
        else if (offset == 8w19) { value = hdr.stack[19].value; }
        else if (offset == 8w20) { value = hdr.stack[20].value; }
        else if (offset == 8w21) { value = hdr.stack[21].value; }
        else if (offset == 8w22) { value = hdr.stack[22].value; }
        else if (offset == 8w23) { value = hdr.stack[23].value; }
        else if (offset == 8w24) { value = hdr.stack[24].value; }
        else if (offset == 8w25) { value = hdr.stack[25].value; }
        else if (offset == 8w26) { value = hdr.stack[26].value; }
        else if (offset == 8w27) { value = hdr.stack[27].value; }
        else if (offset == 8w28) { value = hdr.stack[28].value; }
        else if (offset == 8w29) { value = hdr.stack[29].value; }
        else if (offset == 8w30) { value = hdr.stack[30].value; }
        else if (offset == 8w31) { value = hdr.stack[31].value; }
        else if (offset == 8w32) { value = hdr.stack[32].value; }
        else if (offset == 8w33) { value = hdr.stack[33].value; }
        else if (offset == 8w34) { value = hdr.stack[34].value; }
        else if (offset == 8w35) { value = hdr.stack[35].value; }
        else if (offset == 8w36) { value = hdr.stack[36].value; }
        else if (offset == 8w37) { value = hdr.stack[37].value; }
        else if (offset == 8w38) { value = hdr.stack[38].value; }
        else if (offset == 8w39) { value = hdr.stack[39].value; }
        else if (offset == 8w40) { value = hdr.stack[40].value; }
        else if (offset == 8w41) { value = hdr.stack[41].value; }
        else if (offset == 8w42) { value = hdr.stack[42].value; }
        else if (offset == 8w43) { value = hdr.stack[43].value; }
        else if (offset == 8w44) { value = hdr.stack[44].value; }
        else if (offset == 8w45) { value = hdr.stack[45].value; }
        else if (offset == 8w46) { value = hdr.stack[46].value; }
        else if (offset == 8w47) { value = hdr.stack[47].value; }
        else if (offset == 8w48) { value = hdr.stack[48].value; }
        else if (offset == 8w49) { value = hdr.stack[49].value; }
        else if (offset == 8w50) { value = hdr.stack[50].value; }
        else if (offset == 8w51) { value = hdr.stack[51].value; }
        else if (offset == 8w52) { value = hdr.stack[52].value; }
        else if (offset == 8w53) { value = hdr.stack[53].value; }
        else if (offset == 8w54) { value = hdr.stack[54].value; }
        else if (offset == 8w55) { value = hdr.stack[55].value; }
        else if (offset == 8w56) { value = hdr.stack[56].value; }
        else if (offset == 8w57) { value = hdr.stack[57].value; }
        else if (offset == 8w58) { value = hdr.stack[58].value; }
        else if (offset == 8w59) { value = hdr.stack[59].value; }
        else if (offset == 8w60) { value = hdr.stack[60].value; }
        else if (offset == 8w61) { value = hdr.stack[61].value; }
        else if (offset == 8w62) { value = hdr.stack[62].value; }
        else if (offset == 8w63) { value = hdr.stack[63].value; }
        else if (offset == 8w64) { value = hdr.stack[64].value; }
        else if (offset == 8w65) { value = hdr.stack[65].value; }
        else if (offset == 8w66) { value = hdr.stack[66].value; }
        else if (offset == 8w67) { value = hdr.stack[67].value; }
        else if (offset == 8w68) { value = hdr.stack[68].value; }
        else if (offset == 8w69) { value = hdr.stack[69].value; }
        else if (offset == 8w70) { value = hdr.stack[70].value; }
        else if (offset == 8w71) { value = hdr.stack[71].value; }
        else if (offset == 8w72) { value = hdr.stack[72].value; }
        else if (offset == 8w73) { value = hdr.stack[73].value; }
        else if (offset == 8w74) { value = hdr.stack[74].value; }
        else if (offset == 8w75) { value = hdr.stack[75].value; }
        else if (offset == 8w76) { value = hdr.stack[76].value; }
        else if (offset == 8w77) { value = hdr.stack[77].value; }
        else if (offset == 8w78) { value = hdr.stack[78].value; }
        else if (offset == 8w79) { value = hdr.stack[79].value; }
        else if (offset == 8w80) { value = hdr.stack[80].value; }
        else if (offset == 8w81) { value = hdr.stack[81].value; }
        else if (offset == 8w82) { value = hdr.stack[82].value; }
        else if (offset == 8w83) { value = hdr.stack[83].value; }
        else if (offset == 8w84) { value = hdr.stack[84].value; }
        else if (offset == 8w85) { value = hdr.stack[85].value; }
        else if (offset == 8w86) { value = hdr.stack[86].value; }
        else if (offset == 8w87) { value = hdr.stack[87].value; }
        else if (offset == 8w88) { value = hdr.stack[88].value; }
        else if (offset == 8w89) { value = hdr.stack[89].value; }
        else if (offset == 8w90) { value = hdr.stack[90].value; }
        else if (offset == 8w91) { value = hdr.stack[91].value; }
        else if (offset == 8w92) { value = hdr.stack[92].value; }
        else if (offset == 8w93) { value = hdr.stack[93].value; }
        else if (offset == 8w94) { value = hdr.stack[94].value; }
        else if (offset == 8w95) { value = hdr.stack[95].value; }
        else if (offset == 8w96) { value = hdr.stack[96].value; }
        else if (offset == 8w97) { value = hdr.stack[97].value; }
        else if (offset == 8w98) { value = hdr.stack[98].value; }
        else if (offset == 8w99) { value = hdr.stack[99].value; }
        else if (offset == 8w100) { value = hdr.stack[100].value; }
        else if (offset == 8w101) { value = hdr.stack[101].value; }
        else if (offset == 8w102) { value = hdr.stack[102].value; }
        else if (offset == 8w103) { value = hdr.stack[103].value; }
        else if (offset == 8w104) { value = hdr.stack[104].value; }
        else if (offset == 8w105) { value = hdr.stack[105].value; }
        else if (offset == 8w106) { value = hdr.stack[106].value; }
        else if (offset == 8w107) { value = hdr.stack[107].value; }
        else if (offset == 8w108) { value = hdr.stack[108].value; }
        else if (offset == 8w109) { value = hdr.stack[109].value; }
        else if (offset == 8w110) { value = hdr.stack[110].value; }
        else if (offset == 8w111) { value = hdr.stack[111].value; }
        else if (offset == 8w112) { value = hdr.stack[112].value; }
        else if (offset == 8w113) { value = hdr.stack[113].value; }
        else if (offset == 8w114) { value = hdr.stack[114].value; }
        else if (offset == 8w115) { value = hdr.stack[115].value; }
        else if (offset == 8w116) { value = hdr.stack[116].value; }
        else if (offset == 8w117) { value = hdr.stack[117].value; }
        else if (offset == 8w118) { value = hdr.stack[118].value; }
        else if (offset == 8w119) { value = hdr.stack[119].value; }
        else if (offset == 8w120) { value = hdr.stack[120].value; }
        else if (offset == 8w121) { value = hdr.stack[121].value; }
        else if (offset == 8w122) { value = hdr.stack[122].value; }
        else if (offset == 8w123) { value = hdr.stack[123].value; }
        else if (offset == 8w124) { value = hdr.stack[124].value; }
        else if (offset == 8w125) { value = hdr.stack[125].value; }
        else if (offset == 8w126) { value = hdr.stack[126].value; }
        else if (offset == 8w127) { value = hdr.stack[127].value; }
    }

    action write_stack(in bit<8> offset, in bit<32> value) {
        if (offset == 8w0) { hdr.stack[0].value = value; }
        else if (offset == 8w1) { hdr.stack[1].value = value; }
        else if (offset == 8w2) { hdr.stack[2].value = value; }
        else if (offset == 8w3) { hdr.stack[3].value = value; }
        else if (offset == 8w4) { hdr.stack[4].value = value; }
        else if (offset == 8w5) { hdr.stack[5].value = value; }
        else if (offset == 8w6) { hdr.stack[6].value = value; }
        else if (offset == 8w7) { hdr.stack[7].value = value; }
        else if (offset == 8w8) { hdr.stack[8].value = value; }
        else if (offset == 8w9) { hdr.stack[9].value = value; }
        else if (offset == 8w10) { hdr.stack[10].value = value; }
        else if (offset == 8w11) { hdr.stack[11].value = value; }
        else if (offset == 8w12) { hdr.stack[12].value = value; }
        else if (offset == 8w13) { hdr.stack[13].value = value; }
        else if (offset == 8w14) { hdr.stack[14].value = value; }
        else if (offset == 8w15) { hdr.stack[15].value = value; }
        else if (offset == 8w16) { hdr.stack[16].value = value; }
        else if (offset == 8w17) { hdr.stack[17].value = value; }
        else if (offset == 8w18) { hdr.stack[18].value = value; }
        else if (offset == 8w19) { hdr.stack[19].value = value; }
        else if (offset == 8w20) { hdr.stack[20].value = value; }
        else if (offset == 8w21) { hdr.stack[21].value = value; }
        else if (offset == 8w22) { hdr.stack[22].value = value; }
        else if (offset == 8w23) { hdr.stack[23].value = value; }
        else if (offset == 8w24) { hdr.stack[24].value = value; }
        else if (offset == 8w25) { hdr.stack[25].value = value; }
        else if (offset == 8w26) { hdr.stack[26].value = value; }
        else if (offset == 8w27) { hdr.stack[27].value = value; }
        else if (offset == 8w28) { hdr.stack[28].value = value; }
        else if (offset == 8w29) { hdr.stack[29].value = value; }
        else if (offset == 8w30) { hdr.stack[30].value = value; }
        else if (offset == 8w31) { hdr.stack[31].value = value; }
        else if (offset == 8w32) { hdr.stack[32].value = value; }
        else if (offset == 8w33) { hdr.stack[33].value = value; }
        else if (offset == 8w34) { hdr.stack[34].value = value; }
        else if (offset == 8w35) { hdr.stack[35].value = value; }
        else if (offset == 8w36) { hdr.stack[36].value = value; }
        else if (offset == 8w37) { hdr.stack[37].value = value; }
        else if (offset == 8w38) { hdr.stack[38].value = value; }
        else if (offset == 8w39) { hdr.stack[39].value = value; }
        else if (offset == 8w40) { hdr.stack[40].value = value; }
        else if (offset == 8w41) { hdr.stack[41].value = value; }
        else if (offset == 8w42) { hdr.stack[42].value = value; }
        else if (offset == 8w43) { hdr.stack[43].value = value; }
        else if (offset == 8w44) { hdr.stack[44].value = value; }
        else if (offset == 8w45) { hdr.stack[45].value = value; }
        else if (offset == 8w46) { hdr.stack[46].value = value; }
        else if (offset == 8w47) { hdr.stack[47].value = value; }
        else if (offset == 8w48) { hdr.stack[48].value = value; }
        else if (offset == 8w49) { hdr.stack[49].value = value; }
        else if (offset == 8w50) { hdr.stack[50].value = value; }
        else if (offset == 8w51) { hdr.stack[51].value = value; }
        else if (offset == 8w52) { hdr.stack[52].value = value; }
        else if (offset == 8w53) { hdr.stack[53].value = value; }
        else if (offset == 8w54) { hdr.stack[54].value = value; }
        else if (offset == 8w55) { hdr.stack[55].value = value; }
        else if (offset == 8w56) { hdr.stack[56].value = value; }
        else if (offset == 8w57) { hdr.stack[57].value = value; }
        else if (offset == 8w58) { hdr.stack[58].value = value; }
        else if (offset == 8w59) { hdr.stack[59].value = value; }
        else if (offset == 8w60) { hdr.stack[60].value = value; }
        else if (offset == 8w61) { hdr.stack[61].value = value; }
        else if (offset == 8w62) { hdr.stack[62].value = value; }
        else if (offset == 8w63) { hdr.stack[63].value = value; }
        else if (offset == 8w64) { hdr.stack[64].value = value; }
        else if (offset == 8w65) { hdr.stack[65].value = value; }
        else if (offset == 8w66) { hdr.stack[66].value = value; }
        else if (offset == 8w67) { hdr.stack[67].value = value; }
        else if (offset == 8w68) { hdr.stack[68].value = value; }
        else if (offset == 8w69) { hdr.stack[69].value = value; }
        else if (offset == 8w70) { hdr.stack[70].value = value; }
        else if (offset == 8w71) { hdr.stack[71].value = value; }
        else if (offset == 8w72) { hdr.stack[72].value = value; }
        else if (offset == 8w73) { hdr.stack[73].value = value; }
        else if (offset == 8w74) { hdr.stack[74].value = value; }
        else if (offset == 8w75) { hdr.stack[75].value = value; }
        else if (offset == 8w76) { hdr.stack[76].value = value; }
        else if (offset == 8w77) { hdr.stack[77].value = value; }
        else if (offset == 8w78) { hdr.stack[78].value = value; }
        else if (offset == 8w79) { hdr.stack[79].value = value; }
        else if (offset == 8w80) { hdr.stack[80].value = value; }
        else if (offset == 8w81) { hdr.stack[81].value = value; }
        else if (offset == 8w82) { hdr.stack[82].value = value; }
        else if (offset == 8w83) { hdr.stack[83].value = value; }
        else if (offset == 8w84) { hdr.stack[84].value = value; }
        else if (offset == 8w85) { hdr.stack[85].value = value; }
        else if (offset == 8w86) { hdr.stack[86].value = value; }
        else if (offset == 8w87) { hdr.stack[87].value = value; }
        else if (offset == 8w88) { hdr.stack[88].value = value; }
        else if (offset == 8w89) { hdr.stack[89].value = value; }
        else if (offset == 8w90) { hdr.stack[90].value = value; }
        else if (offset == 8w91) { hdr.stack[91].value = value; }
        else if (offset == 8w92) { hdr.stack[92].value = value; }
        else if (offset == 8w93) { hdr.stack[93].value = value; }
        else if (offset == 8w94) { hdr.stack[94].value = value; }
        else if (offset == 8w95) { hdr.stack[95].value = value; }
        else if (offset == 8w96) { hdr.stack[96].value = value; }
        else if (offset == 8w97) { hdr.stack[97].value = value; }
        else if (offset == 8w98) { hdr.stack[98].value = value; }
        else if (offset == 8w99) { hdr.stack[99].value = value; }
        else if (offset == 8w100) { hdr.stack[100].value = value; }
        else if (offset == 8w101) { hdr.stack[101].value = value; }
        else if (offset == 8w102) { hdr.stack[102].value = value; }
        else if (offset == 8w103) { hdr.stack[103].value = value; }
        else if (offset == 8w104) { hdr.stack[104].value = value; }
        else if (offset == 8w105) { hdr.stack[105].value = value; }
        else if (offset == 8w106) { hdr.stack[106].value = value; }
        else if (offset == 8w107) { hdr.stack[107].value = value; }
        else if (offset == 8w108) { hdr.stack[108].value = value; }
        else if (offset == 8w109) { hdr.stack[109].value = value; }
        else if (offset == 8w110) { hdr.stack[110].value = value; }
        else if (offset == 8w111) { hdr.stack[111].value = value; }
        else if (offset == 8w112) { hdr.stack[112].value = value; }
        else if (offset == 8w113) { hdr.stack[113].value = value; }
        else if (offset == 8w114) { hdr.stack[114].value = value; }
        else if (offset == 8w115) { hdr.stack[115].value = value; }
        else if (offset == 8w116) { hdr.stack[116].value = value; }
        else if (offset == 8w117) { hdr.stack[117].value = value; }
        else if (offset == 8w118) { hdr.stack[118].value = value; }
        else if (offset == 8w119) { hdr.stack[119].value = value; }
        else if (offset == 8w120) { hdr.stack[120].value = value; }
        else if (offset == 8w121) { hdr.stack[121].value = value; }
        else if (offset == 8w122) { hdr.stack[122].value = value; }
        else if (offset == 8w123) { hdr.stack[123].value = value; }
        else if (offset == 8w124) { hdr.stack[124].value = value; }
        else if (offset == 8w125) { hdr.stack[125].value = value; }
        else if (offset == 8w126) { hdr.stack[126].value = value; }
        else if (offset == 8w127) { hdr.stack[127].value = value; }
        el
    }

    action read_current_instr() {
        if (hdr.pdata.PC == 8w0) { curr_instr = hdr.instructions[0].value; }
        else if (hdr.pdata.PC == 8w1) { curr_instr = hdr.instructions[1].value; }
        else if (hdr.pdata.PC == 8w2) { curr_instr = hdr.instructions[2].value; }
        else if (hdr.pdata.PC == 8w3) { curr_instr = hdr.instructions[3].value; }
        else if (hdr.pdata.PC == 8w4) { curr_instr = hdr.instructions[4].value; }
        else if (hdr.pdata.PC == 8w5) { curr_instr = hdr.instructions[5].value; }
        else if (hdr.pdata.PC == 8w6) { curr_instr = hdr.instructions[6].value; }
        else if (hdr.pdata.PC == 8w7) { curr_instr = hdr.instructions[7].value; }
        else if (hdr.pdata.PC == 8w8) { curr_instr = hdr.instructions[8].value; }
        else if (hdr.pdata.PC == 8w9) { curr_instr = hdr.instructions[9].value; }
        else if (hdr.pdata.PC == 8w10) { curr_instr = hdr.instructions[10].value; }
        else if (hdr.pdata.PC == 8w11) { curr_instr = hdr.instructions[11].value; }
        else if (hdr.pdata.PC == 8w12) { curr_instr = hdr.instructions[12].value; }
        else if (hdr.pdata.PC == 8w13) { curr_instr = hdr.instructions[13].value; }
        else if (hdr.pdata.PC == 8w14) { curr_instr = hdr.instructions[14].value; }
        else if (hdr.pdata.PC == 8w15) { curr_instr = hdr.instructions[15].value; }
        else if (hdr.pdata.PC == 8w16) { curr_instr = hdr.instructions[16].value; }
        else if (hdr.pdata.PC == 8w17) { curr_instr = hdr.instructions[17].value; }
        else if (hdr.pdata.PC == 8w18) { curr_instr = hdr.instructions[18].value; }
        else if (hdr.pdata.PC == 8w19) { curr_instr = hdr.instructions[19].value; }
        else if (hdr.pdata.PC == 8w20) { curr_instr = hdr.instructions[20].value; }
        else if (hdr.pdata.PC == 8w21) { curr_instr = hdr.instructions[21].value; }
        else if (hdr.pdata.PC == 8w22) { curr_instr = hdr.instructions[22].value; }
        else if (hdr.pdata.PC == 8w23) { curr_instr = hdr.instructions[23].value; }
        else if (hdr.pdata.PC == 8w24) { curr_instr = hdr.instructions[24].value; }
        else if (hdr.pdata.PC == 8w25) { curr_instr = hdr.instructions[25].value; }
        else if (hdr.pdata.PC == 8w26) { curr_instr = hdr.instructions[26].value; }
        else if (hdr.pdata.PC == 8w27) { curr_instr = hdr.instructions[27].value; }
        else if (hdr.pdata.PC == 8w28) { curr_instr = hdr.instructions[28].value; }
        else if (hdr.pdata.PC == 8w29) { curr_instr = hdr.instructions[29].value; }
        else if (hdr.pdata.PC == 8w30) { curr_instr = hdr.instructions[30].value; }
        else if (hdr.pdata.PC == 8w31) { curr_instr = hdr.instructions[31].value; }
        else if (hdr.pdata.PC == 8w32) { curr_instr = hdr.instructions[32].value; }
        else if (hdr.pdata.PC == 8w33) { curr_instr = hdr.instructions[33].value; }
        else if (hdr.pdata.PC == 8w34) { curr_instr = hdr.instructions[34].value; }
        else if (hdr.pdata.PC == 8w35) { curr_instr = hdr.instructions[35].value; }
        else if (hdr.pdata.PC == 8w36) { curr_instr = hdr.instructions[36].value; }
        else if (hdr.pdata.PC == 8w37) { curr_instr = hdr.instructions[37].value; }
        else if (hdr.pdata.PC == 8w38) { curr_instr = hdr.instructions[38].value; }
        else if (hdr.pdata.PC == 8w39) { curr_instr = hdr.instructions[39].value; }
        else if (hdr.pdata.PC == 8w40) { curr_instr = hdr.instructions[40].value; }
        else if (hdr.pdata.PC == 8w41) { curr_instr = hdr.instructions[41].value; }
        else if (hdr.pdata.PC == 8w42) { curr_instr = hdr.instructions[42].value; }
        else if (hdr.pdata.PC == 8w43) { curr_instr = hdr.instructions[43].value; }
        else if (hdr.pdata.PC == 8w44) { curr_instr = hdr.instructions[44].value; }
        else if (hdr.pdata.PC == 8w45) { curr_instr = hdr.instructions[45].value; }
        else if (hdr.pdata.PC == 8w46) { curr_instr = hdr.instructions[46].value; }
        else if (hdr.pdata.PC == 8w47) { curr_instr = hdr.instructions[47].value; }
        else if (hdr.pdata.PC == 8w48) { curr_instr = hdr.instructions[48].value; }
        else if (hdr.pdata.PC == 8w49) { curr_instr = hdr.instructions[49].value; }
        else if (hdr.pdata.PC == 8w50) { curr_instr = hdr.instructions[50].value; }
        else if (hdr.pdata.PC == 8w51) { curr_instr = hdr.instructions[51].value; }
        else if (hdr.pdata.PC == 8w52) { curr_instr = hdr.instructions[52].value; }
        else if (hdr.pdata.PC == 8w53) { curr_instr = hdr.instructions[53].value; }
        else if (hdr.pdata.PC == 8w54) { curr_instr = hdr.instructions[54].value; }
        else if (hdr.pdata.PC == 8w55) { curr_instr = hdr.instructions[55].value; }
        else if (hdr.pdata.PC == 8w56) { curr_instr = hdr.instructions[56].value; }
        else if (hdr.pdata.PC == 8w57) { curr_instr = hdr.instructions[57].value; }
        else if (hdr.pdata.PC == 8w58) { curr_instr = hdr.instructions[58].value; }
        else if (hdr.pdata.PC == 8w59) { curr_instr = hdr.instructions[59].value; }
        else if (hdr.pdata.PC == 8w60) { curr_instr = hdr.instructions[60].value; }
        else if (hdr.pdata.PC == 8w61) { curr_instr = hdr.instructions[61].value; }
        else if (hdr.pdata.PC == 8w62) { curr_instr = hdr.instructions[62].value; }
        else if (hdr.pdata.PC == 8w63) { curr_instr = hdr.instructions[63].value; }
        else if (hdr.pdata.PC == 8w64) { curr_instr = hdr.instructions[64].value; }
        else if (hdr.pdata.PC == 8w65) { curr_instr = hdr.instructions[65].value; }
        else if (hdr.pdata.PC == 8w66) { curr_instr = hdr.instructions[66].value; }
        else if (hdr.pdata.PC == 8w67) { curr_instr = hdr.instructions[67].value; }
        else if (hdr.pdata.PC == 8w68) { curr_instr = hdr.instructions[68].value; }
        else if (hdr.pdata.PC == 8w69) { curr_instr = hdr.instructions[69].value; }
        else if (hdr.pdata.PC == 8w70) { curr_instr = hdr.instructions[70].value; }
        else if (hdr.pdata.PC == 8w71) { curr_instr = hdr.instructions[71].value; }
        else if (hdr.pdata.PC == 8w72) { curr_instr = hdr.instructions[72].value; }
        else if (hdr.pdata.PC == 8w73) { curr_instr = hdr.instructions[73].value; }
        else if (hdr.pdata.PC == 8w74) { curr_instr = hdr.instructions[74].value; }
        else if (hdr.pdata.PC == 8w75) { curr_instr = hdr.instructions[75].value; }
        else if (hdr.pdata.PC == 8w76) { curr_instr = hdr.instructions[76].value; }
        else if (hdr.pdata.PC == 8w77) { curr_instr = hdr.instructions[77].value; }
        else if (hdr.pdata.PC == 8w78) { curr_instr = hdr.instructions[78].value; }
        else if (hdr.pdata.PC == 8w79) { curr_instr = hdr.instructions[79].value; }
        else if (hdr.pdata.PC == 8w80) { curr_instr = hdr.instructions[80].value; }
        else if (hdr.pdata.PC == 8w81) { curr_instr = hdr.instructions[81].value; }
        else if (hdr.pdata.PC == 8w82) { curr_instr = hdr.instructions[82].value; }
        else if (hdr.pdata.PC == 8w83) { curr_instr = hdr.instructions[83].value; }
        else if (hdr.pdata.PC == 8w84) { curr_instr = hdr.instructions[84].value; }
        else if (hdr.pdata.PC == 8w85) { curr_instr = hdr.instructions[85].value; }
        else if (hdr.pdata.PC == 8w86) { curr_instr = hdr.instructions[86].value; }
        else if (hdr.pdata.PC == 8w87) { curr_instr = hdr.instructions[87].value; }
        else if (hdr.pdata.PC == 8w88) { curr_instr = hdr.instructions[88].value; }
        else if (hdr.pdata.PC == 8w89) { curr_instr = hdr.instructions[89].value; }
        else if (hdr.pdata.PC == 8w90) { curr_instr = hdr.instructions[90].value; }
        else if (hdr.pdata.PC == 8w91) { curr_instr = hdr.instructions[91].value; }
        else if (hdr.pdata.PC == 8w92) { curr_instr = hdr.instructions[92].value; }
        else if (hdr.pdata.PC == 8w93) { curr_instr = hdr.instructions[93].value; }
        else if (hdr.pdata.PC == 8w94) { curr_instr = hdr.instructions[94].value; }
        else if (hdr.pdata.PC == 8w95) { curr_instr = hdr.instructions[95].value; }
        else if (hdr.pdata.PC == 8w96) { curr_instr = hdr.instructions[96].value; }
        else if (hdr.pdata.PC == 8w97) { curr_instr = hdr.instructions[97].value; }
        else if (hdr.pdata.PC == 8w98) { curr_instr = hdr.instructions[98].value; }
        else if (hdr.pdata.PC == 8w99) { curr_instr = hdr.instructions[99].value; }
        else if (hdr.pdata.PC == 8w100) { curr_instr = hdr.instructions[100].value; }
        else if (hdr.pdata.PC == 8w101) { curr_instr = hdr.instructions[101].value; }
        else if (hdr.pdata.PC == 8w102) { curr_instr = hdr.instructions[102].value; }
        else if (hdr.pdata.PC == 8w103) { curr_instr = hdr.instructions[103].value; }
        else if (hdr.pdata.PC == 8w104) { curr_instr = hdr.instructions[104].value; }
        else if (hdr.pdata.PC == 8w105) { curr_instr = hdr.instructions[105].value; }
        else if (hdr.pdata.PC == 8w106) { curr_instr = hdr.instructions[106].value; }
        else if (hdr.pdata.PC == 8w107) { curr_instr = hdr.instructions[107].value; }
        else if (hdr.pdata.PC == 8w108) { curr_instr = hdr.instructions[108].value; }
        else if (hdr.pdata.PC == 8w109) { curr_instr = hdr.instructions[109].value; }
        else if (hdr.pdata.PC == 8w110) { curr_instr = hdr.instructions[110].value; }
        else if (hdr.pdata.PC == 8w111) { curr_instr = hdr.instructions[111].value; }
        else if (hdr.pdata.PC == 8w112) { curr_instr = hdr.instructions[112].value; }
        else if (hdr.pdata.PC == 8w113) { curr_instr = hdr.instructions[113].value; }
        else if (hdr.pdata.PC == 8w114) { curr_instr = hdr.instructions[114].value; }
        else if (hdr.pdata.PC == 8w115) { curr_instr = hdr.instructions[115].value; }
        else if (hdr.pdata.PC == 8w116) { curr_instr = hdr.instructions[116].value; }
        else if (hdr.pdata.PC == 8w117) { curr_instr = hdr.instructions[117].value; }
        else if (hdr.pdata.PC == 8w118) { curr_instr = hdr.instructions[118].value; }
        else if (hdr.pdata.PC == 8w119) { curr_instr = hdr.instructions[119].value; }
        else if (hdr.pdata.PC == 8w120) { curr_instr = hdr.instructions[120].value; }
        else if (hdr.pdata.PC == 8w121) { curr_instr = hdr.instructions[121].value; }
        else if (hdr.pdata.PC == 8w122) { curr_instr = hdr.instructions[122].value; }
        else if (hdr.pdata.PC == 8w123) { curr_instr = hdr.instructions[123].value; }
        else if (hdr.pdata.PC == 8w124) { curr_instr = hdr.instructions[124].value; }
        else if (hdr.pdata.PC == 8w125) { curr_instr = hdr.instructions[125].value; }
        else if (hdr.pdata.PC == 8w126) { curr_instr = hdr.instructions[126].value; }
        else if (hdr.pdata.PC == 8w127) { curr_instr = hdr.instructions[127].value; }
    }

    action increment_pc() {
        hdr.pdata.PC = hdr.pdata.PC + 8w1;
    }

    action apply_instr() {
        if (curr_instr.opcode == i_load) { load.apply(); }
        else if (curr_instr.opcode == i_store) { store.apply(); }
        else if (curr_instr.opcode == i_push) { push.apply(); }
        else if (curr_instr.opcode == i_drop) { drop.apply(); }
        else if (curr_instr.opcode == i_add) { add.apply(); }
        else if (curr_instr.opcode == i_mul) { mul.apply(); }
        else if (curr_instr.opcode == i_sub) { sub.apply(); }
        else if (curr_instr.opcode == i_neg) { neg.apply(); }
        else if (curr_instr.opcode == i_reset) { reset.apply(); }
        else if (curr_instr.opcode == i_and) { and.apply(); }
        else if (curr_instr.opcode == i_or) { or.apply(); }
        else if (curr_instr.opcode == i_gt) { gt.apply(); }
        else if (curr_instr.opcode == i_lt) { lt.apply(); }
        else if (curr_instr.opcode == i_lte) { lte.apply(); }
        else if (curr_instr.opcode == i_gte) { gte.apply(); }
        else if (curr_instr.opcode == i_eq) { eq.apply(); }
        else if (curr_instr.opcode == i_neq) { neq.apply(); }
        else if (curr_instr.opcode == i_dup) { dup.apply(); }
        else if (curr_instr.opcode == i_swap) { swap.apply(); }
        else if (curr_instr.opcode == i_over) { over.apply(); }
        else if (curr_instr.opcode == i_rot) { rot.apply(); }
        else if (curr_instr.opcode == i_jump) { jump.apply(); }
        else if (curr_instr.opcode == i_cjump) { cjump.apply(); }
        else if (curr_instr.opcode == i_done) { done.apply(); }
        else if (curr_instr.opcode == i_error) { error.apply(); }
        else if (curr_instr.opcode == i_nop) { nop.apply(); }
    }

    // TODO instruction actions

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
        if (hdr.pdata.done == 1w1 || hdr.pdata.error == 1w1) {
            ipv4_lpm.apply();
        } else {
            read_current_instr.apply();
            apply_instr.apply();
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
        packet.emit(hdr.stack)
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
