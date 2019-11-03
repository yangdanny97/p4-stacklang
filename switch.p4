/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TCP = 0x06;
const bit<8> UDP = 0x11;
const bit<32> H1_ADDR = 0x0A00010B;
const bit<32> H2_ADDR = 0x0A000216;
const bit<32> H3_ADDR = 0x0A000321;
const bit<32> FAKE_ADDR = 0x0A000063;

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

header myTunnel_t {
    bit<16> proto_id;
    bit<16> dst_id;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> sequenceNum;
    bit<32> ackNum;
    bit<4>  offset;
    bit<3>  reserved;
    bit<9>  ctrl;
    bit<16> windowSize;
    bit<16> checkSum;
    bit<16> urgent;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
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
    tcp_t tcp;
    udp_t udp;
}

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
            TCP: parse_tcp;
            UDP: parse_udp;
            default: accept;
        }
//        transition accept;
    }

    state parse_tcp {
       packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply { 
        verify_checksum(
            hdr.ipv4.isValid(), 
            {   
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                16w0x0000,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum, 
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    bit<1> lb_hash = 0;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action loadBalance() {
        hash(lb_hash, HashAlgorithm.crc16, 16w0, 
            {
                hdr.ipv4.srcAddr, 
                hdr.ipv4.dstAddr, 
                hdr.ipv4.protocol,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.udp.srcPort,
                hdr.udp.dstPort
            }, 16w2);
        if (lb_hash == 1w0) {
            hdr.ethernet.dstAddr = 48w0x080000000216;
            hdr.ipv4.dstAddr = H2_ADDR;
        } else {
            hdr.ethernet.dstAddr = 48w0x080000000321;
            hdr.ipv4.dstAddr = H3_ADDR;
        }
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

    table acl {
        key = {
            hdr.ipv4.srcAddr: ternary;
            hdr.ipv4.dstAddr: ternary;
            hdr.ethernet.srcAddr: ternary;
            hdr.ethernet.dstAddr: ternary;
            hdr.tcp.srcPort: ternary;
            hdr.tcp.dstPort: ternary;
            hdr.udp.srcPort: ternary;
            hdr.udp.dstPort: ternary;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    apply {
        // Process only IPv4 packets.	
        if (hdr.ipv4.isValid() && standard_metadata.checksum_error == 1w0) {
            if (hdr.ipv4.srcAddr == H1_ADDR && hdr.ipv4.dstAddr == FAKE_ADDR) {
                loadBalance();
            }
            ipv4_lpm.apply();
            acl.apply();
        } else {
	       drop();
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
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
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
