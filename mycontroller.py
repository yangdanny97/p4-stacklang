#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep
# from headers import i_load, i_store, i_push, i_drop, i_add, i_mul, i_sub, i_neg, i_reset, i_and, i_or, i_gt, i_lt, i_lte, i_gte, i_eq, i_neq, i_dup, i_swap, i_over, i_rot, i_jump, i_cjump, i_done, i_error, i_nop, i_metadata, i_sal, i_sar
from headers import *

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'utils/'))
import run_exercise
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

switches = {}
p4info_helper = None

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
# (i_metadata, "instr_metadata"),
# (i_sal, "instr_sal"),
# (i_sar, "instr_sar"),
]

def addForwardingRule(switch, dst_ip_addr, dst_port):
    # Helper function to install forwarding rules
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "port": dst_port,
        })
    bmv2_switch = switches[switch]
    bmv2_switch.WriteTableEntry(table_entry)
    print "Installed rule on %s to forward to %s via port %d" % (switch, dst_ip_addr, dst_port)

def addSelfForwardingRule(switch, dst_ip_addr, dst_port):
    # Helper function to install forwarding rules
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_self_fwd",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "port": dst_port,
        })
    bmv2_switch = switches[switch]
    bmv2_switch.WriteTableEntry(table_entry)
    print "Installed rule on %s to forward to %s via port %d" % (switch, dst_ip_addr, dst_port)

def addInstrRule(switch, opcode, action):
    # Helper function to install forwarding rules
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.instruction_table",
        match_fields={
            "hdr.pdata.curr_instr_opcode": opcode
        },
        action_name=action)
    bmv2_switch = switches[switch]
    bmv2_switch.WriteTableEntry(table_entry)
    print "Installed rule for %s" % action
    
def main(p4info_file_path, bmv2_file_path, topo_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    global p4info_helper
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Establish a P4 Runtime connection to each switch
        for switch in ["s1"]:
            switch_id = int(switch[1:])
            bmv2_switch = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name=switch,
                address="127.0.0.1:%d" % (50050 + switch_id),
                device_id=(switch_id - 1),
                proto_dump_file="logs/%s-p4runtime-requests.txt" % switch)            
            bmv2_switch.MasterArbitrationUpdate()
            print "Established as controller for %s" % bmv2_switch.name

            bmv2_switch.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                                    bmv2_json_file_path=bmv2_file_path)
            print "Installed P4 Program using SetForwardingPipelineConfig on %s" % bmv2_switch.name
            switches[switch] = bmv2_switch
            
        addForwardingRule("s1","10.0.3.33",3)
        addForwardingRule("s1","10.0.2.22",2)
        addForwardingRule("s1","10.0.1.11",1)
        addForwardingRule("s2","10.0.3.33",3)
        addForwardingRule("s2","10.0.2.22",1)
        addForwardingRule("s2","10.0.1.11",2)
        addForwardingRule("s3","10.0.3.33",1)
        addForwardingRule("s3","10.0.2.22",3)
        addForwardingRule("s3","10.0.1.11",2)

        addSelfForwardingRule("s1","10.0.3.33",4)
        addSelfForwardingRule("s1","10.0.2.22",4)
        addSelfForwardingRule("s1","10.0.1.11",4)
        addSelfForwardingRule("s2","10.0.3.33",4)
        addSelfForwardingRule("s2","10.0.2.22",4)
        addSelfForwardingRule("s2","10.0.1.11",4)
        addSelfForwardingRule("s3","10.0.3.33",4)
        addSelfForwardingRule("s3","10.0.2.22",4)
        addSelfForwardingRule("s3","10.0.1.11",4)

        for i in instrs:
            opcode, action = i
            addInstrRule("s1", opcode, action)

    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        print "gRPC Error:", e.details(),
        status_code = e.code()
        print "(%s)" % status_code.name,
        traceback = sys.exc_info()[2]
        print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/switch.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/switch.json')
    parser.add_argument('--topo', help='Topology file',
                        type=str, action="store", required=False,
                        default='topology.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    if not os.path.exists(args.topo):
        parser.print_help()
        print "\nTopology file not found: %s" % args.topo
        parser.exit(1)
    main(args.p4info, args.bmv2_json, args.topo)

