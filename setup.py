import json

def load_topology(config):
    topology = config["topology"]
    hosts = topology["hosts"]
    switches = topology["switches"]
    links = topology["links"]
    self_links = set(switches)
    for l in links:
        if "-" in l[0] and "-" in l[1]:
            sl1 = l[0].split("-")
            sl2 = l[1].split("-")
            if sl1[0] == sl2[0] and sl1[0] in switches:
                if ((int(sl2[1][1:]) == config["recirculate-out"] and int(sl1[1][1:]) == config["recirculate-in"]) or
                    (int(sl1[1][1:]) == config["recirculate-out"] and int(sl2[1][1:]) == config["recirculate-in"])):
                    self_links.remove(sl1[0])
    if len(self_links) > 0:
        raise Exception("switches need to be able to send packets to themselves using ports [recirculate_in] and [recirculate_out] in config.json")
    with open("topology.json","w") as f:
        json.dump(topology, f)
    return topology

def setup_headers(config):
    with open("./templates/headers-template.py", "r") as f:
        headers = f.read()
        stack_fields = []
        for i in range(config["stack-size"]):
            stack_fields.append("        IntField('idx_%s', 0)" % str(i))
        headers = headers.replace("<< stack_fields >>", ",\n".join(stack_fields))
        with open("headers.py", "w") as outfile:
            outfile.write(headers)

def setup_switch(config):
    with open("./templates/switch-template.p4", "r") as f:
        switch = f.read()
        switch = switch.replace("<< max_steps >>", str(config["n-steps"]))
        switch = switch.replace("<< stack_size >>", str(config["stack-size"]))
        switch = switch.replace("<< max_instrs >>", str(config["n-instrs"]+1))
        switch = switch.replace("<< n_registers >>", str(config["n-registers"]))
        switch = switch.replace("<< max_steps >>", str(config["n-steps"]))
        switch = switch.replace("<< max_ports >>", str(config["max-ports"]))
        parse_opcodes = []
        parse_args = []
        for i in range(config["n-instrs"]):
            parse_opcodes.append("        opcodes.write(%s, hdr.instructions[%s].opcode);\n" % (str(i), str(i)))
            parse_args.append("        args.write(%s, hdr.instructions[%s].arg);\n" % (str(i), str(i)))
        parse_stack = []
        deparse_stack = []
        for i in range(config["stack-size"]):
            parse_stack.append("        stack.write(%s, hdr.stack[%s].value);\n" % (str(i), str(i)))
            deparse_stack.append("        stack.read(hdr.stack[%s].value, %s);\n" % (str(i), str(i)))
        switch = switch.replace("<< parse_opcodes >>", "".join(parse_opcodes))
        switch = switch.replace("<< parse_args >>", "".join(parse_args))
        switch = switch.replace("<< parse_stack >>", "".join(parse_stack))
        switch = switch.replace("<< deparse_stack >>", "".join(deparse_stack))
        switch = switch.replace("<< recirculate_out >>", str(config["recirculate-out"]))
        switch = switch.replace("<< recirculate_in >>", str(config["recirculate-in"]))
        with open("switch.p4", "w") as outfile:
            outfile.write(switch)

def setup_controller(config, topology):
    switches = [x.encode('ascii') for x in list(topology["switches"])]
    with open("./templates/controller-template.py", "r") as f:
        controller = f.read()
        controller = controller.replace("<< switches >>", str(switches))
        forwarding_rules = []
        if config["populate_fwd_table"]:
            for rule in config["forwarding_rules"]:
                forwarding_rules.append("        addForwardingRule('%s', '%s', %s)\n" % (rule[0], rule[1], str(rule[2])))
        controller = controller.replace("<< forwarding_rules >>", "".join(forwarding_rules))   
        with open("controller.py", "w") as outfile:
            outfile.write(controller)

def __main__():
    with open("config.json","r") as f:
        config = json.load(f)
        topology = load_topology(config)
        setup_switch(config)
        setup_headers(config)
        setup_controller(config, topology)

__main__()