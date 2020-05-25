## Stitch - a stack-based DSL for active networking

#### Final project for CS 6114 Network PL (FA19) taught by Nate Foster

Active networking is a networking paradigm that allows user-defined computations carried in packets to be executed on the network, allowing for dynamic modification of the network's behavior. Stitch is a domain-specific bytecode language that implements a form of active networking. Packets containing Stitch programs can be executed by switches, allowing arbitrary computations and modifications to the network in real-time. This enables a wide variety of measurements, computations, and state changes to be performed without modifying/recompiling the switch. The name Stitch is a combination of the words "stack" and "switch".

<p align="center">
  <img src="https://github.com/yangdanny97/p4-stacklang/blob/master/stitch-logo.png?raw=true" alt="a poorly-drawn Stitch logo"/>
</p>

## Usage Overview

This is designed to be run with the P4 development VM, on the v1model simulated switch target. The target-dependent parts of this system are not modular, so code (mainly metadata-related) will need to be modified for it to work on different targets.

The key part of Stitch is the config file; this controls what metadata is supported, the size of the stack/register bank, and the expected topology of the network. From this information, Stitch generates the P4 code for the switch, the Python code for the controller, and the topology JSON for mininet. The latter 2 are included for ease-of-setup for the examples, and can be swapped out for more sophisticated controllers/topologies.

Stitch programs can be encoded as JSON, as seen in some of the examples. For a full list of instructions, see `docs/isa.md`. Please note that the report is quite outdated and certain parts of the execution model have moved to the egress pipeline. 

## Example Programs

To run the examples, first configure the `config.json` and run `make setup`. This will generate `switch.p4`, `controller.py`, and `topology.json` based on the specified configs.

In the config, there is an example configuration and topology already set. The `populate_fwd_table` field determines if the ipv4 lpb table in the switch will be populated with the specified fowarding rules.

Run `make` to compile the p4 switch.

Use a separate tab in the terminal to run the controller after the switch is done compiling. To run programs on the hosts, in the mininet CLI which appears after you run `make`, run `xterm` followed by the hosts you want to open (ex: `xterm h1 h2 h3`).

You'll notice that when sending the stack is represented as a stack of StackVal headers, but when receiving the stack is represented as a single Stack header with 32 fields. This is intentional and mainly for the purposes of having a nice printout as well as making sure Scapy can separate the stack from any raw payload that comes after it.

The topology for these examples is a triangle of switches each connected to 3 hosts (the definition can be found in `config.json`):

|    | s1    | s2    | s3    |
|----|-------|-------|-------|
| p1 | h1    | h4    | h7    |
| p2 | h2    | h5    | h8    |
| p3 | h3    | h6    | h9    |
| p4 | s2-p4 | s1-p4 | s1-p5 |
| p5 | s3-p4 | s3-p5 | s2-p5 |


Additionally, p4 of each switch is set to forward the packet back to p5 on the same switch.

#### Example: Factorial/Fibonacci
Stitch programs for performing mathematical calculations.

- run the setup script, and compile
- run `controller.py`
- run the desired factorial/fibonacci file on any host
- example: `./ex_factorial.py 5` calculates `5!` and returns the packet with the result (in the `result` field of the pdata header) to the sender (inputs to factorial/fibonnacci should keep in mind stack size limitations and integer overflow)

#### Example: Dropped packets detector
Detect and count dropped packets on a particular path.

- set `populate_fwd_table` to `true`, run the setup script, and compile
- run `controller.py`
- run `receive.py` on the desired destination host
- run `ex_dropped_packets.py` on the sender host
- arguments: destination, num_total_packets, num_dropped_packets
- example: running `ex_dropped_packets.py 10.0.2.22 10 4` on h1 sends 10 packets to h2 of which 4 are dropped, and then sends a counting program should arrive at h2 with the result field set to 6

#### Example: Match-action table
Simulate a match-action table using Stitch using registers, and send programs which use the simulated table to forward themselves to the destination.

- set `populate_fwd_table` to `false`, run the setup script, and compile
- run `controller.py`
- run `ex_routing_table_setup.py` from h1, this sets up the registers on each switch to be a forwarding table.
- run `receive.py` on the desired destination host
- run `ex_routing_table_message.py` on the sender host with the destination (host number, not the IP address) as input
- example: running `ex_routing_table_message.py 2 hello` sends a message to h2

#### Example: Source routing
Simple source routing using Stitch.

- set `populate_fwd_table` to `false`, run the setup script, and compile
- run `controller.py`
- run `receive.py` on the desired destination host
- run `ex_source_routing.py` with the message and the list of egress ports separated by spaces
- example: sending from h1 to h2 `ex_source_routing.py hello 2 3 2 2 1`
- example 2: sending from h1 to h2 `ex_source_routing.py hello 2 1`



