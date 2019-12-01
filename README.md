## Stitch - a stack-based DSL for active networking

#### Final project for CS 6114 Network PL (FA19) taught by Nate Foster

Active networking is a networking paradigm that allows user-defined computations carried in packets to be executed on the network, allowing for dynamic modification of the network's behavior. Stitch is a domain specific bytecode language that implements a form of active networking. Packets containing Stitch programs can be executed by switches, allowing arbitrary computations and modifications to the network in real-time. This enables a wide variety of measurements, computations, and state changes to be performed without modifying/recompiling the switch. The name Stitch is a combination of the words "stack" and "switch".

<p align="center">
  <img src="https://github.com/yangdanny97/p4-stacklang/blob/master/stitch-logo.png?raw=true" alt="a poorly-drawn Stitch logo"/>
</p>

## Example Programs

To run the examples, first run `make`, then follow the instructions below.

Use a separate tab in the terminal to run the controller after the switch is done compiling. To run programs on the hosts, in the mininet cli which appears after you run `make`, run `xterm` followed by the hosts you want to open (ex: `xterm h1 h2 h3`).

There are two controller files:
- `mycontroller.py` sets up the regular ipv4 lpm forwarding table and instruction tables
- `mycontroller_nofwd.py` only sets up the instruction tables, with no forwarding rules - this isn't strictly necessary since Stitch programs can override this forwarding behavior, but I want to show that forwarding tables are not used at all for some of the examples

You'll notice that when sending the stack is represented as a stack of StackVal headers, but when receiving the stack is represented as a single Stack header with 32 fields. This is intentional and mainly for the purposes of having a nice printout as well as making sure Scapy can separate the stack from any raw payload that comes after it.

The topology for these examples is as follows (the definition can be found in `topology.json`):

|    | s1    | s2    | s3    |
|----|-------|-------|-------|
| p1 | h1    | h2    | h3    |
| p2 | s2-p2 | s1-p2 | s1-p3 |
| p3 | s3-p2 | s3-p3 | s2-p3 |

Additionally, p4 of each switch is set to forward the packet back to p5 on the same switch.

#### Factorial/Fibonacci:
Stitch programs for performing mathematical calculations.

- run either controller
- run the desired factorial/fibonacci file on any host
- example: `./ex_factorial.py 5` calculates `5!` and returns the packet with the result (in the `result` field of the pdata header) to the sender (inputs to factorial/fibonnacci should keep in mind stack size limitations and integer overflow)

#### Dropped packets:
Detect and count dropped packets on a particular path.

- run `mycontroller.py`
- run `receive.py` on the desired destination host
- run `ex_dropped_packets.py` on the sender host
- arguments: destination, num_total_packets, num_dropped_packets
- example: running `ex_dropped_packets.py 10.0.2.22 10 4` on h1 sends 10 packets to h2 of which 4 are dropped, and the probe program should arrive at h2 with the result field set to 6

#### Pseudo routing table:
Simulate a match-action table using Stitch using registers, and send programs which use the simulated table to forward themselves to the destination.

- run `mycontroller_nofwd.py`
- run `ex_routing_table_setup.py` from h1, this sets up the registers on each switch to be a forwarding table.
- run `receive.py` on the desired destination host
- run `ex_routing_table_message.py` on the sender host with the destination (host number, not the IP address) as input
- example: running `ex_routing_table_message.py 2 hello` sends a message to h2

#### Source routing:
Simple source routing using Stitch.

- run `mycontroller_nofwd.py`
- run `receive.py` on the desired destination host
- run `ex_source_routing.py` with the message and the list of egress ports separated by spaces
- example: sending from h1 to h2 `ex_source_routing.py hello 2 3 2 2 1`
- example 2: sending from h1 to h2 `ex_source_routing.py hello 2 1`



