### Examples

To run the examples, first run `make`, then follow the instructions below.

Use a separate tab in the terminal to run the controller after the switch is done compiling. To run programs on the hosts, in the mininet cli which appears after you run `make`, run `xterm` followed by the hosts you want to open (ex: `xterm h1 h2 h3`).

There are two controller files:
- mycontroller sets up the regular ipv4 lpm forwarding table and instruction tables
- mycontroller_nofwd only sets up the instruction tables, with no forwarding rules - this isn't strictly necessary since Stitch programs can override this forwarding behavior, but I want to show that forwarding tables are not used at all for some of the examples

You'll notice that when sending the stack is represented as a stack of StackVal headers, but when receiving the stack is represented as a single Stack header with 32 fields. This is intentional and mainly for the purposes of having a nice printout as well as making sure Scapy can separate the stack from any raw payload that comes after it.

#### Factorial/Fibonacci:
- run either controller
- run the desired factorial/fibonacci file on any host
- example: `./ex_factorial.py 5` calculates `5!` and returns the packet with the result (in the `result` field of the pdata header) to the sender

#### Dropped packets:
- run `mycontroller.py`
- run `receive.py` on the desired destination host
- run `ex_dropped_packets.py` on the sender host with the desired arguments
- arguments: destination, num_total_packets, num_dropped_packets
- example: running `ex_dropped_packets.py 10.0.2.22 10 4` on h1 sends 10 packets to h2 of which 4 are dropped, and the probe program should arrive at h2 with the result field set to 6.

#### Pseudo routing table:
- run `mycontroller_nofwd.py`
- run `ex_routing_table_setup.py` from h1, this sets up the registers on each switch to be a forwarding table.
- run `receive.py` on the desired destination host
- run `ex_routing_table_message.py` on the sender host with the desired destination (host number, not the IP address) as input
- example: running `ex_routing_table_message.py 2` sends a message to h2

#### Source routing:
- run `mycontroller_nofwd.py`
- run `receive.py` on the desired destination host
- run `ex_source_routing.py` with the list of egress ports separated by spaces
- example: sending from h1 to h2 `ex_source_routing.py 2 3 2 2 1`
- example 2: sending from h1 to h2 `ex_source_routing.py 2 1`

The topology for these examples is as follows:

|    | s1    | s2    | s3    |
|----|-------|-------|-------|
| p1 | h1    | h2    | h3    |
| p2 | s2-p2 | s1-p2 | s1-p3 |
| p3 | s3-p2 | s3-p3 | s2-p3 |

Additionally, p4 of each switch is set to forward the packet back to the same switch.


