|**Instruction** |**Description** |
|--|--|
|load [n] |copy the value at offset [n] from the bottom of the stack, and push it to the top of the stack |
|store [n] |pop the value at the top of stack and store it at offset [n] from the bottom of the stack |
|loadreg [n] |copy the value in register [n] on the switch, and push it to the top of the stack |
|storereg [n] |pop the value at the top of stack and store it in register [n] on the switch |
|push [n] |push [n] on top of stack |
|drop |pops the value on top of the stack and throws it away |
|add/mul/sub/sal/sar |the left operand is the top of the stack, the right operand is the second from the top, pops both operands and pushes the result onto the stack. |
|neg |unary integer negation |
|reset |set SP to 0, essentially dropping the entire stack; used if the stack should not be preserved between hops |
|and/or |values > 0 are treated as truthy and values <= 0 are treated as falsy; pushes 1 if result is true, 0 if false |
|not |unary boolean negation (values > 0 get turned into 0, values <= 0 get turned into 1) |
|gt/lt/gt/lte/eq/neq |pushes 1 if result is true, 0 if false |
|dup |make a copy of the top value on the stack and push it onto the stack |
|swap |swaps the top 2 values in the stack |
|over |make a copy of the second value from the top the stack and push it onto the stack |
|rot |rotate the top 3 values on the stack, such that the 3rd from the top becomes the top, and the top 2 values move down |
|jump [n] |set PC to [n] |
|cjump [n] |pop the value on top of the stack, if it's truthy then jump to [n] otherwise fall through |
|done |set the [done] flag to 1 |
|error |set the [error] flag to 1 |
|nop |does nothing |
|metadata [n] |hardware specific; push the value of some standard metadata field [n] to top of stack; values are extended/truncated to fit. <br> **Implemented metadata fields for v1model:** <br> 0 ingress_port <br>  1 packet_length<br>  2 enq_qdepth<br>  3 deq_qdepth<br>  4 egresss_spec<br>5 enq_timestamp<br> 6 deq_timedelta<br>  7 switch_id<br> 8 rx_util<br>  9 tx_util<br> 10 ingress_timestamp<br> 11 egress_timestamp
|setegress |pop top of stack and set egress spec to the port corresponding to that value; this ends the current execution of the program, and will emit the packet out of the specified port and reset the PC/steps fields in the program data header. Setting the port to the special drop port will result in the packet being dropped; the value of this port is hardware-dependent
|setresult |pop the top of stack and puts the value in the result field of the program data |
|varload/varloadreg |variant of load/loadreg which pops the top of the stack and uses that value as the offset/register number to read; this effectively replaces the top value on the stack, and the size of the stack should not change. `push 1; varload` is equivalent to `load 1` |
|varstore/varstorereg |variant of load/loadreg which pops the top 2 values of the stack; the top value is used as the offset/register number to write to, and the second value is the value that is stored. `push 1; push 2; varstore` is equivalent to `push 1; store 2`|

|**Instruction** |**Opcode** |
|--|--|
|load |0x00 |
|store |0x01 |
|push |0x02 |
|drop |0x03 |
|add |0x04 |
|mul |0x05 |
|sub |0x06 |
|neg |0x07 |
|reset |0x08 |
|and |0x09 |
|or |0x0A |
|gt |0x0B |
|lt |0x0C |
|lte |0x0D |
|gte |0x0E |
|eq |0x0F |
|neq |0x10 |
|dup |0x11 |
|swap |0x12 |
|over |0x13 |
|rot |0x14 |
|jump |0x15 |
|cjump |0x16 |
|done |0x17 |
|error |0x18 |
|nop |0x19 |
|loadreg |0x1A |
|storereg |0x1B |
|metadata |0x1C |
|sal |0x1D |
|sar |0x1E |
|not |0x1F |
|setegress |0x20 |
|setresult |0x21 |
|varload |0x22 |
|varstore |0x23 |
|varloadreg |0x24 |
|varstorereg |0x25 |
