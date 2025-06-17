VM-v2 [Reversing, 482 points, 13 solves, 2nd solver]  
========

### Description

>Yet another VM challenge.  
>  
>Note: this fixes an unintended solution to vm. The only change is in the
`data.txt` file.  
>  
>Author: kz  
>  
>**Files:**  
>  
> * [chal.sv](https://github.com/kjcolley7/CTF-
> WriteUps/blob/master/2022/maple/vm-1_and_2/chal.sv)  
> * [prog.txt](https://github.com/kjcolley7/CTF-
> WriteUps/blob/master/2022/maple/vm-1_and_2/prog.txt)  
> * [data.txt](https://github.com/kjcolley7/CTF-
> WriteUps/blob/master/2022/maple/vm-1_and_2/data.txt)  
> * [data2.txt](https://github.com/kjcolley7/CTF-
> WriteUps/blob/master/2022/maple/vm-1_and_2/data2.txt)

### Overview

The challenge name and description indicate that this challenge involves a
custom CPU architecture and instruction set. I'm a huge fan of those types of
challenges, so I immediately jumped on this challenge when I started in this
CTF. Taking a look at the [prog.txt](https://github.com/kjcolley7/CTF-
WriteUps/blob/master/2022/maple/vm-1_and_2/prog.txt) and
[data.txt](https://github.com/kjcolley7/CTF-
WriteUps/blob/master/2022/maple/vm-1_and_2/data.txt) files, we can see that
they are text files containing a bunch of hex values. Then we get another file
called [chal.sv](https://github.com/kjcolley7/CTF-
WriteUps/blob/master/2022/maple/vm-1_and_2/chal.sv). I didn't know what that
file extension meant, but after opening it in a code editor, I can see that it
looks a lot like Verilog. I've never really used Verilog before, but I'm
vaguely familiar with how it works. As it turns out, `.sv` files are
SystemVerilog, which I think is like an extension to Verilog. Both Verilog and
SystemVerilog are HDL languages (hardware description language), meaning they
are code files that describe a hardware logic circuit (like a processor).
Therefore, based on the idea that this is a custom CPU challenge and that we
are given a hardware description of a circuit, it's clear that this file must
implement a full CPU that can execute instructions from the `prog.txt` file.

### De-obfuscating the SystemVerilog code

Sadly, the challenge author wasn't very kind to players. All of the variable
names (except for `flag`) were replaced with randomly generated alphanumeric
strings. Therefore, the SystemVerilog code we have to reverse engineer looks
like this:

```SystemVerilog  
module Ol8vW(eo3,nF3,QU6cTlk,Jpup6gEow,nFOoEI7Dnl,QV,pb);  
   input eo3,nF3,pb;

   input [7:0] QU6cTlk;  
   output [7:0] Jpup6gEow,nFOoEI7Dnl;  
   input [2:0] QV;

   parameter WXifi4fqUy9NY = 16;  
   logic [7:0] fgS [2**WXifi4fqUy9NY-1:0];  
   logic [WXifi4fqUy9NY-1:0] gPrDVGD;

   always_ff @(posedge eo3) begin  
```

As a point of reference, after I manually reverse engineered the whole file
and renamed everything, that same code looks like this:

```SystemVerilog  
module Stack(clock,reset,pushValue,poppedHigh,poppedLow,stackOp,stackEnable);  
   input clock,reset,stackEnable;

   input [7:0] pushValue;  
   output [7:0] poppedHigh,poppedLow;  
   input [2:0] stackOp;

   parameter stackBytes = 16;  
   logic [7:0] stackMem [2**stackBytes-1:0];  
   logic [stackBytes-1:0] stackPointer;

   always_ff @(posedge clock) begin  
```

> Note: Likely, the names that I came up with aren't exactly the same as the
> original names. In fact, one thing I noticed while reversing this code is
> that the lengths of the randomly generated names appear to all match the
> lengths of whatever the original names were in the source code. In this
> case, `eo3` probably was `clk` (I named it `clock`) in the original code.

The process for deobfuscating this SystemVerilog file was almost identical to
reverse engineering any program in IDA. I just tried to reason about the
components, and I renamed things for clarity as I went. Eventually, the code
was completely deobfuscated, which you can see in
[chal_edit.sv](https://github.com/kjcolley7/CTF-
WriteUps/blob/master/2022/maple/vm-1_and_2/chal_edit.sv). I also took some
notes to understand how the architecture works:
[notes.txt](https://github.com/kjcolley7/CTF-
WriteUps/blob/master/2022/maple/vm-1_and_2/notes.txt).

### Understanding the CPU architecture

Now that the code has been fully reverse engineered, let's dive into how this
CPU works:

* 12-bit instructions  
* Program counter register (`PC`)  
* A zero flag (`ZF`)  
* Separate program and data memory (Harvard architecture)  
* No general-purpose registers (stack-based architecture)  
* Call stack (holds 10 bytes; stack pointer is `cSP`)  
* Data stack (holds 10 bytes; stack pointer is `dSP`)  
* 8-bit code addresses (maximum of 256 12-bit instructions)  
* 8-bit data addresses (total of 256 bytes of RAM)

Instructions are 12 bits: the top 4 bits are the opcode, then the bottom 8
bits are an immediate value (like `push 0x42`). As the opcode is 4 bits, it
could define up to 16 different instructions. In this case, all 16 are defined
as follows (using my names):

| Opcode | Instruction | Operation                                        |  
|-------:|:------------|:-------------------------------------------------|  
|    `0` | `add`       | `a = dSP.pop(); b = dSP.pop(); dSP.push(a + b)`  |  
|    `1` | `sub`       | `a = dSP.pop(); b = dSP.pop(); dSP.push(a - b)`  |  
|    `2` | `xor`       | `a = dSP.pop(); b = dSP.pop(); dSP.push(a ^ b)`  |  
|    `3` | `and`       | `a = dSP.pop(); b = dSP.pop(); dSP.push(a & b)`  |  
|    `4` | `or`        | `a = dSP.pop(); b = dSP.pop(); dSP.push(a OR b)` |  
|    `5` | `shl`       | `a = dSP.pop(); b = dSP.pop(); dSP.push(a << b)` |  
|    `6` | `shr`       | `a = dSP.pop(); b = dSP.pop(); dSP.push(a >> b)` |  
|    `7` | `pop`       | `dSP--`                                          |  
|    `8` | `jmp imm8`  | `PC = imm8`                                      |  
|    `9` | `call imm8` | `cSP.push(PC + 1); PC = imm8`                    |  
|    `A` | `ret`       | `PC = cSP.pop()`                                 |  
|    `B` | `jzr imm8`  | `if (ZF) { PC = imm8; }`                         |  
|    `C` | `push imm8` | `*dSP++ = imm8`                                  |  
|    `D` | `ldm`       | `a = dSP.pop(); dSP.push(DATAMEM[a])`            |  
|    `E` | `stm`       | `a = dSP.pop(); b = dSP.pop(); DATAMEM[b] = a`   |  
|    `F` | `halt`      | `while(1) {}`                                    |

The first 7 instructions (opcodes `0`-`6`) are ALU instructions, which change
the value of `ZF` when the execute. If the result of the computation is zero,
`ZF` is set to 1 (true). Otherwise, `ZF` is cleared. The value of `ZF` is used
by the `jzr` (jump-if-zero) instruction to decide whether or not to jump to
the target address. That pretty much sums up how this architecture works!

### Writing a disassembler, emulator, and interactive debugger

So I'll start by admitting that when it comes to challenges with custom CPU
architectures, I love to get carried away and do more than is needed to solve
the challenge. In this case, I ended up writing a full disassembler, emulator,
and interactive debugger as part of this challenge. To be fair, it only took
~300 lines of Python code to achieve this:
[emu.py](https://github.com/kjcolley7/CTF-
WriteUps/blob/master/2022/maple/vm-1_and_2/emu.py). The debugger was really
useful for setting breakpoints, stepping through instructions, and watching
memory/stack values change. The emulator also has a couple of really neat
features, namely that it can write a trace log of instructions as they're
executed and count the number of instructions executed (which will come in
handy for this challenge later). It's also fun to use the `watch` debugger
command then `c` to continue execution of the program. This will show the full
contents of RAM every time a byte is changed. Here's an example of the program
running in the debugger and some of the commands:

```  
PC: 00  
Call stack:  
(0x0)

Data stack:  
(0x0)

Next instructions:  
00: push 0x80  
01: push 0x7f  
02: stm  
03: push 0x80  
04: ldm  
(dbg) si  
PC: 01  
Call stack:  
(0x0)

Data stack:  
(0x0, 0x80)

Next instructions:  
01: push 0x7f  
02: stm  
03: push 0x80  
04: ldm  
05: push 0x80  
(dbg)  
PC: 02  
Call stack:  
(0x0)

Data stack:  
(0x0, 0x80, 0x7f)

Next instructions:  
02: stm  
03: push 0x80  
04: ldm  
05: push 0x80  
06: ldm  
(dbg) mem  
Memory dump:  
00: a4 f4 61 9b 1f 28 81 9a  99 74 11 a9 67 cf 1a 47  ..a..(...t..g..G  
10: 4c c6 48 b2 e0 d8 d6 86  0f e5 68 96 03 14 b9 9d  L.H.......h.....  
20: a2 c9 83 fe a3 74 df 2f  51 cb 21 0b 53 c8 8c 69  .....t./Q.!.S..i  
30: 1e 38 c8 c7 1e f2 cd ec  2b 0a 5a 80 97 ea 94 f5  .8......+.Z.....  
40: 9e ae 70 2f 31 b1 b0 42  e6 a8 a3 5a 97 9b 31 9c  ..p/1..B...Z..1.  
50: c5 73 06 a1 86 3b b0 c9  a2 5c 99 e0 24 af e6 d6  .s...;...\..$...  
60: bb 99 46 c1 42 c3 9f 66  8c 4a 88 ac dd 05 73 29  ..F.B..f.J....s)  
70: 8a 18 b0 e3 d5 a5 a3 6b  76 95 b0 e5 10 2a d7 a1  .......kv....*..  
80: 33 55 51 53 a7 59 84 eb  e1 45 63 05 b6 bb 60 60  3UQS.Y...Ec...``  
90: 6f fe 7b 4f da dd 12 93  6c 10 dc 56 1a 6d 6f 0c  o.{O....l..V.mo.  
A0: 3f bb 49 00 34 1e 17 81  69 ce 04 70 a5 ad b9 76  ?.I.4...i..p...v  
B0: 23 e7 a8 f4 05 a5 7a 4b  a1 0f 7f a3 6a 5a 30 6e  #.....zK....jZ0n  
C0: 03 71 6e 3f 7e 75 79 72  24 50 57 6e 17 3a 11 1b  .qn?~uyr$PWn.:..  
D0: 73 2a 26 23 4a 57 4e 2c  20 0a 28 28 6c 21 20 47  s*&#JWN, .((l! G  
E0: 71 0c 22 30 1c 70 6d 3b  6c 73 57 2a ad 2a 85 bf  q."0.pm;lsW*.*..  
F0: 35 34 0d d9 19 67 7c 51  2a 7e 3e 2c bc 41 67 c0  54...g|Q*~>,.Ag.

(dbg) break 7D  
(dbg) c  
Hit breakpoint at 7D  
PC: 7D  
Call stack:  
(0x0, 0x2e)

Data stack:  
(0x0, 0x0)

Next instructions:  
7D: push 0x81  
7E: ldm  
7F: push 0x80  
80: ldm  
81: ldm  
(dbg) mem  
Memory dump:  
00: 00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................  
10: 10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................  
20: 20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f   !"#$%&'()*+,-./  
30: 30 31 32 33 34 35 36 37  38 39 3a 3b 3c 3d 3e 3f  0123456789:;<=>?  
40: 40 41 42 43 44 45 46 47  48 49 4a 4b 4c 4d 4e 4f  @ABCDEFGHIJKLMNO  
50: 50 51 52 53 54 55 56 57  58 59 5a 5b 5c 5d 5e 5f  PQRSTUVWXYZ[\]^_  
60: 60 61 62 63 64 65 66 67  68 69 6a 6b 6c 6d 6e 6f  `abcdefghijklmno  
70: 70 71 72 73 74 75 76 77  78 79 7a 7b 7c 7d 7e 7f  pqrstuvwxyz{|}~.  
80: 00 2a 51 53 a7 59 84 eb  e1 45 63 05 b6 bb 60 60  .*QS.Y...Ec...``  
90: 6f fe 7b 4f da dd 12 93  6c 10 dc 56 1a 6d 6f 0c  o.{O....l..V.mo.  
A0: 3f bb 49 00 34 1e 17 81  69 ce 04 70 a5 ad b9 76  ?.I.4...i..p...v  
B0: 23 e7 a8 f4 05 a5 7a 4b  a1 0f 7f a3 6a 5a 30 6e  #.....zK....jZ0n  
C0: 03 71 6e 3f 7e 75 79 72  24 50 57 6e 17 3a 11 1b  .qn?~uyr$PWn.:..  
D0: 73 2a 26 23 4a 57 4e 2c  20 0a 28 28 6c 21 20 47  s*&#JWN, .((l! G  
E0: 71 0c 22 30 1c 70 6d 3b  6c 73 57 2a ad 2a 85 bf  q."0.pm;lsW*.*..  
F0: 35 34 0d d9 19 67 7c 51  2a 7e 3e 2c bc 41 67 c0  54...g|Q*~>,.Ag.

(dbg) q  
```

Note that the above debug session is running using
[data2.txt](https://github.com/kjcolley7/CTF-
WriteUps/blob/master/2022/maple/vm-1_and_2/data2.txt) (the data file for the
vm-2 challenge, NOT vm-1). In fact, if I use the `mem` debugger command before
executing any instructions with the `data1.txt` file, you can see the problem
and why it had an unintended solution:

```  
(dbg) mem  
Memory dump:  
00: bb 4d 00 80 cb 15 9c ef  90 b9 1f 8b 41 30 07 e1  .M..........A0..  
10: 76 64 eb 44 eb 11 d0 4c  ea 1c f5 96 6a ea 6c 2f  vd.D...L....j.l/  
20: 04 27 e6 d4 56 80 52 38  59 59 c5 aa 82 94 df ab  .'..V.R8YY......  
30: da a3 41 47 c4 53 b3 d5  83 fc 56 a1 43 30 97 0d  ..AG.S....V.C0..  
40: 48 ea 49 d2 5b 77 0e 26  ab d9 f4 e6 61 49 e5 6e  H.I.[w.&....aI.n  
50: 33 d4 bb 42 ef e4 fd 4c  93 56 0c 81 2a 63 84 be  3..B...L.V..*c..  
60: d9 9f 5f a8 f7 ee b8 77  39 b9 db 4e 27 73 a8 89  .._....w9..N's..  
70: 75 89 c5 d8 c5 95 3a 1d  bc 24 83 50 07 1e 74 12  u.....:..$.P..t.  
80: fa 7f 04 1f 72 87 33 ac  ae 8a 85 1b 6d 61 70 6c  ....r.3.....mapl  
90: 65 7b 76 69 72 74 75 61  6c 5f 6d 61 63 68 69 6e  e{virtual_machin  
A0: 65 5f 6d 6f 72 65 5f 6c  69 6b 65 5f 76 65 72 69  e_more_like_veri  
B0: 6c 6f 67 5f 6d 61 63 68  69 6e 65 7d 01 32 1b 67  log_machine}.2.g  
C0: 6a 4e 63 24 65 44 2a 42  24 36 78 6f 0a 64 32 69  jNc$eD*B$6xo.d2i  
D0: 7d 57 5f 18 21 50 1a 15  3e 3f 66 46 2f 42 22 56  }W_.!P..>?fF/B"V  
E0: 2e 03 5e 51 61 26 1d 00  1d 6a 35 61 3a b2 4e bd  ..^Qa&...j5a:.N.  
F0: 7b 9d 70 65 75 60 d8 2b  0b 08 d9 11 9c b4 44 57  {.peu`.+......DW  
```

Yup, the flag was plaintext in the initial data memory! While the flag isn't
in plaintext in the updated `data2.txt` file, having this `data.txt` file with
the flag in it is actually useful when attempting to solve vm-2.

### The challenge program

A quick mention: from the SystemVerilog code I deobfuscated earlier, it can be
seen that the flag should be written into data memory at address 140 (0x8c).
The program will write the value 2 to address 135 (0x87) if the flag is
correct. Any other value there means the flag is wrong. This can help direct
our attention while reverse engineering the program.

Now that we've reverse engineered the CPU architecture and wrote some useful
tooling for this challenge, let's dive into how the challenge program works.
My annotated disassembly for it is here:
[disasm.txt](https://github.com/kjcolley7/CTF-
WriteUps/blob/master/2022/maple/vm-1_and_2/disasm.txt).

As this CPU has a stack-based architecture and no general-purpose registers,
absolute memory addresses are used as variables. To show an example of what
the code looks like, here's the first block of code that executes in the
program:

```  
00: push 0x80  
01: push 0x7f

// a = 0x7f  
02: stm

/*  
* Fills memory like:  
* addr = 0x80  
* do {  
*     *addr = addr;  
*     --addr;  
* } while(addr != 0)  
*  
* Therefore, each memory location <= 0x80 will have its value set to  
* its address.  
*/  
memfill_loop:  
03: push 0x80  
04: ldm  
05: push 0x80  
06: ldm

// mem[mem[0x80]] = mem[0x80]  
07: stm  
08: push 0x00  
09: push 0x80  
0A: ldm

// cmp mem[0x80], 0x00  
0B: sub  
0C: jzr 0x15 (after_loop)

0D: push 0x80  
0E: push 0x01  
0F: push 0x80  
10: ldm  
11: sub

// mem[0x80] -= 1  
12: stm  
13: pop // pops result of comparison  
14: jmp 0x03 (memfill_loop)

after_loop:  
//...more code follows...  
```

Lots of the code in this program uses addresses 0x80 and 0x81 as variables, so
I refer to them as `a` and `b` for convenience later. However, you may notice
that my annotations for the disassembly are incomplete. That's becaused as I
was going through the disassembly code and running the challenge in my
emulator/debugger, I came to a realization that I didn't need to understand
anything more about the code to solve the challenge!

### Exploiting a side-channel vulnerability in the code to brute-force the
flag

The program running on the CPU in this challenge contains a side-channel
vulnerability. While the output from the program is supposed to just be a
binary value (is the flag correct?), another useful output can be extracted.
Namely, the total number of instructions executed. The program checks the
characters in the flag one at a time (using some XORs against a random string
and a permutation array). As soon as one of the characters in the flag is
determined to be incorrect, the program will halt. That means that if the
first character in the flag is correct, more instructions will be executed
than if the first character is wrong.

Using this side-channel leakage, a bruteforce program can be written to build
the flag. The idea is pretty simple: start by running the program without any
changes to get a baseline for the instruction count. Then, starting at the
flag address in the data memory (0x8c), try every possible printable ASCII
character (0x20-0x7e), one at a time. As soon as an execution of the program
hits a higher instruction count than the baseline, that means the character in
the current position is correct! Then, the program advances the memory address
being bruteforced, uses the new instruction count as the new baseline, and
continues in a loop as long as there is an improvement in the number of
instructions executed. The python code that implements my bruteforcer is as
follows:

```python  
cpu.run()  
best_inscount = cpu.inscount

# 0x8c is the start of the flag  
brute_pos = 0x8c  
flag = ""  
improved = True

while improved:  
	improved = False  
	for c in range(0x20, 0x7f):  
		data[brute_pos] = c  
		cpu.reset()  
		cpu.copyin(data)  
		cpu.run()  
  
		print("Trying '%s': %d" % (flag + chr(c), cpu.inscount))  
  
		if cpu.inscount > best_inscount:  
			flag += chr(c)  
			brute_pos += 1  
			best_inscount = cpu.inscount  
			improved = True  
			break

cpu.showmem()  
```

Here's an excerpt of the bruteforcer running to extract the flag:

```  
Trying 'maple{the_1': 8780  
Trying 'maple{the_2': 8780  
Trying 'maple{the_3': 8780  
Trying 'maple{the_4': 8845  
Trying 'maple{the_4 ': 8845  
...  
Trying 'maple{the_4k': 8845  
Trying 'maple{the_4l': 8910  
Trying 'maple{the_4l ': 8910  
Trying 'maple{the_4l!': 8910  
...  
Trying 'maple{the_4l`': 8910  
Trying 'maple{the_4la': 8975  
Trying 'maple{the_4la ': 8975  
Trying 'maple{the_4la!': 8975  
...  
Trying 'maple{the_4laf': 8975  
Trying 'maple{the_4lag': 9040  
...  
Trying 'maple{the_4lag^': 9040  
Trying 'maple{the_4lag_': 9105  
...  
Trying 'maple{the_4lag_r': 9105  
Trying 'maple{the_4lag_s': 9170  
...  
...  
...  
Trying 'maple{the_4lag_shOUld_Not_be_put_1N_initial_RAM|': 11185  
Trying 'maple{the_4lag_shOUld_Not_be_put_1N_initial_RAM}': 11190  
```

And there's the flag!

During competition, I was the second solver for this challenge.

After this challenge, I went on to solve [confounded pondering
unit](https://github.com/kjcolley7/CTF-
WriteUps/blob/master/2022/maple/cpu/README.md), which is another similar
custom CPU challenge.

Original writeup (https://github.com/kjcolley7/CTF-
WriteUps/blob/master/2022/maple/vm-1_and_2/README.md).