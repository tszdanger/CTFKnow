CRAPSemu [Reversing, 493 points, 8 solves]  
========

### Description

>I made this CRAPS emulator, can you log in to my vault ?  
>  
>**Files** :  
>  
>* [crapsemu](crapsemu)  
>  
>**Creator** : voydstack (Discord : voydstack#6035)

### Overview

This challenge is an emulator for a custom architecture written in C, with an
embedded crackme program inside that you need to reverse engineer. When run,
the program asks you to enter a password. It runs some validation on it, and
then it either tells you that the password was correct or wrong. The password
is the flag.

### Initial Attempts

My first ideas were to see if I could quickly solve this as a black-box
problem without reverse engineering the emulator and trying to understand the
architecture. I love challenges involving custom architectures, but if I could
cheese this and quickly solve it I could move onto other challenges to get
points faster.

#### 1. Timing side-channel attack

I thought that maybe the program was checking the password one character at a
time, and that I could figure out what the correct characters were by seeing
which ones made the program run longer (by moving on to compare the next
character of the password).

##### Aside:

> My CTF setup is my Mac, and I run Ubuntu 18.04 in VMware Fusion 12. Normally
> for this type of timing attack, I'd use the `perf` utility from the `linux-
> tools` package to get the number of instructions executed by a program,
> which is more accurate for quick executions like this than actually
> comparing time executing. However, VMware Fusion 12 specifically, as of
> macOS Big Sur, switched from using their own kernel extension to now use
> Apple's official hypervisor framework (from usermode). One side effect of
> this change is that it no longer supports virtualizing performance counters
> (vPMC), which are required for `perf` to access instruction counts among
> other things. Because of this, I instead used Intel's Pin along with the
> included inscount0 pintool for tracking instruction counts in a dynamically
> instrumented target. A bit more involved (and technically less performant,
> though that's irrelevant here), but it works.

After trying to bruteforce the password both in first character and also
length, it was unsuccesful. The executions all had approximately the same
number of instructions executed, so this approach wouldn't work.

#### 2. Scanning memory for the flag

The other idea (mentioned by a teammate) was to scan the process's memory to
see if it builds the correct password in memory before comparing it. The
debugger I use in CTF competitions is gdb-peda (yes, I know it's kinda old and
I should probably switch to GEF). It has a command for finding all printable
strings in a process's memory space, `strings` (not to be confused with the
command line utility `strings`). Using this didn't find a flag string, even
when pointing it to specifically the `mmap`-ed memory region that stored the
emulated CPU's memory.

### Reverse Engineering

I then set to work on solving the challenge in the intended way by reverse
engineering the emulator to figure out the architecture. I spent a while in
IDA's Hex-Rays decompiler, and eventually fully decompiled the entire binary.
I've included in this repo the entirety of IDA's decompiled output, after MUCH
effort massaging it (inside IDA) to be correct. Honestly, the reason I even
decided to compete in this CTF was to test out IDA's cloud decompiler in the
free version to decide if I wanted to buy an IDA Home license, but I had to
fall back to my old (6.6) copy of IDA because the free version doesn't have
the "Set Switch Idiom" command to tell IDA how to recognize a `switch`
statement that it failed to detect. Anyways, you can go through the
[decompiled code](crapsemu_decompiled.c) if you want, but the important
details are below.

### Registers

This architecture has 32 registers, each 32-bits in size. There are also 4
flags separate from these registers.

Register    | Description  
------------|---------------  
ZERO (R0)   | ALWAYS holds the value 0. Writes are ignored.  
R1-R4       | General purpose, except these are used by the `syscall` instruction to determine which syscall to invoke and the parameters.  
R5-R20      | General purpose  
TMP (R21)   | Used internally by the CPU during many operations, so shouldn't be used by programs.  
R22-R29     | General purpose  
PC (R30)    | Program counter (address of currently executing instruction, updated after execution finishes)  
FETCH (R31) | Used internally by the CPU to store the 32-bit instruction fetched from memory. It is decoded from this register.  
ZF          | Zero flag, set when the result of a computation is zero.  
SF          | Sign flag, set when the result of a computation is negative (in 2's complement representation).  
CF          | Carry flag, set when a computation would have a bit carried out. (Not actually sure about this, the implementation for setting this flag is unusual.)  
VF          | Overflow flag, set when a computation overflows. (Not sure either, might actually instead be carry. Again, the implementation of this was weird.)

### Memory

The CPU's memory is stored as an array of 32-bit values, meaning memory is not
byte-addressible (only DWORD-addressible). There are a total of 0x4000 DWORDs
(64KiB of RAM). When the CPU is initialized, program memory (stored in the
`crapsemu` binary) is loaded starting at address 0.

### Instructions

There are 4 classes of instructions based on their encoding: XYZ, syscall,
jcc, and movt. Only instructions denoted with an `s` suffix will update the
relevant CPU flags (`ZF`, `SF`, `CF`, `VF`).

In the notation below:

* `Rz` can be any register from `R0-R31`, and is typically the destination register.  
* `Rx` can be any register from `R0-R31`, and is typically the first operand in an operation like addition or subtraction.  
* `Vy` can be any register from `R0-R31` OR a 13-bit immediate value (sign-extended to 32-bits), and is typically the second operand in an operation like addition or subtraction.

Instruction Name (chosen by me) | Class   | Opcode (if XYZ class) | Description  
--------------------------------|---------|-----------------------|----------------  
`add[s]`                        | XYZ     | 0x00/0x10(s)          | Addition: `Rz = Rx + Vy`  
`sub[s]`                        | XYZ     | 0x04/0x14(s)          | Subtraction: `Rz = Rx - Vy`  
`and[s]`                        | XYZ     | 0x01/0x11(s)          | Bitwise AND: `Rz = Rx & Vy`  
`orr[s]`                        | XYZ     | 0x02/0x12(s)          | Bitwise OR: `Rz = Rx \| Vy`  
`xor[s]`                        | XYZ     | 0x03/0x13(s)          | Bitwise XOR: `Rz = Rx ^ Vy`  
`shr`                           | XYZ     | 0x0D                  | Bitwise right shift: `Rz = Rx >> Vy`  
`shl`                           | XYZ     | 0x0E                  | Bitwise left shift: `Rz = Rx << Vy`  
`syscall`                       | syscall | N/A                   | Perform a system call (`read`/`write`/`exit`). More details later.  
`j(cc)`                         | jcc     | N/A                   | Conditional jump/branch. More details later.  
`movt`                          | movt    | N/A                   | Move Top. Sets the top 24-bits of a register to an immediate, while clearing the low 8 bits.  
`x13`                           | XYZ     | 0x20                  | (Used internally) Sign extend from 13-bit value. `Rz = sign_extend_13(Rx)`  
`x25`                           | XYZ     | 0x21                  | (Used internally) Sign extend from 25-bit value. `Rz = sign_extend_25(Rx)`  
`sl8`                           | XYZ     | 0x23                  | (Used internally) Shift left by 8 bits. `Rz = Rx << 8`  
`nop`                           | XYZ     | 0x28                  | No operation is performed.  
`ldr`                           | XYZ(\*) | 0x00                  | Load DWORD: `Rz = MEM[Rx + Vy]`  
`str`                           | XYZ(\*) | 0x04                  | Store DWORD: `MEM[Rx + Vy] = Rz`

Some of these instructions require more details. The `ldr` and `str`
instructions use the same encoding as the `add` and `sub` instructions,
respectively, except they have an additional bit set.

As for the `syscall` instruction, here is pseudocode for how it works:

```c  
switch(r1) {  
   case 0: read(fd=r2, ptr=&memory[r3], size=r4); break;  
   case 1: write(fd=r2, ptr=&memory[r3], size=r4); break;  
   case 2: exit(status=r2);  
   default: exit(status=1);  
}  
```

As for `j(cc)`, here are the supported condition codes and their meaning:

Name  | Value | Operation         | Description  
------|------:|-------------------|-------------  
`nv`  | `0x0` | `false`           | NEVER  
`eq`  | `0x1` | `ZF`              | EQUAL_or_ZERO  
`le`  | `0x2` | `ZF \|\| SF != CF`  | SIGNED_LESS_OR_EQUAL  
`lt`  | `0x3` | `SF != CF`        | LESS  
`le2` | `0x4` | `ZF \|\| SF != CF`  | SIGNED_LESS_OR_EQUAL_again  
`vs`  | `0x5` | `VF`              | OVERFLOW  
`ng`  | `0x6` | `SF`              | NEGATIVE  
`cs`  | `0x7` | `CF`              | CARRY_SET  
`al`  | `0x8` | `true`            | ALWAYS  
`ne`  | `0x9` | `!ZF`             | NOT_EQUAL_or_ZERO  
`gt`  | `0xA` | `!ZF && SF == CF` | SIGNED_GREATER  
`ge`  | `0xB` | `SF == CF`        | GREATER_OR_EQUAL  
`gt2` | `0xC` | `!ZF && SF == CF` | SIGNED_GREATER_again  
`vc`  | `0xD` | `!VF`             | NOT_OVERFLOW  
`ps`  | `0xE` | `!SF`             | NOT_NEGATIVE  
`cc`  | `0xF` | `!CF`             | CARRY_CLEAR

Finally, there's `movt`. In practice, this instruction is normally followed by
an `orr` instruction to set the low 8 bits of the same register using an
immediate. This pattern is similar to ARM's `movt`/`movw` combination for
setting a 32-bit immediate value in a register 16 bits at a time, except in
this case it's 24 bits followed by the final 8.

I won't go into the instruction encoding here. If you're curious about that,
refer to either the [decompiled code](crapsemu_decompiled.c) or [my CRAPS
disassembler](dis_craps.py). Just know that each instruction is exactly 32
bits large.

### The crackme program

After fully reversing the emulator and understanding the architecture, I wrote
a quick disassembler. The program is pretty small, only 115 instructions in
total. I highly recommend looking at [my annotated disassembly](craps.asm). To
summarize what it does:

1. Ask for the user to enter a password.  
2. Read 24 bytes to address 0x100 (pointed to by `R3`).  
3. Write an encrypted form of the correct password to memory starting at 0x1ff and working backwards. After this, `R29` points to the beginning of the encrypted correct password.  
4. Iterate through the DWORDs in the correct password, so 6 times:  
5. Load a DWORD from the encrypted correct password into `R4`.  
6. XOR that against the constant `0x1337f00d`.  
7. Compare that against the DWORD from the user's entered password. If it doesn't match, set a fail flag to indicate the password doesn't match and keep going.  
8. At the end of the 6 iterations, check the fail flag. If it's set, print wrong password. Otherwise, print correct password.

To solve, I took the memory of the encrypted correct password and XORed each
4-byte block with `0x1337f00d`. This resulted in the flag
`SPARC[::-1]_15_d4_w43e!!`, which cleverly shows that the architecture name
"CRAPS" is just SPARC backwards.

### Review of previous techniques

Now that the program has been fully reverse engineered, it is clear that the
author took some measures to specifically prevent my two earlier techniques
and actually require some reverse engineering. Specifically, the timing attack
was thwarted because of the use of the fail flag for detecting mismatch rather
than breaking from the loop early. Also, searching memory for the flag failed
because the flag was only stored in an encrypted form in memory. Each 4-byte
chunk is decrypted just as it's loaded into a register, so the entire flag is
never in plaintext in memory at a time. If there were a specific `cmp`
instruction, you could've set a breakpoint on it to see each chunk of the
password fly by, but the `subs` instruction is used instead. You could've
still used a breakpoint on this instruction, but to find where it's executed
and where to put a breakpoint still requires a lot of reversing.

Original writeup (https://github.com/kjcolley7/CTF-
WriteUps/blob/master/2021/thcon/CRAPSemu/README.md).