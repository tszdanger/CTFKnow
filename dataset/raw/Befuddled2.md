# Misc: befuddled2  
solver: [Pr0f3550rZak](https://github.com/Pr0f3550rZak)  
writeup-writer: [L3d](https://github.com/imL3d)  
___  
**Author:** doubledelete  
**Description:**  
> ok, that one mighta been a little too easy >.<

**files (copy):**
[befunge.py](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled2/files/befunge.py),
[challenge.py](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled2/files/challenge.py)  

In this challenge we receive a befunge compiler, with the Flag in the top of
the stack.  
We need to write befunge code under some restrictions, and get the flag.  

## Solution

Before starting to tackle this challenge, we need to know firstly what is
Befunge.  
Befunge is a two-dimensional esoteric programming language invented in 1993 by
Chris Pressey with the goal of being as difficult to compile as possible. The
code is laid out on a two-dimensional grid of instructions, and execution can
proceed in any direction of that grid - we can see this being implemented in
the source file.[[1](https://esolangs.org/wiki/Befunge)]  

This channel has the same source, with minor restriction changes:  
1. We still have 16 character limit.    
2. We can't use characters that manipulate the program counter directly.    
  
This means our old solution is now invalid. Instead we can craft the following
program:  
` 0_0..1_`  
This program iterates and prints the ascii values of the flag. Lets break it
down:  
`0` - pushes 0 to the stack.  
`1` - pushes 1 to the stack.  
`_` - pops a value and changes the way the program will continue to move: set
direction to right if value=0, set to left otherwise.  
`.` - Pop top of stack and output as integer.  

The program flow will move back and fourth, while printing 2 character of the
flag each time (and occasionally 0). I will leave the actuall execution flow
of the program as an exercise to the reader (hehe!), since it's fairly simple,
and it's late already here.  
Anyhow, we get the flag?!  
`wctf{4_0n3_l1n3_turn_0f_3v3nt5}`  
  
To the [next
one](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/tree/main/befuddled3)
➡️

Original writeup
(https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/tree/main/befuddled2).