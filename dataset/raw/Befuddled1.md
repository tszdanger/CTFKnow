# Misc: befuddled1  
solver: [Pr0f3550rZak](https://github.com/Pr0f3550rZak)  
writeup-writer: [L3d](https://github.com/imL3d)  
___  
**Author:** doubledelete  
**Description:**  
> it seems yall enjoyed the befunge challenges, here's more  
> i've been doing a little too much code golf recently...  

**files (copy):**
[befunge.py](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/files/befunge.py),
[challenge.py](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/files/challenge.py)  

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
  
In this challenge we are asked to input the Befunge code to be compile, with a
limit for 16 characters.  
After a quick glace of the syntax, we find how to create a loop, and pop the
stack. This is the result:  
`>,<`  

`>` - means increment program counter.  
`,` - means pop the stack.  
`<` - decrement program counter.  
  
And we get the flag: `wctf{my_s0lv3_l00k5_l1k3_4_cut3_f4c3_>,<}`.  
  
To the [next
one](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/tree/main/befuddled2)
➡️  

Original writeup
(https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/tree/main/befuddled1).