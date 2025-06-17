# Return Of The Rops

> **Points** 480  
>  
>Is ROP dead? God no. But it returns from a long awaited time, this time in a
weird fashion. Three instructions ... can you pwn it?  
>  
> `EU instance: 161.97.176.150 2222`  
>  
> `US instance: 185.172.165.118 2222`  
>  
>author: Tango

# Challenge Overview

Here we are given 2 binary file. The first one was a `PoW` Proof-Of-Concept
file that required us to pass some four letter lowercase  
whose `md5` hash was given.  
The second binary file was the challenge file that was a 64-bit executable
file dynamically linked and not stripped. `NX` was the  
only protection enabled in the binary.

# Exploitation Overview

Therefore to exploit this challenge you had to pass the `PoW` level first.
Using python `itertools`, `hashlib` and `string` module I used to  
permutate all lowercase letters in groups of 4 hashed them into md5 and looped
though to check which string's hash matches the given hash.

The other challenge is we had to rop and get a shell. There was a `gets`
function that was used to get input therefore this was definately a  
`bof` bug. I used this to leak the address of `libc` and then popped a shell
calling `system` with `bin/sh` as the argument.

The final exploit @ [exploit.py](exploit.py)  
# Flag

The flag was after popping a shell

flag{w3_d0n't_n33d_n0_rdx_g4dg3t,ret2csu_15_d3_w4y_7821243}

Original writeup (https://github.com/mutur4/CTF-
WRITEUPS-2021/blob/main/0x41414141%20CTF/Return%20Of%20The%20Rops/solution.md).