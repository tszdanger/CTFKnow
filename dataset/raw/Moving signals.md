## Moving Signals  
>  
> **category** : pwn  
>  
> **Points**: 442  
>  
> We don't like giving binaries that contain loads of information, so we
> decided that a small program should do for this challenge. Even written in
> some custom assembly. I wonder how this could be exploited.  
>  
> `EU instance: 161.97.176.150 2525`  
>  
> `US instance: 185.172.165.118 2525`  
>  
> author: Tango

## Challenge Overview

The given file is a 64-bit executable that is statically linked and that is
not stripped.

## Exploit Overview

Following the challenge's description `Moving Signals` we conclude that the
challenge can be exploited via `srop` technique.This technique  
can work under the following conditions. Read more
[here](https://amriunix.com/post/sigreturn-oriented-programming-srop/)  
 > Buffer overflow to overwrite the stack return address  
  
 >`syscall` and `rax` gadgets that can be used to call sigreturn syscall.  
  
 > There should be enough space on the stack to be used to sigcontext frame.  
  
Does this Binary meet all these conditions?  
 > There is a buffer overflow at offset `0x8`  
 >  
 > There is a `syscall` and `pop_rax` gadget in the binary file.  
 >  
 > There is enough space that we can write on the stack because `syscall_read`
max input check is `0x1f4`  
  
Therefore the exploit will be as follows  
  
 `exploit=b'A'*8 + pop_rax + 0xf + syscall + frame`  
  
We can now control the value of out registers including `rip` therefore we
determine the next instruction to execute.  
I decided to call `execve` because there was `/bin/sh` provided to us in the
binary. :/  
  
Check the final exploit @ [exploit.py](exploit.py)  
  
## Flag  
The flag after spawning a shell was:  
`flag{s1gROPp1ty_r0p_321321}` :smile:

  

Original writeup (https://github.com/mutur4/CTF-
WRITEUPS-2021/blob/main/0x41414141%20CTF/Moving%20Signals/solution.md).