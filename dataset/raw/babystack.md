https://www.da.vidbuchanan.co.uk/blog/0CTF-2018-babystack-ret2dlresolve.html

Feedback/questions: https://twitter.com/David3141593/status/981593710642237440

Original writeup (https://www.da.vidbuchanan.co.uk/blog/0CTF-2018-babystack-
ret2dlresolve.html).# Babystack  
421pts

## TLDR  
* stack over flow  
	* overwrite rbp  
* one gadget RCE

## Challenge  
### Description  
result of file command  
* Arch    : x86-64  
* Library : Dynamically linked  
* Symbol  : Stripped

result of checksec  
* RELRO  : No RELRO  
* Canary : Enable  
* NX     : Enable  
* PIE    : Disable

libc version: 2.29

### Exploit  
This binary has a stack overflow vulnerabirity which can overwrite old rbp
value, not return address.  

In the function at 0x401182, read() is called 2 times.  
At first, read(0, \[rbp-0x40], 0x10) is called and strlen(\[rbp-0x40]) is
also.  
I name the return value of first read() "acutual\_len", that of strlen()
"virtual\_len".  
Second, read(0, \[rbp-0x40+actural\_len], 0x38-virtual\_len).  
So if the first input is "\x00"\*0x10, second read() is read(0, \[rbp-0x30],
0x38) and we can overwrite old_rbp value.

Here is an part of main().  
```  
...  
...  
4013e9:       b8 00 00 00 00          mov    eax,0x0  
4013ee:       e8 2a ff ff ff          call   40131d <exit@plt+0x28d>  
4013f3:       b8 00 00 00 00          mov    eax,0x0  
4013f8:       e8 85 fd ff ff          call   401182 <exit@plt+0xf2>  
4013fd:       b8 00 00 00 00          mov    eax,0x0  
401402:       e8 7b fd ff ff          call   401182 <exit@plt+0xf2>  
401407:       48 8d 45 b0             lea    rax,[rbp-0x50]  
40140b:       ba 18 00 00 00          mov    edx,0x18  
401410:       48 89 c6                mov    rsi,rax  
401413:       bf 00 00 00 00          mov    edi,0x0  
401418:       e8 43 fc ff ff          call   401060 <read@plt>  
40141d:       48 8d 45 b0             lea    rax,[rbp-0x50]  
401421:       48 89 c7                mov    rdi,rax  
401424:       e8 07 fc ff ff          call   401030 <puts@plt>  
401429:       48 c7 c7 01 00 00 00    mov    rdi,0x1  
401430:       48 c7 c0 03 00 00 00    mov    rax,0x3  
401437:       0f 05                   syscall  
401439:       b8 00 00 00 00          mov    eax,0x0  
40143e:       48 8b 4d f8             mov    rcx,QWORD PTR [rbp-0x8]  
401442:       64 48 33 0c 25 28 00    xor    rcx,QWORD PTR fs:0x28  
401449:       00 00  
40144b:       74 05                   je     401452 <exit@plt+0x3c2>  
40144d:       e8 fe fb ff ff          call   401050 <__stack_chk_fail@plt>  
401452:       c9                      leave  
401453:       c3                      ret  
```  
After calling 0x401182 2 times, read(0, [rbp-0x50], 0x18) is executed.  
As explained above, we can overwrite old rbp value at 0x401182.  
So we can AAW.  

For AAW, I leaked the address of the stack and canary value which remains on
the stack in first 0x401182.  
And, I overwrote old rbp value in second 0x401182,return from 0x401182 and
overwrote again the return address of read().  

We can control rip value, but the length of overwriting is 0x18.  
It is not enough for ROP chain, so I made 3 chain gadget(\[pop rbp; ret],
fake_rbp_value, \[leave; ret]).  
I set fake_rbp_value to the buffer used in read() at 0x401182.  
Now we can make ROP chain more then 0x18 bytes :)

My exploit code is
[solve.py](https://github.com/kam1tsur3/2021_CTF/blob/master/bamboofox/pwn/babystack/solve.py).

## Reference  
twitter: @kam1tsur3  

Original writeup
(https://github.com/kam1tsur3/2021_CTF/blob/master/bamboofox/pwn/babystack/README.md).https://teamrocketist.github.io/2017/12/13/Pwn-SECCON-Baby-Stack/

Original writeup (https://teamrocketist.github.io/2017/12/13/Pwn-SECCON-Baby-
Stack/).In `StarCTF 2018 - babystack` challenge, there is a `stack overflow`
vulnerability by which we can leak `atol@GOT` address to find `libc` base
address, and jump to `one gadget` in order to execute `execve("/bin/sh")`. The
interesting part is replacing the `stack canary` with the correct value in
order to replace the `return address` without crashing the program.

Basically, when using `pthread`, the `Thread Local Storage (TLS)` will be
located somewhere near the thread stack, so it can be overwritten in case of a
`stack overflow` vulnerability. In this challenge, we can replace the
`stack_guard` attribute in `TLS` (http://www.openwall.com/lists/oss-
security/2018/02/27/5) with an arbitrary value in order to bypass `canary`
protection. This is an interesting `ROP` challenge to learn bypassing
protections like `NX`, `Canary`, `Full RELRO`, and `ASLR` in `x86_64`
binaries.

Original writeup (https://github.com/sajjadium/ctf-
writeups/tree/master/StarCTF/2018/babystack).