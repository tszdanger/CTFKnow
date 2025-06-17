# DarkCTF 2020

## rev/c_maths

> 44 solves / 465 points  
>  
> Author: p3t4j0n  
>  
> Description: Clearly u know some C programming and a bit of maths right...?
> Note: Enclose the flag within darkCTF{} There are 3 parts to the flag.  
>  
> `nc cmaths.darkarmy.xyz 7001`  
>  
> [c_maths](c_maths)

Tags: _rev_ _x86-64_ _strcmp_

## Summary

Classic _compare_ reverse.

This binary will prompt for three inputs.  The first is the first part of the
flag (string), the second is a number that if correct will emit the second
part of the flag, the third and final part of the flag is just like the second
--put in the right digits and get the final part of the flag.

> Credit to teammate
> [dobs](https://github.com/dobsonj/ctf/tree/master/writeups) for handing me
> the analysis--I just had to automate.

> Oh, and _no_ maths required.

## Analysis

### Decompile with Ghidra

> Only the interesting bits.

```c  
 tVar2 = time((time_t *)0x0);  
 srand((uint)tVar2);  
```

This problem changes every second.  But since we all use the same clocks (UTC
seconds), this is not an issue at all.

```c  
 local_95[local_20] = '\0';  
 __isoc99_scanf("%[^\n]%*c",local_9c);  
 __n = strlen(local_95);  
 iVar1 = strncmp(local_95,local_9c,__n);  
 if (iVar1 != 0) {  
   exit(1);  
 }  
```

The first compare.  We just need to know what `local_95` is.  If we highlight
the `local_95[local_20] = '\0';` line, the corresponding disassembly
highlights as:

```  
001013bf c6 84 05        MOV        byte ptr [RBP + RAX*0x1 + -0x8d],0x0  
        73 ff ff   
        ff 00  
```

Ignore that leading `001` from Ghidra, the instruction we're interested in
setting a break point is at `0x13bf` and we want to read `local_95`.  Remember
that for later.

```c  
 local_44 = (int)dVar4;  
 __isoc99_scanf(&DAT_00102015,&local_cc);  
 if (local_44 == local_cc) {  
   system("cat small_chunk.txt");  
```

The second compare is an integer.  Get this right and you get that sweet sweet
_small chunk_.

The first line disassembly:

```  
00101509 f2 0f 2c c0     CVTTSD2SI  EAX,XMM0  
0010150d 89 45 c4        MOV        dword ptr [RBP + local_44],EAX  
```

`local_44` is set by instruction `0x150d`; we'll set a breakpoint there to get
the value directly from `EAX`.

```c  
   local_50 = (int)uVar3;  
   __isoc99_scanf(&DAT_00102015,&local_dc);  
   time(&local_80);  
   local_58 = (double)(local_80 - local_78);  
   if ((local_50 != local_dc) || (5.00000000 <= local_58)) {  
     puts("Nothing for u here");  
   }  
   else {  
     system("cat big_chunk.txt");  
   }  
```

Last compare, also integer, for the final chunk.  There's a time check in here
as well (5 second from start to end).  Clearly the game master didn't want you
manually using GDB to slog through this.  No prob, we'll automate.

Disassembly:

```  
0010161c 89 45 b8        MOV        dword ptr [RBP + local_50],EAX  
```

Same as before, get the integer from `EAX` after setting a breakpoint at
`0x161c`.

## Solve

```  
#!/usr/bin/env python3

from pwn import *

binary = ELF('./c_maths')

r = remote('cmaths.darkarmy.xyz', 7001)

d = process(['gdb',binary.path])  
d.sendlineafter('gdb) ','b *0x555555554000+0x13bf')  
d.sendlineafter('gdb) ','b *0x555555554000+0x150d')  
d.sendlineafter('gdb) ','b *0x555555554000+0x161c')  
d.sendlineafter('gdb) ','r')  
d.sendlineafter('gdb) ','x/s $rbp-0x95+8')  
a1 = d.recvline().strip().split(b'"')[1]  
d.sendlineafter('gdb) ','c')  
d.sendlineafter('Continuing.\n',a1)  
d.sendlineafter('gdb) ','p/d $rax')  
a2 = d.recvline().strip().split()[-1]  
d.sendlineafter('gdb) ','c')  
d.sendlineafter('Continuing.\n',a2)  
d.sendlineafter('gdb) ','p/d $rax')  
a3 = d.recvline().strip().split()[-1]  
d.sendlineafter('gdb) ','c')  
d.sendlineafter('Continuing.\n',a3)  
d.sendlineafter('gdb) ','q')  
d.close()

log.info(b'sending: ' + a1)  
r.sendline(a1)  
for i in range(9): log.info(r.recvline())  
log.info(b'sending: ' + a2)  
r.sendline(a2)  
for i in range(3): log.info(r.recvline())  
log.info(b'sending: ' + a3)  
r.sendline(a3)  
log.info(r.recvline())  
```

Instead of reversing how `c_maths` works, just use GDB to get the values from
the stack and registers.

From the top down, start the remote and local processes at the same time.

> There's a small probability you'll be off by a second.  Just rerun.  After
> 20 tests I had one failure.

Next, set all the break points.  `0x555555554000` is the base process address
for GDB x86_64 binaries (GDB is disabling PIE/ASLR), so just add that to the
breakpoints.

At the first breakpoint get the string used in the string compare.  `x/s
$rbp-0x95+8` is that string.  The `0x95` correlates to `local_95` from Ghidra
--the distance from the return address.  The `+8` translates the base to `rbp`
(since it's 8 bytes above the return address).

At the second and third breakpoints return the value of `$rax` with `p/d`
since we want a base-10 integer.

With all the answers in hand, just answer the questions and get the flag--_no
maths required!_

Output:

```bash  
# ./sol.py  
[*] '/pwd/datajerk/darkctf2020/c_maths/c_maths'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[+] Opening connection to cmaths.darkarmy.xyz on port 7001: Done  
[+] Starting local process '/usr/bin/gdb': pid 8030  
[*] Stopped process '/usr/bin/gdb' (pid 8030)  
[*] b'sending: p1e8s3'  
[*] b'299\n'  
[*] b'3329\n'  
[*] b'4232\n'  
[*] b'2098\n'  
[*] b'8098\n'  
[*] b'8561\n'  
[*] b'8815\n'  
[*] b'154\n'  
[*] b'7464\n'  
[*] b'sending: 3331'  
[*] b'_just_\n'  
[*] b'\n'  
[*] b'7418\n'  
[*] b'sending: 2295273'  
[*] b'give_me_the_flag\n'  
```

Flag: `darkCTF{p1e8s3_just_give_me_the_flag}`

Original writeup (https://github.com/datajerk/ctf-write-
ups/tree/master/darkctf2020/c_maths).