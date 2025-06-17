CRAPSaaS [Pwn, 498 points, 5 solves]  
========

### Description

>I slightly modified my CRAPS emulator to make it accessible to the world!
Please take care of it.  
>  
>`nc remote1.thcon.party 10905`  
>`nc remote2.thcon.party 10905`  
>**Files** :  
>  
>* [crapsemu](crapsemu)  
>* [libc.so.6](libc.so.6)  
>  
>**Creator** : voydstack (Discord : voydstack#6035)

### Overview

This challenge allows users to upload blobs of code written for the CRAPS
architecture and have them run on a remote server. The program's stdin/stdout
are connected over the socket. The goal is to find and exploit a vulnerability
in the emulator to get code execution outside the emulator and read a flag
file. This write-up (and the challenge itself) is a sequel to the [write-up
for CRAPSemu](../CRAPSemu/README.md), so be sure to read that one first! I
will not be discussing the architecture details in this write-up.

### Initial attempt

From reversing the previous `crapsemu` binary for the CRAPSemu reversing
challenge, I already knew about vulnerabilies in the implementation of the
`read` and `write` syscalls reachable from the `syscall` instruction. I
started work on this challenge by writing a quick and dirty "assembler" and by
trying to leak memory using the `read` syscall. However, I quickly discovered
a big problem with this technique when I noticed that the `crapsemu` process
running locally was crashing. Based on my understanding from the previous
challenge, the `write` syscall shouldn't crash even when hitting unmapped
memory (because it directly called the underlying `write` syscall on Linux,
which simply returns an error code rather than crashing upon hitting an
unmapped page). So clearly, the binary for this challenge was different in
more ways than just accepting a program from the user rather than using a
hardcoded one.

### Reversing, again...

This time, I was significantly lazier with the reversing process since I
already fully reverse engineered this exact program (just about) for the
CRAPSemu challenge. I don't have an easy way to use any form of binary diffing
tool, which may have saved me some time. So I started by locating the function
responsible for handling the `syscall` instruction (which I named
`exec_syscall`). In the previous challenge, it was doing something like the
following:

```c  
//write  
if ((uint32_t)(r3 + r4) <= 0x1fff) {  
	r1 = write(r2, &memory[r3], r4);  
}

//read  
if ((uint32_t)(r3 + r4) <= 0x1fff) {  
	r1 = read(r2, &memory[r3], r4);  
}  
```

The overflow check is insufficient, as is evident when `r3 = 4` and `r4 = -4`.
The sum will be 0, which will pass the check. However, when this is passed to
the size parameter of the `write` syscall, it will be extremely large. In
Linux, this will result in writing as much memory as is contiguously readable
to the socket, which would be extremely useful as a primitive for leaking
memory. Similarly, the `read` syscall had the exact same format with the same
insufficient overflow check, meaning I could call `read` with a nearly
arbitrary address (relative to the `mmap`-ed memory region, +/- a few
gigabytes) and a ridiculously large size. In that case, the super big size
doesn't even matter, because I could just choose to only send like 8 bytes.

Sadly, the implementation for both `read` and `write` syscalls changed in this
challenge to instead look like the following:

```c  
//write  
if ((uint32_t)(r3 + r4) > 0x1fff) {  
	exit(1);  
}  
char* write_buf = malloc(r4);  
memcpy(write_buf, &memory[r3], r4);  
r1 = write(r2, write_buf, r4);  
free(write_buf);

//read  
if ((uint32_t)(r3 + r4) > 0x1fff) {  
	exit(1);  
}  
char* read_buf = malloc(r4);  
r1 = read(r2, read_buf, r4);  
memcpy(&memory[r3], read_buf, r1);  
free(read_buf);  
```

The change to the overflow check to now exit the progam upon failure is
unimportant, as we can bypass this check already. The addition of the
temporary buffer and call to `memcpy`, however, does matter. This seemingly
unimpactful change means that now an integer overflow would result in trying
to call `memcpy` with a ridiculously large size, which would crash the program
upon hitting an unmapped page. Clearly, there must be another vulnerability to
exploit somewhere. However, when I first reversed the original `crapsemu`
program, I was looking for vulnerabilities, but this vulnerability in
`exec_syscall()` was the only one I found. My assumption now is that another
vulnerability was introduced elsewhere in the program, so I have to go back
and reverse engineer the emulator again, carefully looking for any new
vulnerabilities.

The first place I check for new vulnerabilities is the implementation of the
`ldr`/`str` instructions, since they access memory, and sure enough the code
has changed to introduce a new vulnerability here.

Before:

```c  
// Instruction is either ldr or str  
TMP = Rx + Vy;  
if (TMP < 0 || TMP > 0x1FFF) {  
	exit(1);  
}

if (is_str) {  
	memory[TMP] = Rz;  
}  
else {  
	Rz = memory[TMP];  
}  
```

After:

```c  
// Instruction is either ldr or str  
TMP = Rx + Vy;

if (is_str) {  
	memory[TMP] = Rz;  
}  
else {  
	Rz = memory[TMP];  
}  
```

So they literally just removed the bounds check for the `ldr`/`str`
instructions. I really don't know why the bounds check was included in the
CRAPSemu challenge, as that caused me to lose a bunch of time by assuming the
only vulnerability was in the `read`/`write` syscalls. Regardless, I had now
found the intended vulnerability, and this is all that's needed to fully
exploit the target.

### Exploitation Part 1: Finding libc

The vulnerability I've found provides the primitive to read/write 4 bytes at a
time out of bounds (before or after) a `mmap`-ed memory region. From previous
experience with Linux pwn challenges at CTFs, I know that `mmap` regions are
usually located at predictable offsets from other modules loaded into memory
(such as the main executable or dynamic libraries). For this challenge
specifically, the virtual memory layout on my local machine (using libc-2.27)
is different than that on the remote server (using libc-2.31), so I had to do
a bit of bruteforcing to find the offset from the `mmap`-ed memory region to
libc. On my machine, libc was located _before_ the `mmap`-ed region in memory,
but the remote server had it after.

To find where libc was located relative to the `mmap`-ed region, I wrote an
exploit script that would send a program to the service that tried reading a
memory page from `memory + offset * PAGE_SIZE` to the server, and I
bruteforced `PAGE_SIZE` by adding something like 0x10 or 0x100 pages at a time
(because libc-2.27's .text segment is over 0x1e0 pages on my machine). I first
tried searching memory before my `mmap`-ed region, though, so I spent an hour
or so (while eating dinner) searching the wrong area of the address space on
the remote server. After that, I tried searching after my `mmap`-ed region,
and quickly found that the base address of libc is always 0x8000 bytes (index
0x2000) from the beginning of the `mmap`-ed memory region.

### Exploitation Part 2: Gaining control

Now that I had a reliable way to locate libc in memory, I needed to come up
with a plan for what to corrupt to gain control. I remembered the change to
the `read` syscall, specifically how it passes the temporary `read_buffer` to
`free()`, and decided that overwriting `__free_hook` with the address of
`system()` and then sending `/bin/sh\0` would be a good strategy for
exploitation.

To do this, I needed to figure out the absolute address of `system()`. My go-
to way to locate libc's base address is to find `environ` in the GOT (because
it's located within libc itself), so I read that out using the `ldr` leak.
Since I already know the index to the base address of libc, I can easily
calculate the index to `environ` in the GOT like so: `index_to_libc_base +
(&GOT["environ"] - libc_base) // 4`. After reading that out, then subtracting
the address of `environ` w/o ASLR, I now know the ASLR slide and can add it to
the address of `system()` w/o ASLR to find the real address. Then, it's just a
matter of calculating the index to `__free_hook` (`index_to_libc_base +
(&__free_hook - libc_base) // 4`), and doing two 32-bit writes using the `str`
bug twice to replace `__free_hook` with `&system`. Following this, my CRAPS
program invokes the `read` syscall one final time and my Python exploit script
sends `/bin/sh\0`, giving me a shell. Then it's a simple matter to `cat` the
flag, which was `THCon21{h0lY_CR4P5_U_Pwn3D_M3!!!}`.

### Other files

* [My exploit script](solve.py)  
* [Disassembled version of the CRAPS exploit program](solve.asm)

Original writeup (https://github.com/kjcolley7/CTF-
WriteUps/blob/master/2021/thcon/CRAPSaaS/README.md).