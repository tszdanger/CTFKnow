# weenie_hut_general

## Description

```  
Can you crack the code before you get demoted to weenie hut junior?

Difficulty: Easy

by ndamalas  
```

## Analysis

It's a binary, but it segfaults when trying to run it:

```  
kali@kali:~/Downloads$ file weenie_hut_general  
weenie_hut_general: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV),
dynamically linked, BuildID[sha1]=93fdae3c669aff2c2d337e4c09a41cefb8004b3f,
not stripped  
kali@kali:~/Downloads$ ./weenie_hut_general  
Segmentation fault  
```

```  
gef➤  r  
Starting program: /home/kali/Downloads/weenie_hut_general

Program received signal SIGSEGV, Segmentation fault.  
0x0000000000000001 in ?? ()  
```

Doesn't really matter though, the part we have to reverse is pretty simple.
From Ghidra:

```c  
void revvy(void)  
{  
 srand(0x11c4);  
 return;  
}

void tryToRev(uint param_1)  
{  
 uint uVar1;  
 uint uVar2;  
  
 revvy();  
 uVar1 = rand();  
 uVar2 = rand();  
 if ((param_1 ^ uVar1 ^ 0x3597b741) == uVar2) {  
   puts(  
       "Password Accepted, welcome to weenie hut general! Submit input as flag! (Don\'t forget towrap it in bctf{})"  
       );  
 }  
 else {  
   puts("That\'s incorrect. Try going to weenie hut junior.");  
 }  
 return;  
}  
```

We have the seed (`0x11c4`), so uVar1 and uVar2 will always be the same as
long as we use that seed. Then it's just a matter of doing the math to get the
value for `param_1`.

## Solution

Write a small C program to derive `param_1` based on the decompiled code
above.

```c  
#include <stdio.h>  
#include <stdlib.h>  
#include <inttypes.h>

int main() {  
       srand(0x11c4);  
       uint32_t uVar1 = rand();  
       uint32_t uVar2 = rand();  
       printf("uVar1 = %u\n", uVar1);  
       printf("uVar2 = %u\n", uVar2);

       uint32_t x = uVar2 ^ uVar1 ^ 0x3597b741;  
       printf("uVar2 ^ uVar1 ^ 0x3597b741 = %u\n", x);

       if ((x ^ uVar1 ^ 0x3597b741) == uVar2)  
               printf("bctf{%u}\n", x);

       return 0;  
}  
```

Run it to get the flag.

```  
kali@kali:~/Downloads$ gcc -o weenie_solve weenie_solve.c && ./weenie_solve  
uVar1 = 1915766271  
uVar2 = 318420489  
uVar2 ^ uVar1 ^ 0x3597b741 = 1432175799  
bctf{1432175799}  
```

The flag is:

```  
bctf{1432175799}  
```  

Original writeup
(https://github.com/dobsonj/ctf/tree/master/writeups/2021/b01lersctf/weenie_hut_general).