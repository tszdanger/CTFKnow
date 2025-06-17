## Description

The Viet Cong in transmitting a secret message. They built a password checker
so that only a selected few can view the secret message. We've recovered the
binary, we need you to find out what they're trying to say.

```  
nc chall.csivit.com 30814  
```

## Analysis

What does it do?:

```  
kali@kali:~/Downloads$ ./vietnam  
foo  
Failed.  
```

It takes some input and performs a pass / fail check.

Decompile with Ghidra and look at `main()`:

```c  
undefined8 main(void)  
{  
 undefined *puVar1;  
 int iVar2;  
 int local_18;  
 int local_14;  
 char *local_10;  
  
 local_10 = (char *)malloc(0x400);  
 fgets(local_10,0x400,stdin);  
 setbuf(stdout,(char *)0x0);  
 while (puVar1 = sa, *local_10 != '\0') {  
   switch(*local_10) {  
   case '!':  
     tmp = sa;  
     sa = sb;  
     sb = sc;  
     sc = puVar1;  
     break;  
   case '$':  
     sa = sa + 1;  
     *sa = 1;  
     break;  
   case '+':  
     sa[-1] = *sa + sa[-1];  
     sa = sa + -1;  
     break;  
   case ',':  
     iVar2 = getchar();  
     *sa = (char)iVar2;  
     break;  
   case '-':  
     sa[-1] = sa[-1] - *sa;  
     sa = sa + -1;  
     break;  
   case '.':  
     puVar1 = str + 1;  
     *str = *sa;  
     str = puVar1;  
     break;  
   case '[':  
     if (*sa == '\0') {  
       local_14 = 1;  
       while (local_14 != 0) {  
         local_10 = local_10 + 1;  
         if (*local_10 == '[') {  
           local_14 = local_14 + 1;  
         }  
         else {  
           if (*local_10 == ']') {  
             local_14 = local_14 + -1;  
           }  
         }  
       }  
     }  
     break;  
   case ']':  
     if (*sa != '\0') {  
       local_18 = 1;  
       while (local_18 != 0) {  
         local_10 = local_10 + -1;  
         if (*local_10 == '[') {  
           local_18 = local_18 + -1;  
         }  
         else {  
           if (*local_10 == ']') {  
             local_18 = local_18 + 1;  
           }  
         }  
       }  
     }  
   }  
   local_10 = local_10 + 1;  
 }  
 str = STR;  
 iVar2 = strcmp(STR,"HELLO\n");  
 if (iVar2 == 0) {  
   puts(str);  
   system("cat flag.txt");  
 }  
 else {  
   puts("Failed.");  
 }  
 return 0;  
}  
```

The main input string is limited to this character set:

```  
! $ + , - . [ ] \0  
```

That's what the big switch statement is parsing. Then down at the bottom of
`main()`, there is a string comparison:

```  
 str = STR;  
 iVar2 = strcmp(STR,"HELLO\n");  
 if (iVar2 == 0) {  
   puts(str);  
   system("cat flag.txt");  
 }  
 else {  
   puts("Failed.");  
 }  
```

At first glance you might think entering "HELLO\n" as input is all you need,
but alas... it's not that simple. Set a breakpoint on the `strcmp()` call in
`main()` to see the arguments.

```  
gef➤  break *0x00000000004013ea  
Breakpoint 1 at 0x4013ea  
gef➤  r  
Starting program: /home/kali/Downloads/vietnam  
HELLO

Breakpoint 1, 0x00000000004013ea in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]  
─────────────────────────────────────────────────────────────────────────────────────
registers ────  
$rax   : 0x0000000000404ca0  →  0x0000000000000000  
$rbx   : 0x0  
$rcx   : 0xc00  
$rdx   : 0x0000000000402020  →  0xfffff390fffff289  
$rsp   : 0x00007fffffffdd10  →  0x00007fffffffde18  →  0x00007fffffffe104  →
"/home/kali/Downloads/vietnam"  
$rbp   : 0x00007fffffffdd30  →  0x0000000000401430  →  <__libc_csu_init+0>
endbr64  
$rsi   : 0x0000000000402004  →  0x63000a4f4c4c4548 ("HELLO\n"?)  
$rdi   : 0x0000000000404ca0  →  0x0000000000000000  
$rip   : 0x00000000004013ea  →  <main+612> call 0x401070 <strcmp@plt>  
$r8    : 0x00000000004062a0  →  0x00000a4f4c4c4548 ("HELLO\n"?)  
$r9    : 0x40  
$r10   : 0x00007ffff7fefb80  →  <strcmp+3504> pxor xmm0, xmm0  
$r11   : 0x00007ffff7e70db0  →  <setbuf+0> mov edx, 0x2000  
$r12   : 0x00000000004010a0  →  <_start+0> endbr64  
$r13   : 0x00007fffffffde10  →  0x0000000000000001  
$r14   : 0x0  
$r15   : 0x0  
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow
resume virtualx86 identification]  
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000  
─────────────────────────────────────────────────────────────────────────────────────────
stack ────  
0x00007fffffffdd10│+0x0000: 0x00007fffffffde18  →  0x00007fffffffe104  →
"/home/kali/Downloads/vietnam"     ← $rsp  
0x00007fffffffdd18│+0x0008: 0x00000001004010a0  
0x00007fffffffdd20│+0x0010: 0x00007fffffffde10  →  0x0000000000000001  
0x00007fffffffdd28│+0x0018: 0x00000000004062a6  →  0x0000000000000000  
0x00007fffffffdd30│+0x0020: 0x0000000000401430  →  <__libc_csu_init+0> endbr64
← $rbp  
0x00007fffffffdd38│+0x0028: 0x00007ffff7e1ae0b  →  <__libc_start_main+235> mov
edi, eax  
0x00007fffffffdd40│+0x0030: 0x00007ffff7fad618  →  0x00007ffff7e1a6f0  →
<init_cacheinfo+0> push r15  
0x00007fffffffdd48│+0x0038: 0x00007fffffffde18  →  0x00007fffffffe104  →
"/home/kali/Downloads/vietnam"  
───────────────────────────────────────────────────────────────────────────────────
code:x86:64 ────  
    0x4013d9 <main+595>       mov    rax, QWORD PTR [rip+0x2c98]        # 0x404078 <str>  
    0x4013e0 <main+602>       lea    rsi, [rip+0xc1d]        # 0x402004  
    0x4013e7 <main+609>       mov    rdi, rax  
→   0x4013ea <main+612>       call   0x401070 <strcmp@plt>  
  ↳    0x401070 <strcmp@plt+0>   jmp    QWORD PTR [rip+0x2fc2]        #
0x404038 <[email protected]>  
       0x401076 <strcmp@plt+6>   push   0x4  
       0x40107b <strcmp@plt+11>  jmp    0x401020  
       0x401080 <getchar@plt+0>  jmp    QWORD PTR [rip+0x2fba]        # 0x404040 <[email protected]>  
       0x401086 <getchar@plt+6>  push   0x5  
       0x40108b <getchar@plt+11> jmp    0x401020  
───────────────────────────────────────────────────────────────────────────
arguments (guessed) ────  
strcmp@plt (  
  $rdi = 0x0000000000404ca0 → 0x0000000000000000,  
  $rsi = 0x0000000000402004 → 0x63000a4f4c4c4548 ("HELLO\n"?)  
)  
───────────────────────────────────────────────────────────────────────────────────────
threads ────  
[#0] Id 1, Name: "vietnam", stopped 0x4013ea in main (), reason: BREAKPOINT  
─────────────────────────────────────────────────────────────────────────────────────────
trace ────  
[#0] 0x4013ea → main()  
────────────────────────────────────────────────────────────────────────────────────────────────────  
gef➤  c  
Continuing.  
Failed.  
[Inferior 1 (process 210596) exited normally]  
```

Notice that despite the input, we're comparing an empty string (`$rdi`) to
"HELLO\n" (`$rsi`), and of course that comparison fails. So we're not
comparing the main input string... we're comparing `STR` which is statically
allocated memory, and there is a pointer `str` that points to the current
char.

Looking back at the case statements in `main()`, there are a few interesting
ones that can be used to manipulate `str`. The only 2 that we really have to
care about though are `,` and `.`:

This calls `getchar()` to accept a new input character:

```  
   case ',':  
     iVar2 = getchar();  
     *sa = (char)iVar2;  
     break;  
```

Then this will set the current `str` char to what is stored in `sa`:

```  
   case '.':  
     puVar1 = str + 1;  
     *str = *sa;  
     str = puVar1;  
     break;  
```

We can test this out in gdb to see what we get for the string comparison if we
provide `,.` for the primay input and then `H` for the call to `getchar()`.

```  
gef➤  r  
Starting program: /home/kali/Downloads/vietnam ;  
,.  
H

Breakpoint 1, 0x00000000004013ea in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]  
─────────────────────────────────────────────────────────────────────────────────────
registers ────  
$rax   : 0x0000000000404ca0  →  0x0000000000000048 ("H"?)  
$rbx   : 0x0  
$rcx   : 0x0000000000404ca1  →  0x0000000000000000  
$rdx   : 0x48  
$rsp   : 0x00007fffffffdd10  →  0x00007fffffffde18  →  0x00007fffffffe104  →
"/home/kali/Downloads/vietnam"  
$rbp   : 0x00007fffffffdd30  →  0x0000000000401430  →  <__libc_csu_init+0>
endbr64  
$rsi   : 0x0000000000402004  →  0x63000a4f4c4c4548 ("HELLO\n"?)  
$rdi   : 0x0000000000404ca0  →  0x0000000000000048 ("H"?)  
$rip   : 0x00000000004013ea  →  <main+612> call 0x401070 <strcmp@plt>  
$r8    : 0x0  
$r9    : 0x40  
$r10   : 0x000000000040049c  →  0x0072616863746567 ("getchar"?)  
$r11   : 0x246  
$r12   : 0x00000000004010a0  →  <_start+0> endbr64  
$r13   : 0x00007fffffffde10  →  0x0000000000000001  
$r14   : 0x0  
$r15   : 0x0  
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow
resume virtualx86 identification]  
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000  
─────────────────────────────────────────────────────────────────────────────────────────
stack ────  
0x00007fffffffdd10│+0x0000: 0x00007fffffffde18  →  0x00007fffffffe104  →
"/home/kali/Downloads/vietnam"     ← $rsp  
0x00007fffffffdd18│+0x0008: 0x00000001004010a0  
0x00007fffffffdd20│+0x0010: 0x00007fffffffde10  →  0x0000000000000001  
0x00007fffffffdd28│+0x0018: 0x00000000004062a3  →  0x0000000000000000  
0x00007fffffffdd30│+0x0020: 0x0000000000401430  →  <__libc_csu_init+0> endbr64
← $rbp  
0x00007fffffffdd38│+0x0028: 0x00007ffff7e1ae0b  →  <__libc_start_main+235> mov
edi, eax  
0x00007fffffffdd40│+0x0030: 0x00007ffff7fad618  →  0x00007ffff7e1a6f0  →
<init_cacheinfo+0> push r15  
0x00007fffffffdd48│+0x0038: 0x00007fffffffde18  →  0x00007fffffffe104  →
"/home/kali/Downloads/vietnam"  
───────────────────────────────────────────────────────────────────────────────────
code:x86:64 ────  
    0x4013d9 <main+595>       mov    rax, QWORD PTR [rip+0x2c98]        # 0x404078 <str>  
    0x4013e0 <main+602>       lea    rsi, [rip+0xc1d]        # 0x402004  
    0x4013e7 <main+609>       mov    rdi, rax  
→   0x4013ea <main+612>       call   0x401070 <strcmp@plt>  
  ↳    0x401070 <strcmp@plt+0>   jmp    QWORD PTR [rip+0x2fc2]        #
0x404038 <[email protected]>  
       0x401076 <strcmp@plt+6>   push   0x4  
       0x40107b <strcmp@plt+11>  jmp    0x401020  
       0x401080 <getchar@plt+0>  jmp    QWORD PTR [rip+0x2fba]        # 0x404040 <[email protected]>  
       0x401086 <getchar@plt+6>  push   0x5  
       0x40108b <getchar@plt+11> jmp    0x401020  
───────────────────────────────────────────────────────────────────────────
arguments (guessed) ────  
strcmp@plt (  
  $rdi = 0x0000000000404ca0 → 0x0000000000000048 ("H"?),  
  $rsi = 0x0000000000402004 → 0x63000a4f4c4c4548 ("HELLO\n"?)  
)  
───────────────────────────────────────────────────────────────────────────────────────
threads ────  
[#0] Id 1, Name: "vietnam", stopped 0x4013ea in main (), reason: BREAKPOINT  
─────────────────────────────────────────────────────────────────────────────────────────
trace ────  
[#0] 0x4013ea → main()  
────────────────────────────────────────────────────────────────────────────────────────────────────  
gef➤  
```

Bingo, we got the first character in the right buffer for the string compare.
Now we just have to use that technique for the remaining characters.

## Solution

```  
kali@kali:~/Downloads$ perl -e 'print ",.,.,.,.,.,.\n" . "HELLO\n"' >
hello.txt  
```

Try it locally first and make sure the input looks correct in gdb:

```  
gef➤  r < hello.txt  
Starting program: /home/kali/Downloads/vietnam < hello.txt

Breakpoint 1, 0x00000000004013ea in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]  
─────────────────────────────────────────────────────────────────────────────────────
registers ────  
$rax   : 0x0000000000404ca0  →  0x00000a4f4c4c4548 ("HELLO\n"?)  
$rbx   : 0x0  
$rcx   : 0x0000000000404ca6  →  0x0000000000000000  
$rdx   : 0xa  
$rsp   : 0x00007fffffffdd10  →  0x00007fffffffde18  →  0x00007fffffffe104  →
"/home/kali/Downloads/vietnam"  
$rbp   : 0x00007fffffffdd30  →  0x0000000000401430  →  <__libc_csu_init+0>
endbr64  
$rsi   : 0x0000000000402004  →  0x63000a4f4c4c4548 ("HELLO\n"?)  
$rdi   : 0x0000000000404ca0  →  0x00000a4f4c4c4548 ("HELLO\n"?)  
$rip   : 0x00000000004013ea  →  <main+612> call 0x401070 <strcmp@plt>  
$r8    : 0xa  
$r9    : 0x70  
$r10   : 0x000000000040049c  →  0x0072616863746567 ("getchar"?)  
$r11   : 0x00007ffff7e70860  →  <getchar+0> push r12  
$r12   : 0x00000000004010a0  →  <_start+0> endbr64  
$r13   : 0x00007fffffffde10  →  0x0000000000000001  
$r14   : 0x0  
$r15   : 0x0  
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow
resume virtualx86 identification]  
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000  
─────────────────────────────────────────────────────────────────────────────────────────
stack ────  
0x00007fffffffdd10│+0x0000: 0x00007fffffffde18  →  0x00007fffffffe104  →
"/home/kali/Downloads/vietnam"     ← $rsp  
0x00007fffffffdd18│+0x0008: 0x00000001004010a0  
0x00007fffffffdd20│+0x0010: 0x00007fffffffde10  →  0x0000000000000001  
0x00007fffffffdd28│+0x0018: 0x00000000004062ad  →  0x0000000000000000  
0x00007fffffffdd30│+0x0020: 0x0000000000401430  →  <__libc_csu_init+0> endbr64
← $rbp  
0x00007fffffffdd38│+0x0028: 0x00007ffff7e1ae0b  →  <__libc_start_main+235> mov
edi, eax  
0x00007fffffffdd40│+0x0030: 0x00007ffff7fad618  →  0x00007ffff7e1a6f0  →
<init_cacheinfo+0> push r15  
0x00007fffffffdd48│+0x0038: 0x00007fffffffde18  →  0x00007fffffffe104  →
"/home/kali/Downloads/vietnam"  
───────────────────────────────────────────────────────────────────────────────────
code:x86:64 ────  
    0x4013d9 <main+595>       mov    rax, QWORD PTR [rip+0x2c98]        # 0x404078 <str>  
    0x4013e0 <main+602>       lea    rsi, [rip+0xc1d]        # 0x402004  
    0x4013e7 <main+609>       mov    rdi, rax  
→   0x4013ea <main+612>       call   0x401070 <strcmp@plt>  
  ↳    0x401070 <strcmp@plt+0>   jmp    QWORD PTR [rip+0x2fc2]        #
0x404038 <[email protected]>  
       0x401076 <strcmp@plt+6>   push   0x4  
       0x40107b <strcmp@plt+11>  jmp    0x401020  
       0x401080 <getchar@plt+0>  jmp    QWORD PTR [rip+0x2fba]        # 0x404040 <[email protected]>  
       0x401086 <getchar@plt+6>  push   0x5  
       0x40108b <getchar@plt+11> jmp    0x401020  
───────────────────────────────────────────────────────────────────────────
arguments (guessed) ────  
strcmp@plt (  
  $rdi = 0x0000000000404ca0 → 0x00000a4f4c4c4548 ("HELLO\n"?),  
  $rsi = 0x0000000000402004 → 0x63000a4f4c4c4548 ("HELLO\n"?)  
)  
───────────────────────────────────────────────────────────────────────────────────────
threads ────  
[#0] Id 1, Name: "vietnam", stopped 0x4013ea in main (), reason: BREAKPOINT  
─────────────────────────────────────────────────────────────────────────────────────────
trace ────  
[#0] 0x4013ea → main()  
────────────────────────────────────────────────────────────────────────────────────────────────────  
gef➤  c  
Continuing.  
HELLO

[Detaching after vfork from child process 210520]  
cat: flag.txt: No such file or directory  
[Inferior 1 (process 210518) exited normally]  
gef➤  
```

Now that it works locally, we just have to send it to the remote server to get
the flag.

```  
kali@kali:~/Downloads$ perl -e 'print ",.,.,.,.,.,.\n" . "HELLO\n"' | nc chall.csivit.com 30814  
HELLO

csictf{l00k_4t_th3_t0w3rs_0f_h4n01}  
```  

Original writeup
(https://github.com/dobsonj/ctf/tree/master/writeups/2020/csictf/vietnam).