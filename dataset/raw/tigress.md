# tigress (11 solves)

Description:

> what's the flag?  
>  
> by Dan

The binary is packed with tigress virtual machine.
http://tigress.cs.arizona.edu/

Disclaimer:

I solved it by hand, again. I tried **triton** deobfuscation, but did not
succeed :(

main function:

```c++  
int main(int a1, char **a2, char **a3)  
{  
 char **v4;  
 char input;  
 unsigned __int64 v6;

 v4 = a3;  
 v6 = __readfsqword(0x28u);  
 sub_5631FFB89F3C();  
 dword_5631FFD8EB70 = a1;  
 qword_5631FFD8EB60 = (__int64)a2;  
 qword_5631FFD8EBB0 = (__int64)v4;  
 printf("enter the flag: ");  
 __isoc99_scanf("%300s", &input);  
 virtual_machine(input);  
 return 0LL;  
}  
```

The virtual machine is big, I wont list it here.

The solution is simple:

We set hw bp on our input, we trace where our input gets accessed.

First, we break on "get_byte" handler which stores one byte from our input in
some memory location:

```  
.text:0000564CB3E5A83C movzx   edx, byte ptr [rdx]      ; our input  
.text:0000564CB3E5A83F mov     [rax], dl                        ; some memory
loc  
.text:0000564CB3E5A841 jmp     loc_564CB3E59AD1  
```

We hw bp that memory location and hit run.

We break on xor handler, first argument being our input char, second being
unknown value:

```  
.text:0000562173C9A86C mov     ecx, [rax]  
.text:0000562173C9A86E mov     rax, [rbp+var_290]  
.text:0000562173C9A875 mov     edx, [rax]  
.text:0000562173C9A877 mov     rax, [rbp+var_290]  
.text:0000562173C9A87E sub     rax, 8  
.text:0000562173C9A882 xor     edx, ecx         ; edx - input[i], ecx -
unknown[i]  
.text:0000562173C9A884 mov     [rax], edx  
.text:0000562173C9A886 mov     rax, [rbp+var_290]  
.text:0000562173C9A88D sub     rax, 8  
.text:0000562173C9A891 mov     [rbp+var_290], rax  
.text:0000562173C9A898 jmp     loc_562173C99AD1  
```

After that we break on "cmp" handler:

```  
.text:0000562173C9A545 mov     [rbp+var_288], rax  
.text:0000562173C9A54C mov     rax, [rbp+var_290]  
.text:0000562173C9A553 mov     edx, [rax]  
.text:0000562173C9A555 mov     rax, [rbp+var_290]  
.text:0000562173C9A55C sub     rax, 8  
.text:0000562173C9A560 mov     eax, [rax]  
.text:0000562173C9A562 cmp     edx, eax         ; edx - xored input, eax -
unkown val  
.text:0000562173C9A564 setnz   cl  
.text:0000562173C9A567 mov     rax, [rbp+var_290]  
.text:0000562173C9A56E lea     rdx, [rax-8]  
.text:0000562173C9A572 movzx   eax, cl  
.text:0000562173C9A575 mov     [rdx], eax  
.text:0000562173C9A577 mov     rax, [rbp+var_290]  
.text:0000562173C9A57E sub     rax, 8  
.text:0000562173C9A582 mov     [rbp+var_290], rax  
.text:0000562173C9A589 jmp     loc_562173C99AD1  
```

After that we loop again.

So, the solution is simple, we write down unknown values for every input char.

Solution:

```python  
import sys  
from z3 import *

# flag len = 0x33

magics = [  
   # xor,  cmp  
   (0x15, 0x60), # u  
   (0x34, 0x40), # t  
   (0xcb, 0xad), # f  
   (0xe2, 0x8e), # l  
   (0xb4, 0xd5), # a  
   (0x6b, 0x0c), # g  
   (0xdc, 0xa7), # {  
   (0xdd, 0x89),  
   (0xa9, 0xc1),  
   (0x8e, 0xcb),  
   (0xff, 0xa0),  
   (0x98, 0xfd),  
   (0x9b, 0xc2),  
   (0x63, 0x06),  
   (0xf2, 0xad),  
   (0x99, 0xf6),  
   (0xb1, 0xf7),  
   (0x62, 0x3d),  
   (0xf2, 0x86),  
   (0xe3, 0xab),  
   (0xed, 0x88),  
   (0x45, 0x1a),  
   (0x19, 0x4d),  
   (0x90, 0xd9),  
   (0x21, 0x66),  
   (0x36, 0x64),  
   (0x57, 0x12),  
   (0x92, 0xc1),  
   (0x38, 0x6b),  
   (0x75, 0x2a),  
   (0x41, 0x35),  
   (0xe9, 0x8d),  
   (0xc6, 0xa5),  
   (0x45, 0x1d),  
   (0x5b, 0x03),  
   (0xf2, 0xa4),  
   (0x3a, 0x58),  
   (0x64, 0x0c),  
   (0xb3, 0xdb),  
   (0x69, 0x29),  
   (0x9f, 0xec),  
   (0x1d, 0x50),  
   (0x5b, 0x29),  
   (0x39, 0x5c),  
   (0x5e, 0x66),  
   (0x09, 0x5a),  
   (0x53, 0x6b),  
   (0x67, 0x1e),  
   (0x97, 0xa1),  
   (0xa9, 0x8c),  
   (0x21, 0x5c)  # }

]

flag_len = 0x33

def find_all_possible(s):  
   while s.check() == sat:  
       model = s.model()  
       block = []  
       out = ''  
       for i in range(flag_len):  
           c = globals()['b%i' % i]  
           out += chr(model[c].as_long())  
           block.append(c != model[c])  
       s.add(Or(block))  
       print(out)

def main():  
   s = Solver()  
  
   for i in range(flag_len):  
       k, v = magics[i]  
       globals()['b%d' % i] = BitVec('b%d' % i, 8)  
       s.add(globals()['b%d' % i] >= 32)  
       s.add(globals()['b%d' % i] <= 127)  
       s.add(globals()['b%d' % i] ^ k == v)

   find_all_possible(s)

if __name__ == "__main__":  
   sys.exit(main())  
```

yields the flag:

```  
utflag{ThE_eYe_oF_tHe_TIGRESS_tdcXXVbhh@sMre8S8y6%}  
```

Original writeup (https://github.com/archercreat/CTF-
Writeups/blob/master/utctf/rev/tigress/README.md).