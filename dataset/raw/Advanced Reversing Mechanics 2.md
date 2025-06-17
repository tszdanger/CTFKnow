## Description

```  
More advanced than very very advanced  
0A, FB, F4, 88, DD, 9D, 7D, 5F, 9E, A3, C6, BA, F5, 95, 5D, 88, 3B, E1, 31,
50, C7, FA, F5, 81, 99, C9, 7C, 23, A1, 91, 87, B5, B1, 95, E4,  
```

Category: Reversing

## Analysis

This is a tiny ARM object, very similar to [Advanced Reversing Mechanics
1](https://github.com/dobsonj/ctf/blob/master/writeups/2020/rgbctf/advanced_reversing_mechanics_1).

```  
kali@kali:~/Downloads$ ls -l hard.o  
-rw-r--r-- 1 kali kali 1560 Jul 11 18:59 hard.o  
kali@kali:~/Downloads$ file hard.o  
hard.o: ELF 32-bit LSB relocatable, ARM, EABI5 version 1 (SYSV), not stripped  
```

## Decompile with Ghidra

Let's just look at the `encryptFlag()` function:

```c  
void encryptFlag(byte *param_1)  
{  
 byte *pbVar1;  
 byte *pbVar2;  
 uint uVar3;  
 byte bVar4;  
 uint uVar5;  
 uint uVar6;  
  
 bVar4 = *param_1;  
 pbVar1 = param_1;  
 if (bVar4 == 0) {  
   return;  
 }  
 while( true ) {  
   uVar5 = (uint)bVar4;  
   uVar3 = uVar5 - 10 & 0xff;  
   uVar6 = uVar5;  
   if ((bVar4 < 0x50) && (uVar6 = uVar3, 0x50 < uVar3)) {  
     uVar6 = uVar5 + 0x46 & 0xff;  
   }  
   uVar6 = (uVar6 - 7 ^ 0x43) & 0xff;  
   pbVar2 = pbVar1 + 1;  
   *pbVar1 = (byte)(uVar6 << 6) | (byte)(uVar6 >> 2);  
   bVar4 = *pbVar2;  
   if (bVar4 == 0) break;  
   uVar6 = (int)(pbVar2 + -(int)param_1) % 5;  
   bVar4 = bVar4 << (-uVar6 & 7) | bVar4 >> (uVar6 & 0xff);  
   if (uVar6 == 2) {  
     bVar4 = bVar4 - 1;  
   }  
   *pbVar2 = bVar4;  
   bVar4 = *pbVar2;  
   pbVar1 = pbVar2;  
 }  
 return;  
}  
```

This obviously does a more complex transformation on the input string than
just a simple decrement on each character like the last one.

Here's the disassembly of the main while loop in `encryptFlag()`:

```  
                            LAB_0001001c                                    XREF[1]:     00010098(j)    
       0001001c 92 4c c5 e0     smull      r4,r5,r2,r12  
       00010020 c5 30 63 e0     rsb        r3,r3,r5, asr #0x1  
       00010024 03 31 83 e0     add        r3,r3,r3, lsl #0x2  
       00010028 03 30 42 e0     sub        r3,r2,r3  
       0001002c 00 20 63 e2     rsb        r2,r3,#0x0  
       00010030 07 20 02 e2     and        r2,r2,#0x7  
       00010034 1e 22 a0 e1     mov        r2,lr, lsl r2  
       00010038 02 00 53 e3     cmp        r3,#0x2  
       0001003c 3e 33 82 e1     orr        r3,r2,lr, lsr r3  
       00010040 ff 30 03 e2     and        r3,r3,#0xff  
       00010044 01 30 43 02     subeq      r3,r3,#0x1  
       00010048 00 30 c1 e5     strb       r3,[r1,#0x0]  
       0001004c 00 30 d1 e5     ldrb       r3,[r1,#0x0]  
                            LAB_00010050                                    XREF[1]:     00010018(j)    
       00010050 0a 20 43 e2     sub        r2,r3,#0xa  
       00010054 4f 00 53 e3     cmp        r3,#0x4f  
       00010058 ff 20 02 e2     and        r2,r2,#0xff  
       0001005c 03 00 00 8a     bhi        LAB_00010070  
       00010060 50 00 52 e3     cmp        r2,#0x50  
       00010064 46 30 83 e2     add        r3,r3,#0x46  
       00010068 02 30 a0 91     cpyls      r3,r2  
       0001006c ff 30 03 82     andhi      r3,r3,#0xff  
                            LAB_00010070                                    XREF[1]:     0001005c(j)    
       00010070 07 30 43 e2     sub        r3,r3,#0x7  
       00010074 43 30 23 e2     eor        r3,r3,#0x43  
       00010078 ff 30 03 e2     and        r3,r3,#0xff  
       0001007c 03 23 a0 e1     mov        r2,r3, lsl #0x6  
       00010080 23 31 82 e1     orr        r3,r2,r3, lsr #0x2  
       00010084 01 30 c1 e4     strb       r3,[r1],#0x1  
       00010088 00 e0 d1 e5     ldrb       lr,[r1,#0x0]  
       0001008c 00 20 41 e0     sub        r2,r1,r0  
       00010090 00 00 5e e3     cmp        lr,#0x0  
       00010094 c2 3f a0 e1     mov        r3,r2, asr #0x1f  
       00010098 df ff ff 1a     bne        LAB_0001001c  
       0001009c 30 40 bd e8     ldmia      sp!,{ r4 r5 lr }=>local_c  
       000100a0 1e ff 2f e1     bx         lr  
```

My first thought when I look at this is that it's probably going to be quicker
and easier to solve this one character at a time with the extracted
`encryptFlag()` function than to try to understand all the details and derive
a working `decryptFlag()` function. I did something similar in
[Put_your_thang_down](https://github.com/dobsonj/ctf/blob/master/writeups/2020/dawgctf/Put_your_thang_down),
so I took the same approach here.

## Solution

Write a solver that takes the decompiled `encryptFlag()` function and then
calls that in a loop for each printable character to derive the correct input
character that transforms to the expected output character.

```c  
#include <stdio.h>  
#include <stdlib.h>  
#include <stdint.h>  
#include <string.h>

typedef unsigned char byte;

void encryptFlag(byte *param_1)  
{  
 byte *pbVar1;  
 byte *pbVar2;  
 uint uVar3;  
 byte bVar4;  
 uint uVar5;  
 uint uVar6;  
  
 bVar4 = *param_1;  
 pbVar1 = param_1;  
 if (bVar4 == 0) {  
   return;  
 }  
 while( 1 ) {  
   uVar5 = (uint)bVar4;  
   uVar3 = uVar5 - 10 & 0xff;  
   uVar6 = uVar5;  
   if ((bVar4 < 0x50) && (uVar6 = uVar3, 0x50 < uVar3)) {  
     uVar6 = uVar5 + 0x46 & 0xff;  
   }  
   uVar6 = (uVar6 - 7 ^ 0x43) & 0xff;  
   pbVar2 = pbVar1 + 1;  
   *pbVar1 = (byte)(uVar6 << 6) | (byte)(uVar6 >> 2);  
   bVar4 = *pbVar2;  
   if (bVar4 == 0) break;  
   uVar6 = (int)(pbVar2 + -(int)param_1) % 5;  
   bVar4 = bVar4 << (-uVar6 & 7) | bVar4 >> (uVar6 & 0xff);  
   if (uVar6 == 2) {  
     bVar4 = bVar4 - 1;  
   }  
   *pbVar2 = bVar4;  
   bVar4 = *pbVar2;  
   pbVar1 = pbVar2;  
 }  
 return;  
}

int main()  
{  
       char *printable_chars = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";  
       int npchars = strlen(printable_chars);

       byte nums[35] = {0x0A, 0xFB, 0xF4, 0x88, 0xDD, 0x9D, 0x7D, 0x5F, 0x9E, 0xA3, 0xC6, 0xBA, 0xF5, 0x95, 0x5D, 0x88, 0x3B, 0xE1, 0x31, 0x50, 0xC7, 0xFA, 0xF5, 0x81, 0x99, 0xC9, 0x7C, 0x23, 0xA1, 0x91, 0x87, 0xB5, 0xB1, 0x95, 0xE4};  
       byte flag[36] = {'r', 'g', 'b', 'C', 'T', 'F', '{', 0};

       for (int cur = 0; cur < sizeof(flag); cur++) {  
               for (int x = 0; x < npchars; x++) {  
                       char ch = printable_chars[x];  
                       byte arr[36] = {0};  
                       strcpy(arr,flag);  
                       arr[cur] = ch;  
                       encryptFlag(arr);  
                       if (nums[cur] == arr[cur]) {  
                               flag[cur] = ch;  
                               printf("%s\n",flag);  
                               break;  
                       }  
               }  
       }

       printf("\n");  
}  
```

Run it and we quickly get our flag:

```  
kali@kali:~/Downloads$ gcc -Wno-pointer-to-int-cast -o adv_rev_mech2
adv_rev_mech2.c && time ./adv_rev_mech2  
rgbCTF{  
rgbCTF{  
rgbCTF{  
rgbCTF{  
rgbCTF{  
rgbCTF{  
rgbCTF{  
rgbCTF{A  
rgbCTF{AR  
rgbCTF{ARM  
rgbCTF{ARM_  
rgbCTF{ARM_a  
rgbCTF{ARM_ar  
rgbCTF{ARM_ar1  
rgbCTF{ARM_ar1t  
rgbCTF{ARM_ar1th  
rgbCTF{ARM_ar1thm  
rgbCTF{ARM_ar1thm3  
rgbCTF{ARM_ar1thm3t  
rgbCTF{ARM_ar1thm3t1  
rgbCTF{ARM_ar1thm3t1c  
rgbCTF{ARM_ar1thm3t1c_  
rgbCTF{ARM_ar1thm3t1c_r  
rgbCTF{ARM_ar1thm3t1c_r0  
rgbCTF{ARM_ar1thm3t1c_r0c  
rgbCTF{ARM_ar1thm3t1c_r0ck  
rgbCTF{ARM_ar1thm3t1c_r0cks  
rgbCTF{ARM_ar1thm3t1c_r0cks_  
rgbCTF{ARM_ar1thm3t1c_r0cks_f  
rgbCTF{ARM_ar1thm3t1c_r0cks_fa  
rgbCTF{ARM_ar1thm3t1c_r0cks_fad  
rgbCTF{ARM_ar1thm3t1c_r0cks_fad9  
rgbCTF{ARM_ar1thm3t1c_r0cks_fad96  
rgbCTF{ARM_ar1thm3t1c_r0cks_fad961  
rgbCTF{ARM_ar1thm3t1c_r0cks_fad961}

real    0m0.003s  
user    0m0.003s  
sys     0m0.000s  
```

Now this worked just fine and solved it in milliseconds, but immediately after
this I realized angr.io would have been a nice way to solve this without
having to recompile any code. That solution would probably be quicker to write
but take longer to run.

In any case, the flag is:

```  
rgbCTF{ARM_ar1thm3t1c_r0cks_fad961}  
```  

Original writeup
(https://github.com/dobsonj/ctf/tree/master/writeups/2020/rgbctf/advanced_reversing_mechanics_2).