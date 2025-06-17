# Turbo Blaise - BalCCon2k20 CTF (rev, 443p, 14 solved)  
## Introduction

Turbo Blaise is a reversing task.

An archive containing an exe file and a "BGI" file is provided. The file names  
(8-3, all in caps) hint an MS-DOS challenge.

## Reverse engineering

`file` removes all doubts : this is an MS-DOS executable.

```  
$ file MAIN.EXE  
MAIN.EXE: MS-DOS executable  
```

Importing the binary in Ghidra shows a pleasant surprise : the binary is  
obfuscated.  
```c  
uRam0000af28 = 0xffc;  
uRam0000af24 = 0xc02;  
uRam0000af22 = 0xff;  
uRam0000af20 = 0x14d1;  
uRam0000af1e = 0xa1;  
FUN_14d1_0898();  
uRam0000af26 = 0x14d1;  
uRam0000af24 = 0xa6;  
FUN_14d1_0800();  
uRam0000af2a = 0x14d1;  
uRam0000af28 = 0xab;  
FUN_14d1_04f4();  
uRam0000af2a = 0x14d1;  
uRam0000af28 = 0xb;  
uRam0000af24 = 0xd02;  
uRam0000af22 = 0xff;  
uRam0000af20 = 0x14d1;  
uRam0000af1e = 0xbe;  
FUN_14d1_0c05();  
```

You start crying uncontrollably.

As you wipe the tears from your eyes, you notice the following lines :  
```assembler  
CMP byte ptr [0xc02], 0x15  
JZ  LAB_1000_00f3  
```

Setting a breakpoint on this instruction shows that address `ds:0c02` contains  
the size of the password. In fact, the whole password is stored here, in a  
Pascal string :  
```  
Trap 3, system state: emulated,stopped  
AX=001b  BX=3fec  CX=0000  DX=0877  SI=0027  DI=0d1e  SP=3ffa  BP=3ffc  
DS=0877  ES=0877  FS=0299  GS=c443  FL=7246  
CS:IP=02a9:00be       SS:SP=099c:3ffa

02a9:00be 803E020C15       cmp  byte [0C02],15  
d ds:0c02

0877:0c02 1A 4C 6F 72 65 6D 20 69 70 73 75 6D 20 64 6F 6C  .Lorem ipsum dol  
0877:0c12 6F 72 20 73 69 74 20 61 6D 65 74 00 00 00 00 00  or sit amet.....  
0877:0c22 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................  
0877:0c32 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................  
0877:0c42 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................  
0877:0c52 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................  
0877:0c62 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................  
0877:0c72 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................  
```

Using a 21-char password gives a different error message : `I am sorry :-(`  
instead of `I am very sorry :-(`

This addresses are referenced in a while loop at the end of the obfuscated  
function :  
```assembler  
MOV AL, [0xe02]  
XOR AH, AH  
MOV DI, AX  
MOV CL, byte ptr [DI + 0x7e1]

MOV AL, [0xe02]  
XOR AH, AH  
MOV DI, AX  
MOV DL, byte ptr [DI + 0xd02]

MOV AL, [0xe02]  
XOR AH, AH  
MOV DI, AX  
MOV AL, byte ptr [DI + 0xc02]

XOR AL, DL  
CMP AL, CL  
JZ  LAB_1000_015e  
```

The code is pretty straightforward : it xors every bytes in the `ds:0c02`
buffer  
with every bytes in the `ds:0d02` buffer and compare it with the bytes of the  
`ds:07e1` buffer.

Using an other breakpoint and a 21-chars password, it is possible to dump all  
three buffers :  
```  
0877:07e1 4C 08 00 01 0C 1D 12 02 42 19 0E 14 17 1C 16 41  L.......B......A  
0877:07f1 08 08 1A 1B 0D 17 53 4F 4C 01 06 0B 00 07 07 43  ......SOL......C

0877:0c02 15 61 73 64 66 61 73 64 66 61 73 64 66 61 73 64  .asdfasdfasdfasd  
0877:0c12 66 61 73 64 66 78 00 00 00 00 00 00 00 00 00 00  fasdfx..........

0877:0d02 1B 6C 69 66 65 69 73 6E 6F 74 61 70 72 6F 62 6C  .lifeisnotaprobl  
0877:0d12 65 6D 74 6F 62 65 73 6F 6C 76 65 64 00 00 00 00  emtobesolved....  
```

Xoring the `ds:07e1` buffer with `lifeisnotaproblemtobesolved` shows the  
password : `digital-modest-mentor`

When entering this password, the flag gets drawn on the screen.

**Flag**: `BCTF{BLA1SE_PASCAL_WE_MADE_HIM_TURB0}`

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-09-25-BalCCon/turboblaise/README.md).