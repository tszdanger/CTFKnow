# rev/Trampoline (51 solves/154 points)  
## Description:  
Trampolines cause about 100,000 emergency room visits annually.

## Solution:  
Decompiling the code in ghidra says  
```  
/* WARNING: Could not recover jumptable at 0x00101208. Too many branches */  
/* WARNING: Treating indirect jump as call */  
```  
in `chk_flag()`. Uh oh, I can't decompile anymore time to give up. So then I
read through the disassembly and there's a lot of `DEC RAX` followed by a
single `INC RAX` apparently we're supposed to jump past all those `DEC`'s and
reach the `INC`. That means that the number of DECs is the ord of the char.
How do we know this? The last cmp in main for chk_flag ask for a value of
0x39. If we return RAX we need it to be 0x39 (57). There is also 57 of these
"blocks". 57 is the number of jumps, the number we cmp, and the number of
chars in the flag. Here's an example piece of code, it would be too much to
put all of it here.  
```  
                            LAB_00106b44                                    XREF[1]:     00106b38(*)    
       00106b44 48 ff c8        DEC        RAX  
       00106b47 48 ff c8        DEC        RAX  
       00106b4a 48 ff c8        DEC        RAX  
       00106b4d 48 ff c8        DEC        RAX  
       00106b50 48 ff c8        DEC        RAX  
       00106b53 48 ff c8        DEC        RAX  
       00106b56 48 ff c8        DEC        RAX  
       00106b59 48 ff c8        DEC        RAX  
       00106b5c 48 ff c8        DEC        RAX  
       00106b5f 48 ff c8        DEC        RAX  
       00106b62 48 ff c8        DEC        RAX  
       00106b65 48 ff c8        DEC        RAX  
       00106b68 48 ff c8        DEC        RAX  
       00106b6b 48 ff c8        DEC        RAX  
       00106b6e 48 ff c8        DEC        RAX  
       00106b71 48 ff c8        DEC        RAX  
       00106b74 48 ff c8        DEC        RAX  
       00106b77 48 ff c8        DEC        RAX  
       00106b7a 48 ff c8        DEC        RAX  
       00106b7d 48 ff c8        DEC        RAX  
       00106b80 48 ff c8        DEC        RAX  
       00106b83 48 ff c8        DEC        RAX  
       00106b86 48 ff c8        DEC        RAX  
       00106b89 48 ff c8        DEC        RAX  
       00106b8c 48 ff c8        DEC        RAX  
       00106b8f 48 ff c8        DEC        RAX  
       00106b92 48 ff c8        DEC        RAX  
       00106b95 48 ff c8        DEC        RAX  
       00106b98 48 ff c8        DEC        RAX  
       00106b9b 48 ff c8        DEC        RAX  
       00106b9e 48 ff c8        DEC        RAX  
       00106ba1 48 ff c8        DEC        RAX  
       00106ba4 48 ff c8        DEC        RAX  
       00106ba7 48 ff c8        DEC        RAX  
       00106baa 48 ff c8        DEC        RAX  
       00106bad 48 ff c8        DEC        RAX  
       00106bb0 48 ff c8        DEC        RAX  
       00106bb3 48 ff c8        DEC        RAX  
       00106bb6 48 ff c8        DEC        RAX  
       00106bb9 48 ff c8        DEC        RAX  
       00106bbc 48 ff c8        DEC        RAX  
       00106bbf 48 ff c8        DEC        RAX  
       00106bc2 48 ff c8        DEC        RAX  
       00106bc5 48 ff c8        DEC        RAX  
       00106bc8 48 ff c8        DEC        RAX  
       00106bcb 48 ff c8        DEC        RAX  
       00106bce 48 ff c8        DEC        RAX  
       00106bd1 48 ff c8        DEC        RAX  
       00106bd4 48 ff c8        DEC        RAX  
       00106bd7 48 ff c8        DEC        RAX  
       00106bda 48 ff c8        DEC        RAX  
       00106bdd 48 ff c8        DEC        RAX  
       00106be0 48 ff c8        DEC        RAX  
       00106be3 48 ff c8        DEC        RAX  
       00106be6 48 ff c8        DEC        RAX  
       00106be9 48 ff c8        DEC        RAX  
       00106bec 48 ff c8        DEC        RAX  
       00106bef 48 ff c8        DEC        RAX  
       00106bf2 48 ff c8        DEC        RAX  
       00106bf5 48 ff c8        DEC        RAX  
       00106bf8 48 ff c8        DEC        RAX  
       00106bfb 48 ff c8        DEC        RAX  
       00106bfe 48 ff c8        DEC        RAX  
       00106c01 48 ff c8        DEC        RAX  
       00106c04 48 ff c8        DEC        RAX  
       00106c07 48 ff c8        DEC        RAX  
       00106c0a 48 ff c8        DEC        RAX  
       00106c0d 48 ff c8        DEC        RAX  
       00106c10 48 ff c8        DEC        RAX  
       00106c13 48 ff c8        DEC        RAX  
       00106c16 48 ff c8        DEC        RAX  
       00106c19 48 ff c8        DEC        RAX  
       00106c1c 48 ff c8        DEC        RAX  
       00106c1f 48 ff c8        DEC        RAX  
       00106c22 48 ff c8        DEC        RAX  
       00106c25 48 ff c8        DEC        RAX  
       00106c28 48 ff c8        DEC        RAX  
       00106c2b 48 ff c8        DEC        RAX  
       00106c2e 48 ff c8        DEC        RAX  
       00106c31 48 ff c8        DEC        RAX  
       00106c34 48 ff c8        DEC        RAX  
       00106c37 48 ff c8        DEC        RAX  
       00106c3a 48 ff c8        DEC        RAX  
       00106c3d 48 ff c8        DEC        RAX  
       00106c40 48 ff c8        DEC        RAX  
       00106c43 48 ff c8        DEC        RAX  
       00106c46 48 ff c8        DEC        RAX  
       00106c49 48 ff c8        DEC        RAX  
       00106c4c 48 ff c8        DEC        RAX  
       00106c4f 48 ff c8        DEC        RAX  
       00106c52 48 ff c8        DEC        RAX  
       00106c55 48 ff c8        DEC        RAX  
       00106c58 48 ff c8        DEC        RAX  
       00106c5b 48 ff c8        DEC        RAX  
       00106c5e 48 ff c8        DEC        RAX  
       00106c61 48 ff c8        DEC        RAX  
       00106c64 48 ff c8        DEC        RAX  
       00106c67 48 ff c8        DEC        RAX  
       00106c6a 48 ff c8        DEC        RAX  
       00106c6d 48 ff c8        DEC        RAX  
       00106c70 48 ff c8        DEC        RAX  
       00106c73 48 ff c8        DEC        RAX  
       00106c76 48 ff c8        DEC        RAX  
       00106c79 48 ff c8        DEC        RAX  
       00106c7c 48 ff c8        DEC        RAX  
       00106c7f 48 ff c8        DEC        RAX  
       00106c82 48 ff c8        DEC        RAX  
       00106c85 48 ff c8        DEC        RAX  
       00106c88 48 ff c8        DEC        RAX  
       00106c8b 48 ff c8        DEC        RAX  
       00106c8e 48 ff c0        INC        RAX  
       00106c91 0f 1f c0        NOP        EAX  
       00106c94 0f 1f c0        NOP        EAX  
       00106c97 0f 1f c0        NOP        EAX  
       00106c9a 0f 1f c0        NOP        EAX  
       00106c9d 0f 1f c0        NOP        EAX  
       00106ca0 0f 1f c0        NOP        EAX  
       00106ca3 0f 1f c0        NOP        EAX  
       00106ca6 0f 1f c0        NOP        EAX  
       00106ca9 0f 1f c0        NOP        EAX  
       00106cac 0f 1f c0        NOP        EAX  
       00106caf 0f 1f c0        NOP        EAX  
       00106cb2 0f 1f c0        NOP        EAX  
       00106cb5 0f 1f c0        NOP        EAX  
       00106cb8 0f 1f c0        NOP        EAX  
       00106cbb 0f 1f c0        NOP        EAX  
       00106cbe 0f 1f c0        NOP        EAX  
       00106cc1 0f 1f c0        NOP        EAX  
       00106cc4 48 89 45 f8     MOV        qword ptr [RBP + -0x8],RAX  
       00106cc8 48 31 c0        XOR        RAX,RAX  
       00106ccb 8a 07           MOV        AL,byte ptr [RDI]  
       00106ccd 48 ff c7        INC        RDI  
       00106cd0 ba 03 00        MOV        EDX,0x3  
                00 00  
       00106cd5 48 f7 e2        MUL        RDX  
       00106cd8 48 89 c1        MOV        RCX,RAX  
       00106cdb 48 8b 45 f8     MOV        RAX,qword ptr [RBP + -0x8]  
       00106cdf 48 8d 15        LEA        RDX,[LAB_00106ceb]  
                05 00 00 00  
       00106ce6 48 01 d1        ADD        RCX,RDX  
       00106ce9 ff e1           JMP        RCX  
                            LAB_00106ceb                                    XREF[1]:     00106cdf(*)    
       00106ceb 48 ff c8        DEC        RAX  
       00106cee 48 ff c8        DEC        RAX  
       00106cf1 48 ff c8        DEC        RAX  
       00106cf4 48 ff c8        DEC        RAX  
       00106cf7 48 ff c8        DEC        RAX  
       00106cfa 48 ff c8        DEC        RAX  
       00106cfd 48 ff c8        DEC        RAX  
       00106d00 48 ff c8        DEC        RAX  
       00106d03 48 ff c8        DEC        RAX  
       00106d06 48 ff c8        DEC        RAX  
       00106d09 48 ff c8        DEC        RAX  
       00106d0c 48 ff c8        DEC        RAX  
       00106d0f 48 ff c8        DEC        RAX  
       00106d12 48 ff c8        DEC        RAX  
       00106d15 48 ff c8        DEC        RAX  
       00106d18 48 ff c8        DEC        RAX  
       00106d1b 48 ff c8        DEC        RAX  
       00106d1e 48 ff c8        DEC        RAX  
       00106d21 48 ff c8        DEC        RAX  
       00106d24 48 ff c8        DEC        RAX  
       00106d27 48 ff c8        DEC        RAX  
       00106d2a 48 ff c8        DEC        RAX  
       00106d2d 48 ff c8        DEC        RAX  
       00106d30 48 ff c8        DEC        RAX  
       00106d33 48 ff c8        DEC        RAX  
       00106d36 48 ff c8        DEC        RAX  
       00106d39 48 ff c8        DEC        RAX  
       00106d3c 48 ff c8        DEC        RAX  
       00106d3f 48 ff c8        DEC        RAX  
       00106d42 48 ff c8        DEC        RAX  
       00106d45 48 ff c8        DEC        RAX  
       00106d48 48 ff c8        DEC        RAX  
       00106d4b 48 ff c8        DEC        RAX  
       00106d4e 48 ff c8        DEC        RAX  
       00106d51 48 ff c8        DEC        RAX  
       00106d54 48 ff c8        DEC        RAX  
       00106d57 48 ff c8        DEC        RAX  
       00106d5a 48 ff c8        DEC        RAX  
       00106d5d 48 ff c8        DEC        RAX  
       00106d60 48 ff c8        DEC        RAX  
       00106d63 48 ff c8        DEC        RAX  
       00106d66 48 ff c8        DEC        RAX  
       00106d69 48 ff c8        DEC        RAX  
       00106d6c 48 ff c8        DEC        RAX  
       00106d6f 48 ff c8        DEC        RAX  
       00106d72 48 ff c8        DEC        RAX  
       00106d75 48 ff c8        DEC        RAX  
       00106d78 48 ff c8        DEC        RAX  
       00106d7b 48 ff c8        DEC        RAX  
       00106d7e 48 ff c8        DEC        RAX  
       00106d81 48 ff c8        DEC        RAX  
       00106d84 48 ff c8        DEC        RAX  
       00106d87 48 ff c8        DEC        RAX  
       00106d8a 48 ff c8        DEC        RAX  
       00106d8d 48 ff c8        DEC        RAX  
       00106d90 48 ff c8        DEC        RAX  
       00106d93 48 ff c8        DEC        RAX  
       00106d96 48 ff c8        DEC        RAX  
       00106d99 48 ff c8        DEC        RAX  
       00106d9c 48 ff c8        DEC        RAX  
       00106d9f 48 ff c8        DEC        RAX  
       00106da2 48 ff c8        DEC        RAX  
       00106da5 48 ff c8        DEC        RAX  
       00106da8 48 ff c8        DEC        RAX  
       00106dab 48 ff c8        DEC        RAX  
       00106dae 48 ff c8        DEC        RAX  
       00106db1 48 ff c8        DEC        RAX  
       00106db4 48 ff c8        DEC        RAX  
       00106db7 48 ff c8        DEC        RAX  
       00106dba 48 ff c8        DEC        RAX  
       00106dbd 48 ff c8        DEC        RAX  
       00106dc0 48 ff c8        DEC        RAX  
       00106dc3 48 ff c8        DEC        RAX  
       00106dc6 48 ff c8        DEC        RAX  
       00106dc9 48 ff c8        DEC        RAX  
       00106dcc 48 ff c8        DEC        RAX  
       00106dcf 48 ff c8        DEC        RAX  
       00106dd2 48 ff c8        DEC        RAX  
       00106dd5 48 ff c8        DEC        RAX  
       00106dd8 48 ff c8        DEC        RAX  
       00106ddb 48 ff c8        DEC        RAX  
       00106dde 48 ff c8        DEC        RAX  
       00106de1 48 ff c8        DEC        RAX  
       00106de4 48 ff c8        DEC        RAX  
       00106de7 48 ff c8        DEC        RAX  
       00106dea 48 ff c8        DEC        RAX  
       00106ded 48 ff c8        DEC        RAX  
       00106df0 48 ff c8        DEC        RAX  
       00106df3 48 ff c8        DEC        RAX  
       00106df6 48 ff c8        DEC        RAX  
       00106df9 48 ff c8        DEC        RAX  
       00106dfc 48 ff c8        DEC        RAX  
       00106dff 48 ff c8        DEC        RAX  
       00106e02 48 ff c8        DEC        RAX  
       00106e05 48 ff c8        DEC        RAX  
       00106e08 48 ff c8        DEC        RAX  
       00106e0b 48 ff c8        DEC        RAX  
       00106e0e 48 ff c8        DEC        RAX  
       00106e11 48 ff c8        DEC        RAX  
       00106e14 48 ff c8        DEC        RAX  
       00106e17 48 ff c0        INC        RAX  
       00106e1a 0f 1f c0        NOP        EAX  
       00106e1d 0f 1f c0        NOP        EAX  
       00106e20 0f 1f c0        NOP        EAX  
       00106e23 0f 1f c0        NOP        EAX  
       00106e26 0f 1f c0        NOP        EAX  
       00106e29 0f 1f c0        NOP        EAX  
       00106e2c 0f 1f c0        NOP        EAX  
       00106e2f 0f 1f c0        NOP        EAX  
       00106e32 0f 1f c0        NOP        EAX  
       00106e35 0f 1f c0        NOP        EAX  
       00106e38 0f 1f c0        NOP        EAX  
       00106e3b 0f 1f c0        NOP        EAX  
       00106e3e 0f 1f c0        NOP        EAX  
       00106e41 0f 1f c0        NOP        EAX  
       00106e44 0f 1f c0        NOP        EAX  
       00106e47 0f 1f c0        NOP        EAX  
       00106e4a 0f 1f c0        NOP        EAX  
       00106e4d 0f 1f c0        NOP        EAX  
       00106e50 0f 1f c0        NOP        EAX  
       00106e53 0f 1f c0        NOP        EAX  
       00106e56 0f 1f c0        NOP        EAX  
       00106e59 0f 1f c0        NOP        EAX  
       00106e5c 0f 1f c0        NOP        EAX  
       00106e5f 0f 1f c0        NOP        EAX  
       00106e62 0f 1f c0        NOP        EAX  
       00106e65 0f 1f c0        NOP        EAX  
       00106e68 0f 1f c0        NOP        EAX  
       00106e6b 48 89 45 f8     MOV        qword ptr [RBP + -0x8],RAX  
       00106e6f 48 31 c0        XOR        RAX,RAX  
       00106e72 8a 07           MOV        AL,byte ptr [RDI]  
       00106e74 48 ff c7        INC        RDI  
       00106e77 ba 03 00        MOV        EDX,0x3  
                00 00  
       00106e7c 48 f7 e2        MUL        RDX  
       00106e7f 48 89 c1        MOV        RCX,RAX  
       00106e82 48 8b 45 f8     MOV        RAX,qword ptr [RBP + -0x8]  
       00106e86 48 8d 15        LEA        RDX,[LAB_00106e92]  
                05 00 00 00  
       00106e8d 48 01 d1        ADD        RCX,RDX  
       00106e90 ff e1           JMP        RCX  
```  
Copy and pasting the entire disassembly into a text editor, we just need to
parse it out. This should do.  
```  
for line in fat.split('\n'):  
   if 'DEC' in line:  
       dec += 1  
   else:  
       if dec > 0:  
           print(f'DEC ENDS HERE {dec} NUMBER OF DECS')  
           dec_list.append(dec)  
       dec = 0  
print(''.join([chr(x) for x in dec_list]))  
```  
flag{i_r3a1ly_h0pe_you_d1dnt_d0_a1l_th1s_jump1ng_by_h4nd}

## Flag:  
flag{i_r3a1ly_h0pe_you_d1dnt_d0_a1l_th1s_jump1ng_by_h4nd}

Original writeup (https://github.com/idekctf/litctf-
writeups/blob/main/trampoline.md).