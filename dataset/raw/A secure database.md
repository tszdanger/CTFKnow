# A secure database

## Description

A friend of mine told me that he has an encrypted leaked database somewhere on
his server. He has been willing to give me a program to retrieve it, but he
did not give me the password used to decrypt the database. Can you find it?

He also told me that his program was super safe, and that I would not be able
to use my tools on it.

Creator : Nofix

## What are we dealing with?

```  
kali@kali:~/Downloads/secure_db$ ls -l  
total 24  
-rw-r--r-- 1 kali kali 21068 May  9 12:06 secure_db  
kali@kali:~/Downloads/secure_db$ file secure_db  
secure_db: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux.so.2, not stripped

kali@kali:~/Downloads/secure_db$ chmod +x secure_db  
kali@kali:~/Downloads/secure_db$ ./secure_db  
Usage : ./secure_db output_file  
kali@kali:~/Downloads/secure_db$ ./secure_db foo  
Hi Doge !  
░░░░░░░░░▄░░░░░░░░░░░░░░▄░░░░  
░░░░░░░░▌▒█░░░░░░░░░░░▄▀▒▌░░░  
░░░░░░░░▌▒▒█░░░░░░░░▄▀▒▒▒▐░░░  
░░░░░░░▐▄▀▒▒▀▀▀▀▄▄▄▀▒▒▒▒▒▐░░░  
░░░░░▄▄▀▒░▒▒▒▒▒▒▒▒▒█▒▒▄█▒▐░░░  
░░░▄▀▒▒▒░░░▒▒▒░░░▒▒▒▀██▀▒▌░░░  
░░▐▒▒▒▄▄▒▒▒▒░░░▒▒▒▒▒▒▒▀▄▒▒▌░░  
░░▌░░▌█▀▒▒▒▒▒▄▀█▄▒▒▒▒▒▒▒█▒▐░░  
░▐░░░▒▒▒▒▒▒▒▒▌██▀▒▒░░░▒▒▒▀▄▌░  
░▌░▒▄██▄▒▒▒▒▒▒▒▒▒░░░░░░▒▒▒▒▌░  
▀▒▀▐▄█▄█▌▄░▀▒▒░░░░░░░░░░▒▒▒▐░  
▐▒▒▐▀▐▀▒░▄▄▒▄▒▒▒▒▒▒░▒░▒░▒▒▒▒▌  
▐▒▒▒▀▀▄▄▒▒▒▄▒▒▒▒▒▒▒▒░▒░▒░▒▒▐░  
░▌▒▒▒▒▒▒▀▀▀▒▒▒▒▒▒░▒░▒░▒░▒▒▒▌░  
░▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒░▒░▒░▒▒▄▒▒▐░░  
░░▀▄▒▒▒▒▒▒▒▒▒▒▒░▒░▒░▒▄▒▒▒▒▌░░  
░░░░▀▄▒▒▒▒▒▒▒▒▒▒▄▄▄▀▒▒▒▒▄▀░░░  
░░░░░░▀▄▄▄▄▄▄▀▀▀▒▒▒▒▒▄▄▀░░░░░  
░░░░░░░░░▒▒▒▒▒▒▒▒▒▒▀▀░░░░░░░░  
Please input the password :  
-> hello  
ok  
Wrong password sorry, exiting.  
```

It's a 32-bit executable that takes a single filename argument and a single
password via STDIN.

## Analysis

Open the binary in Ghidra and find where the input is accepted.

```c  
undefined4 FUN_0804870a(void)  
{  
 size_t sVar1;  
 undefined4 uVar2;  
 int *in_ECX;  
 int in_GS_OFFSET;  
 bool bVar3;  
 undefined4 local_30;  
 undefined4 local_2c;  
 undefined4 local_28;  
 undefined4 local_24;  
 int local_20;  
 undefined4 uStack24;  
 int *local_14;  
  
 uStack24 = 0x8048716;  
 local_20 = *(int *)(in_GS_OFFSET + 0x14);  
 local_14 = in_ECX;  
 if (*in_ECX != 2) {  
   __printf_chk();  
                   /* WARNING: Subroutine does not return */  
   exit(1);  
 }  
 _DAT_0804d0a4 = FUN_08048b70();  
 local_30 = 0;  
 local_2c = 0;  
 local_28 = 0;  
 local_24 = 0;  
 __printf_chk();  
 fgets(&DAT_0804d0c0,0x50,*(FILE **)PTR_stdin_0804cffc);  
 sVar1 = strcspn(&DAT_0804d0c0,"\n");  
 (&DAT_0804d0c0)[sVar1] = 0;  
 strncpy((char *)&local_30,&DAT_0804d0c0,0x10);  
 bVar3 = false;  
 FUN_08048a90();  
 if (bVar3) {  
   puts("ok");  
   if (((((DAT_0804d0c0 == *PTR_DAT_0804d068) && (DAT_0804d0c1 ==
PTR_DAT_0804d068[1])) &&  
        (DAT_0804d0c2 == PTR_DAT_0804d068[2])) &&  
       (((DAT_0804d0c3 == PTR_DAT_0804d068[3] && (DAT_0804d0c4 == PTR_DAT_0804d068[4])) &&  
        ((DAT_0804d0c5 == PTR_DAT_0804d068[5] &&  
         ((DAT_0804d0c6 == PTR_DAT_0804d068[6] && (DAT_0804d0c7 == PTR_DAT_0804d068[7])))))))) &&  
      ((DAT_0804d0c8 == PTR_DAT_0804d068[8] &&  
       (((((DAT_0804d0c9 == PTR_DAT_0804d068[9] && (DAT_0804d0ca == PTR_DAT_0804d068[10])) &&  
          (DAT_0804d0cb == PTR_DAT_0804d068[0xb])) &&  
         ((DAT_0804d0cc == PTR_DAT_0804d068[0xc] && (DAT_0804d0cd == PTR_DAT_0804d068[0xd])))) &&  
        (DAT_0804d0ce == PTR_DAT_0804d068[0xe])))))) {  
     puts("The password is valid.");  
     FUN_08048c60();  
     puts("Received and *hopefully* sucessfuly decrypted the database with the given password.");  
     uVar2 = 0;  
   }  
   else {  
     puts("Wrong password sorry, exiting.");  
     uVar2 = 1;  
   }  
   if (local_20 != *(int *)(in_GS_OFFSET + 0x14)) {  
     FUN_0804a460();  
     __libc_start_main();  
     do {  
                   /* WARNING: Do nothing block with infinite loop */  
     } while( true );  
   }  
   return uVar2;  
 }  
 func_0x8b927754();  
                   /* WARNING: Bad instruction - Truncating control flow here */  
 halt_baddata();  
}  
```

That's just an ugly looking string comparison. What's in `PTR_DAT_0804d068`?

```  
                            PTR_DAT_0804d068                                XREF[1]:     FUN_0804870a:080487ec(R)    
       0804d068 e4 ac 04 08     addr       DAT_0804ace4                                     = 4Eh  
       0804d06c f5 ac 04 08     addr       s_You_can't_debug_me_:*_0804acf5                 = "You can't debug me :*"

What's in DAT_0804ace4?

                            DAT_0804ace4                                    XREF[2]:     FUN_0804870a:080487f5(R),   
                                                                                         0804d068(*)    
       0804ace4 4e              undefined1 4Eh  
                            DAT_0804ace5                                    XREF[1]:     FUN_0804870a:08048804(R)    
       0804ace5 33              undefined1 33h  
                            DAT_0804ace6                                    XREF[1]:     FUN_0804870a:08048814(R)    
       0804ace6 6b              undefined1 6Bh  
                            DAT_0804ace7                                    XREF[1]:     FUN_0804870a:08048824(R)    
       0804ace7 76              undefined1 76h  
                            DAT_0804ace8                                    XREF[1]:     FUN_0804870a:08048834(R)    
       0804ace8 69              undefined1 69h  
                            DAT_0804ace9                                    XREF[1]:     FUN_0804870a:08048844(R)    
       0804ace9 58              undefined1 58h  
                            DAT_0804acea                                    XREF[1]:     FUN_0804870a:08048854(R)    
       0804acea 37              undefined1 37h  
                            DAT_0804aceb                                    XREF[1]:     FUN_0804870a:08048864(R)    
       0804aceb 2d              undefined1 2Dh  
                            DAT_0804acec                                    XREF[1]:     FUN_0804870a:08048874(R)    
       0804acec 76              undefined1 76h  
                            DAT_0804aced                                    XREF[1]:     FUN_0804870a:08048884(R)    
       0804aced 58              undefined1 58h  
                            DAT_0804acee                                    XREF[1]:     FUN_0804870a:08048890(R)    
       0804acee 45              undefined1 45h  
                            DAT_0804acef                                    XREF[1]:     FUN_0804870a:0804889c(R)    
       0804acef 71              undefined1 71h  
                            DAT_0804acf0                                    XREF[1]:     FUN_0804870a:080488a8(R)    
       0804acf0 76              undefined1 76h  
                            DAT_0804acf1                                    XREF[1]:     FUN_0804870a:080488b4(R)    
       0804acf1 6c              undefined1 6Ch  
                            DAT_0804acf2                                    XREF[1]:     FUN_0804870a:080488c0(R)    
       0804acf2 70              undefined1 70h  
       0804acf3 00              ??         00h  
       0804acf4 00              ??         00h  
```

In ASCII, that comes out to `N3kviX7-vXEqvlp`.

```  
kali@kali:~/Downloads/secure_db$ perl -e 'print
"\x4e\x33\x6B\x76\x69\x58\x37\x2d\x76\x58\x45\x71\x76\x6c\x70\n"'  
N3kviX7-vXEqvlp  
```

Is that the password?

```  
kali@kali:~/Downloads/secure_db$ ./secure_db foo  
Hi Doge !  
░░░░░░░░░▄░░░░░░░░░░░░░░▄░░░░  
░░░░░░░░▌▒█░░░░░░░░░░░▄▀▒▌░░░  
░░░░░░░░▌▒▒█░░░░░░░░▄▀▒▒▒▐░░░  
░░░░░░░▐▄▀▒▒▀▀▀▀▄▄▄▀▒▒▒▒▒▐░░░  
░░░░░▄▄▀▒░▒▒▒▒▒▒▒▒▒█▒▒▄█▒▐░░░  
░░░▄▀▒▒▒░░░▒▒▒░░░▒▒▒▀██▀▒▌░░░  
░░▐▒▒▒▄▄▒▒▒▒░░░▒▒▒▒▒▒▒▀▄▒▒▌░░  
░░▌░░▌█▀▒▒▒▒▒▄▀█▄▒▒▒▒▒▒▒█▒▐░░  
░▐░░░▒▒▒▒▒▒▒▒▌██▀▒▒░░░▒▒▒▀▄▌░  
░▌░▒▄██▄▒▒▒▒▒▒▒▒▒░░░░░░▒▒▒▒▌░  
▀▒▀▐▄█▄█▌▄░▀▒▒░░░░░░░░░░▒▒▒▐░  
▐▒▒▐▀▐▀▒░▄▄▒▄▒▒▒▒▒▒░▒░▒░▒▒▒▒▌  
▐▒▒▒▀▀▄▄▒▒▒▄▒▒▒▒▒▒▒▒░▒░▒░▒▒▐░  
░▌▒▒▒▒▒▒▀▀▀▒▒▒▒▒▒░▒░▒░▒░▒▒▒▌░  
░▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒░▒░▒░▒▒▄▒▒▐░░  
░░▀▄▒▒▒▒▒▒▒▒▒▒▒░▒░▒░▒▄▒▒▒▒▌░░  
░░░░▀▄▒▒▒▒▒▒▒▒▒▒▄▄▄▀▒▒▒▒▄▀░░░  
░░░░░░▀▄▄▄▄▄▄▀▀▀▒▒▒▒▒▄▄▀░░░░░  
░░░░░░░░░▒▒▒▒▒▒▒▒▒▒▀▀░░░░░░░░  
Please input the password :  
-> N3kviX7-vXEqvlp  
ok  
Wrong password sorry, exiting.  
```

That didn't work, so there must be some transformation.  
Before the string comparison, we get the input from STDIN here:

```c  
 fgets(&DAT_0804d0c0,0x50,*(FILE **)PTR_stdin_0804cffc);  
 sVar1 = strcspn(&DAT_0804d0c0,"\n");  
 (&DAT_0804d0c0)[sVar1] = 0;  
 strncpy((char *)&local_30,&DAT_0804d0c0,0x10);  
 bVar3 = false;  
 FUN_08048a90();  
 if (bVar3) {  
```

It takes the string and replaces \n with a NULL terminator.  
The buffer is 16 bytes (15 chars + '\0')

What does `FUN_08048a90()` do?  
The decompiled C code is useless:

```c  
void FUN_08048a90(void)  
{  
 return;  
}  
```

Here's the disassembly:

```  
                            **************************************************************  
                            *                          FUNCTION                          *  
                            **************************************************************  
                            undefined FUN_08048a90()  
            undefined         AL:1           <RETURN>  
            undefined4        Stack[-0x14]:4 local_14                                XREF[1]:     08048aa4(*)    
                            FUN_08048a90                                    XREF[1]:     FUN_0804870a:080487d4(c)    
       08048a90 55              PUSH       EBP  
       08048a91 57              PUSH       EDI  
       08048a92 e8 2e 05        CALL       __i686.get_pc_thunk.cx                           undefined __i686.get_pc_thunk.cx()  
                00 00  
       08048a97 81 c1 69        ADD        ECX,0x4569  
                45 00 00  
       08048a9d 56              PUSH       ESI  
       08048a9e 53              PUSH       EBX  
       08048a9f e8 00 00        CALL       LAB_08048aa4  
                00 00  
                            LAB_08048aa4                                    XREF[1]:     08048a9f(j)    
       08048aa4 83 04 24 05     ADD        dword ptr [ESP]=>local_14,offset LAB_08048aa9  
       08048aa8 c3              RET  
                            LAB_08048aa9                                    XREF[1]:     FUN_08048a90:08048aa4(*)    
       08048aa9 8d b9 c0        LEA        EDI,[ECX + 0xc0]  
                00 00 00  
       08048aaf 89 fe           MOV        ESI,EDI  
       08048ab1 eb 0d           JMP        LAB_08048ac0  
       08048ab3 90              ??         90h  
       08048ab4 90              ??         90h  
       08048ab5 90              ??         90h  
       08048ab6 90              ??         90h  
       08048ab7 90              ??         90h  
       08048ab8 90              ??         90h  
       08048ab9 90              ??         90h  
       08048aba 90              ??         90h  
       08048abb 90              ??         90h  
       08048abc 90              ??         90h  
       08048abd 90              ??         90h  
       08048abe 90              ??         90h  
       08048abf 90              ??         90h  
                            LAB_08048ac0                                    XREF[2]:     08048ab1(j), 08048ad4(j)    
       08048ac0 8b 16           MOV        EDX,dword ptr [ESI]  
       08048ac2 83 c6 04        ADD        ESI,0x4  
       08048ac5 8d 82 ff        LEA        EAX,[EDX + 0xfefefeff]  
                fe fe fe  
       08048acb f7 d2           NOT        EDX  
       08048acd 21 d0           AND        EAX,EDX  
       08048acf 25 80 80        AND        EAX,0x80808080  
                80 80  
       08048ad4 74 ea           JZ         LAB_08048ac0  
       08048ad6 89 c2           MOV        EDX,EAX  
       08048ad8 c1 ea 10        SHR        EDX,0x10  
       08048adb a9 80 80        TEST       EAX,0x8080  
                00 00  
       08048ae0 0f 44 c2        CMOVZ      EAX,EDX  
       08048ae3 8d 56 02        LEA        EDX,[ESI + 0x2]  
       08048ae6 0f 44 f2        CMOVZ      ESI,EDX  
       08048ae9 89 c2           MOV        EDX,EAX  
       08048aeb 00 c2           ADD        DL,AL  
       08048aed 83 de 03        SBB        ESI,0x3  
       08048af0 29 fe           SUB        ESI,EDI  
       08048af2 74 3c           JZ         LAB_08048b30  
       08048af4 0f b6 a9        MOVZX      EBP,byte ptr [ECX + 0xa0]  
                a0 00 00 00  
       08048afb 31 db           XOR        EBX,EBX  
       08048afd 8d 76 00        LEA        ESI,[ESI]  
                            LAB_08048b00                                    XREF[1]:     08048b25(j)    
       08048b00 89 d8           MOV        EAX,EBX  
       08048b02 31 d2           XOR        EDX,EDX  
       08048b04 89 d9           MOV        ECX,EBX  
       08048b06 f7 f6           DIV        ESI  
       08048b08 8b 44 24 14     MOV        EAX,dword ptr [ESP + 0x14]  
       08048b0c 83 e1 03        AND        ECX,0x3  
       08048b0f 83 c3 01        ADD        EBX,0x1  
       08048b12 c1 e1 03        SHL        ECX,0x3  
       08048b15 d3 f8           SAR        EAX,CL  
       08048b17 89 c1           MOV        ECX,EAX  
       08048b19 89 e8           MOV        EAX,EBP  
       08048b1b 32 04 17        XOR        AL,byte ptr [EDI + EDX*0x1]  
       08048b1e 31 c8           XOR        EAX,ECX  
       08048b20 39 de           CMP        ESI,EBX  
       08048b22 88 04 17        MOV        byte ptr [EDI + EDX*0x1],AL  
       08048b25 75 d9           JNZ        LAB_08048b00  
       08048b27 89 f6           MOV        ESI,ESI  
       08048b29 8d bc 27        LEA        EDI,[EDI]  
                00 00 00 00  
                            LAB_08048b30                                    XREF[1]:     08048af2(j)    
       08048b30 5b              POP        EBX  
       08048b31 5e              POP        ESI  
       08048b32 5f              POP        EDI  
       08048b33 5d              POP        EBP  
       08048b34 c3              RET  
       08048b35 8d              ??         8Dh  
       08048b36 74              ??         74h    t  
       08048b37 26              ??         26h    &  
       08048b38 00              ??         00h  
       08048b39 8d              ??         8Dh  
       08048b3a bc              ??         BCh  
       08048b3b 27              ??         27h    '  
       08048b3c 00              ??         00h  
       08048b3d 00              ??         00h  
       08048b3e 00              ??         00h  
       08048b3f 00              ??         00h  
       08048b40 53              ??         53h    S  
       08048b41 e8              ??         E8h  
       08048b42 7a              ??         7Ah    z  
       08048b43 fe              ??         FEh  
       08048b44 ff              ??         FFh  
       08048b45 ff              ??         FFh  
       08048b46 81              ??         81h  
       08048b47 c3              ??         C3h  
       08048b48 ba              ??         BAh  
       08048b49 44              ??         44h    D  
       08048b4a 00              ??         00h  
       08048b4b 00              ??         00h  
       08048b4c 83              ??         83h  
       08048b4d ec              ??         ECh  
       08048b4e 14              ??         14h  
       08048b4f ff              ??         FFh  
       08048b50 74              ??         74h    t  
       08048b51 24              ??         24h    $  
       08048b52 1c              ??         1Ch  
       08048b53 e8              ??         E8h  
       08048b54 f8              ??         F8h  
       08048b55 fa              ??         FAh  
       08048b56 ff              ??         FFh  
       08048b57 ff              ??         FFh  
       08048b58 83              ??         83h  
       08048b59 f8              ??         F8h  
       08048b5a 0f              ??         0Fh  
       08048b5b 0f              ??         0Fh  
       08048b5c 94              ??         94h  
       08048b5d 83              ??         83h  
       08048b5e 64              ??         64h    d  
       08048b5f 00              ??         00h  
       08048b60 00              ??         00h  
       08048b61 00              ??         00h  
       08048b62 83              ??         83h  
       08048b63 c4              ??         C4h  
       08048b64 18              ??         18h  
       08048b65 5b              ??         5Bh    [  
       08048b66 c3              ??         C3h  
       08048b67 89              ??         89h  
       08048b68 f6              ??         F6h  
       08048b69 8d              ??         8Dh  
       08048b6a bc              ??         BCh  
       08048b6b 27              ??         27h    '  
       08048b6c 00              ??         00h  
       08048b6d 00              ??         00h  
       08048b6e 00              ??         00h  
       08048b6f 00              ??         00h  
```

That's... something I guess. It's probably faster to solve this 1 character at
a time than to understand WTF this is doing.

Let's try `angr` to solve this.

## Solution

```python  
#!/usr/bin/env python3  
import angr, time, claripy

BINARY='./secure_db'  
OUTFILE='out.db'  
t=time.time()  
proj = angr.Project(BINARY, auto_load_libs=False)  
print(proj.arch)  
print(proj.filename)  
print("Entry: 0x%x" % proj.entry)

FIND=0x080488d6 # puts("The password is valid.");  
AVOID=0x0804890a # puts("Wrong password sorry, exiting.");  
print("Find: 0x%x" % FIND)  
print("Avoid: 0x%x" % AVOID)

password = claripy.BVS('password', 8 * 16)  
state = proj.factory.entry_state(args=[BINARY, OUTFILE], stdin=password)  
simgr = proj.factory.simulation_manager(state)  
simgr.explore(find=FIND, avoid=AVOID)

print(simgr.found[0].posix.dumps(0))  
print(time.time() - t, "seconds")  
```

```  
kali@kali:~/Downloads/secure_db$ ./solve.py  
ERROR   | 2020-05-09 17:06:30,010 | cle.backends.elf.elf | PyReadELF couldn't load this file. Trying again without section headers...                                                                     
<Arch X86 (LE)>  
./secure_db  
Entry: 0x8048970  
Find: 0x80488d6  
Avoid: 0x804890a  
WARNING | 2020-05-09 17:06:30,327 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.                   
WARNING | 2020-05-09 17:06:30,327 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:               
WARNING | 2020-05-09 17:06:30,327 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state                                                                                          
WARNING | 2020-05-09 17:06:30,327 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null                         
WARNING | 2020-05-09 17:06:30,327 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.                             
WARNING | 2020-05-09 17:06:30,327 | angr.state_plugins.symbolic_memory | Filling register edi with 4 unconstrained bytes referenced from 0x804a3f1 (PLT.close+0x1d11 in secure_db (0x804a3f1))            
b'T4h7s_4ll_F0lks\x00'  
175.94404363632202 seconds  
```

That's pretty freakin' incredible. This was my first time using angr, and it
could have saved me hours on previous CTF challenges like this.

Now that we have the password, pass it into `secure_db`.

```  
kali@kali:~/Downloads/secure_db$ echo 'T4h7s_4ll_F0lks' > pass  
kali@kali:~/Downloads/secure_db$ ./secure_db out.db < pass  
Hi Doge !  
░░░░░░░░░▄░░░░░░░░░░░░░░▄░░░░  
░░░░░░░░▌▒█░░░░░░░░░░░▄▀▒▌░░░  
░░░░░░░░▌▒▒█░░░░░░░░▄▀▒▒▒▐░░░  
░░░░░░░▐▄▀▒▒▀▀▀▀▄▄▄▀▒▒▒▒▒▐░░░  
░░░░░▄▄▀▒░▒▒▒▒▒▒▒▒▒█▒▒▄█▒▐░░░  
░░░▄▀▒▒▒░░░▒▒▒░░░▒▒▒▀██▀▒▌░░░  
░░▐▒▒▒▄▄▒▒▒▒░░░▒▒▒▒▒▒▒▀▄▒▒▌░░  
░░▌░░▌█▀▒▒▒▒▒▄▀█▄▒▒▒▒▒▒▒█▒▐░░  
░▐░░░▒▒▒▒▒▒▒▒▌██▀▒▒░░░▒▒▒▀▄▌░  
░▌░▒▄██▄▒▒▒▒▒▒▒▒▒░░░░░░▒▒▒▒▌░  
▀▒▀▐▄█▄█▌▄░▀▒▒░░░░░░░░░░▒▒▒▐░  
▐▒▒▐▀▐▀▒░▄▄▒▄▒▒▒▒▒▒░▒░▒░▒▒▒▒▌  
▐▒▒▒▀▀▄▄▒▒▒▄▒▒▒▒▒▒▒▒░▒░▒░▒▒▐░  
░▌▒▒▒▒▒▒▀▀▀▒▒▒▒▒▒░▒░▒░▒░▒▒▒▌░  
░▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒░▒░▒░▒▒▄▒▒▐░░  
░░▀▄▒▒▒▒▒▒▒▒▒▒▒░▒░▒░▒▄▒▒▒▒▌░░  
░░░░▀▄▒▒▒▒▒▒▒▒▒▒▄▄▄▀▒▒▒▒▄▀░░░  
░░░░░░▀▄▄▄▄▄▄▀▀▀▒▒▒▒▒▄▄▀░░░░░  
░░░░░░░░░▒▒▒▒▒▒▒▒▒▒▀▀░░░░░░░░  
Please input the password :  
-> ok  
The password is valid.  
Contacting server  
Retrieving to DB, decrypting it using your password.  
File downloaded. 32768 bytes.  
Done. Check your output file.  
Received and *hopefully* sucessfuly decrypted the database with the given
password.  
```

Now that we have the file, we can see that it is a SQLite DB. It's small, so
running `.dump` is an easy way to find where the flag is.

```  
kali@kali:~/Downloads/secure_db$ file out.db  
out.db: SQLite 3.x database, last written using SQLite version 3022000  
kali@kali:~/Downloads/secure_db$ sqlite3 out.db  
SQLite version 3.31.0 2019-12-29 00:52:41  
Enter ".help" for usage hints.  
sqlite> .dump  
...  
sqlite> select * from flag;  
shkCTF{p4ssw0rd_pr0t3ct3d_db_6a773d0fcb5d742603167d2958547914}  
```

Original writeup
(https://github.com/dobsonj/ctf/tree/master/writeups/2020/sharkyctf/secure_db).