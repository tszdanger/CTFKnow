## 0CTF 2020 - baby MIPS (Reversing 297)  
##### 29/06 - 01/07/2020 (48hr)  
___

### Description

-  
___

We have a binary in
[nanoMIPS](https://www.mips.com/products/architectures/nanomips) architecture.
We can  
infer this from the output of `file` command:  
```  
ispo@ispo-glaptop:~/ctf/0ctf/babymips$ ./babymips  
   bash: ./babymips: cannot execute binary file: Exec format error  
ispo@ispo-glaptop:~/ctf/0ctf/babymips$ file babymips  
   babymips: ELF 32-bit LSB executable, *unknown arch 0xf9* version 1 (SYSV),
dynamically linked, interpreter /lib/ld-musl-nanomips-sf.so.1, stripped  
```

This is a fairly new architecture used in **I7200** processor. There is a mail
named  
[Introducing a nanoMIPS port for GCC](https://gcc.gnu.org/legacy-
ml/gcc/2018-05/msg00012.html)  
where it provides some information about the architecture. Furthermore, the  
[Reference Manual](https://s3-eu-west-1.amazonaws.com/downloads-
mips/I7200/I7200+product+launch/MIPS_nanomips32_ISA_TRM_01_01_MD01247.pdf)  
and the [Datasheet](https://cdn.weka-
fachmedien.de/media_uploads/documents/1525340900-291-mips-i7200-datasheet-01-20-md01227.pdf)  
are two useful resources.

After some searching we found a
[toolchain](https://codescape.mips.com/components/toolchain/nanomips/2018.04-02/downloads.html)  
for nanomips binaries. First we run `readelf`. The most important fields are
shown below:  
```  
ispo@ispo-glaptop:~/ctf/0ctf/babymips/nanomips-linux-musl/2018.04-02/bin$
./nanomips-linux-musl-readelf --all ../../../babymips  
ELF Header:  
 Entry point address:               0x4003f6

Section Headers:  
 [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf
Al  
 [ 0]                   NULL            00000000 000000 000000 00      0   0
0  
 [ 6] .rel.nanoMIPS.stu REL             004003a0 0003a0 000028 08  AI  2   8
4  
 [ 8] .nanoMIPS.stubs   PROGBITS        004003d0 0003d0 000026 00  AX  0   0
4  
 [ 9] .text             PROGBITS        004003f6 0003f6 000398 00  AX  0   0
2  
 [11] .rodata           PROGBITS        00400798 000798 00007e 00   A  0   0
4  
 [12] .nanoMIPS.abiflag LOPROC+0        00400818 000818 000018 00   A  0   0
8  
 [15] .init_array       INIT_ARRAY      0041ff24 00ff24 000004 04  WA  0   0
4  
 [16] .fini_array       FINI_ARRAY      0041ff28 00ff28 000004 04  WA  0   0
4  
 [17] .jcr              PROGBITS        0041ff2c 00ff2c 000004 00  WA  0   0
4  
 [19] .data             PROGBITS        00420000 010000 0000a5 00  WA  0   0
4  
 [21] .sdata            PROGBITS        004200a8 0100a8 000004 00  WA  0   0
4  
 [22] .got              PROGBITS        004200ac 0100ac 000038 00 WAp  0   0
4  
 [23] .bss              NOBITS          004200e4 0100e4 00001c 00  WA  0   0
4

Entries:  
 Address       Access   Value     Type        Name  
004200b4        8(gp)  00400790  
004200b8       12(gp)  004003c8  
004200bc       16(gp)  00000000  Global      _ITM_deregisterTMCloneTable  
004200c0       20(gp)  00000000  Global      _ITM_registerTMCloneTable  
004200c4       24(gp)  00000000  Global      __deregister_frame_info  
004200c8       28(gp)  00000000  Global      __register_frame_info  
004200cc       32(gp)  00000000  Global      _Jv_RegisterClasses  
004200d0       36(gp)  004003d0  Lazy-stub   read  
004200d4       40(gp)  004003d6  Lazy-stub   strncmp  
004200d8       44(gp)  004003dc  Lazy-stub   puts  
004200dc       48(gp)  004003e2  Lazy-stub   memset  
004200e0       52(gp)  004003e8  Lazy-stub   __libc_start_main  
```

Then we load the binary on `gdb`. Obviously we cannot debug it, but we can get
a nice  
disassembly listing of the `.text` section. Below is the analyzed assembly of
the binary:  
```Assembly  
(gdb) disas 0x4003d0, 0x40078e  
Dump of assembler code from 0x4003d0 to 0x40078e:  
  0x004003d0:   li      t8,0                    ;  
  0x004003d4:   bc      0x4003ee                ;  
  0x004003d6:   li      t8,1                    ;  
  0x004003da:   bc      0x4003ee                ;  
  0x004003dc:   li      t8,2                    ;  
  0x004003e0:   bc      0x4003ee                ;  
  0x004003e2:   li      t8,3                    ;  
  0x004003e6:   bc      0x4003ee                ;  
  0x004003e8:   li      t8,4                    ;  
  0x004003ec:   bc      0x4003ee                ;  
  0x004003ee:   lw      t9,0(gp)                ;  
  0x004003f2:   move    t3,ra               ;  
  0x004003f4:   jalrc   t9                  ;

PROG_ENTRY_POINT:  
  0x004003f6:   move    fp,zero             ;  
  0x004003f8:   lapc    t0,0x400410         ;  
  0x004003fc:   lapc    a1,0x41ff30         ; a1 = .dynamic  
  0x00400400:   lapc    gp,0x4200ac         ; gp = .got  
  0x00400404:   move    a0,sp               ;  
  0x00400406:   li      at,-16                  ;  
  0x0040040a:   and     sp,sp,at                ;  
  0x0040040e:   jalrc   t0                  ;

INITIALIZATION:  
  0x00400410:   save    16,ra,gp  
  0x00400414:   lapc    gp,0x4200ac         ; gp = .got  
  0x00400418:   addiu   a2,a0,4             ; a2 = a0 + 4  
  0x0040041a:   lw      a1,0(a0)                ;  
  0x0040041c:   lw      a6,52(gp)               ; a6 = .got + 0x34 =
__libc_start_main  
  0x00400420:   lapc    a0,0x4006e4         ; a0 = &main  
  0x00400424:   move    a5,zero             ; a5 = 0  
  0x00400426:   lwpc    a4,0x4200b4         ; a4 = 0x4200b4 -> 0x400790  
  0x0040042c:   lwpc    a3,0x4200b8         ; a3 = 0x4200b8 -> 0x4003c8  
  0x00400432:   jalrc   a6

  ;
---------------------------------------------------------------------------  
  ; .ctors (we don't care)  
  ;
---------------------------------------------------------------------------  
  0x00400434:   lapc    a3,0x4200a8         ; a3 = 0x4200a8  
  0x00400438:   lapc    a0,0x4200a8         ; a0 = 0x4200a8  
  0x0040043c:   addiu   a3,a3,3             ; a3 += 3  
  0x0040043e:   subu    a3,a3,a0            ; a3 -= a0  
  0x00400440:   bltiuc  a3,7,0x40044e       ; if a3 < 7 goto 0x40044e  
  0x00400444:   lwpc    a3,0x4200bc         ; a3 = _ITM_deregisterTMClone  
  0x0040044a:   beqzc   a3,0x40044e         ; if a3 == 0 goto 0x40044e  
  0x0040044c:   jrc     a3                      ;  
  0x0040044e:   jrc     ra                      ;  
  0x00400450:   lapc    a0,0x4200a8         ;  
  0x00400454:   li      a2,2                    ;  
  0x00400456:   lapc    a3,0x4200a8         ;  
  0x0040045a:   subu    a3,a3,a0            ;  
  0x0040045c:   sra     a3,a3,2                 ; a3 /= 2  
  0x00400460:   div     a1,a3,a2                ; a1 = a3 / a2  
  0x00400464:   beqzc   a1,0x400470         ;  
  0x00400466:   lwpc    a3,0x4200c0         ;  
  0x0040046c:   beqzc   a3,0x400470         ;  
  0x0040046e:   jrc     a3                      ;

  0x00400470:   jrc     ra                      ;  
  0x00400472:   save    16,ra,s0            ;  
  0x00400474:   aluipc  a3,0x420000         ;  
  0x00400478:   lbu     a2,228(a3)              ;  
  0x0040047c:   move    s0,a3               ;  
  0x0040047e:   bnezc   a2,0x400496         ;  
  0x00400480:   balc    0x400434            ; Function call  
  0x00400482:   lwpc    a3,0x4200c4         ;  
  0x00400488:   beqzc   a3,0x400490         ;  
  0x0040048a:   lapc    a0,0x400830         ;  
  0x0040048e:   jalrc   a3                  ;  
  0x00400490:   li      a3,1                    ;  
  0x00400492:   sb      a3,228(s0)              ;  
  0x00400496:   restore.jrc     16,ra,s0        ;  
  0x00400498:   save    16,ra               ;  
  0x0040049a:   lwpc    a3,0x4200c8         ;  
  0x004004a0:   beqzc   a3,0x4004ac         ;  
  0x004004a2:   lapc    a1,0x4200e8         ;  
  0x004004a6:   lapc    a0,0x400830         ;  
  0x004004aa:   jalrc   a3                  ;  
  0x004004ac:   lapc    a0,0x41ff2c         ;  
  0x004004b0:   lw      a3,0(a0)                ;  
  0x004004b2:   bnezc   a3,0x4004ba         ;

  0x004004b4:   restore 16,ra               ;  
  0x004004b8:   bc      0x400450                ; goto LOOP  
  0x004004ba:   lwpc    a3,0x4200cc         ; a3 = 0x4200cc  
  0x004004c0:   beqzc   a3,0x4004b4         ;  
  0x004004c2:   jalrc   a3                  ;  
  0x004004c4:   bc      0x4004b4                ; return

  ;
---------------------------------------------------------------------------  
  ; is_valid_perm(byte *perm)  
  ;  
  ; Checks if a string is a valid permutation of 'zxcasdqwe'.  
  ;
---------------------------------------------------------------------------  
  0x004004c6:   save    80,fp,ra            ; prolog  
  0x004004c8:   addiu   fp,sp,-4016         ;  
  0x004004cc:   sw      a0,12(sp)               ; var_c = arg0  
  0x004004ce:   sw      zero,20(sp)             ; initialize vars  
  0x004004d0:   sw      zero,24(sp)             ;  
  0x004004d2:   sw      zero,28(sp)             ;  
  0x004004d4:   sw      zero,32(sp)             ;  
  0x004004d6:   sw      zero,36(sp)             ;  
  0x004004d8:   sw      zero,40(sp)             ;  
  0x004004da:   sw      zero,44(sp)             ;  
  0x004004dc:   sw      zero,48(sp)             ;  
  0x004004de:   sw      zero,52(sp)             ;  
  0x004004e0:   sw      zero,60(sp)             ;  
  0x004004e2:   bc      0x400550                ; goto LOOP_END

LOOP:  
  0x004004e4:   lw      a3,60(sp)               ; a3 = var_3c = i  
  0x004004e6:   lw      a2,12(sp)               ; a2 = arg0  
  0x004004e8:   addu    a3,a2,a3            ; a3 = &arg0[i]  
  0x004004ea:   lbu     a3,0(a3)                ; a3 = arg0[i] (byte)  
  0x004004ec:   addiu   a3,a3,-97           ; a3 = arg0[1] - 'a'  
  ; (gdb) x/26xw 0x400798  
  ; 0x400798:   0x0000000c      0x00000024      0x00000008      0x00000014  
  ; 0x4007a8:   0x00000020      0x00000024      0x00000024      0x00000024  
  ; 0x4007b8:   0x00000024      0x00000024      0x00000024      0x00000024  
  ; 0x4007c8:   0x00000024      0x00000024      0x00000024      0x00000024  
  ; 0x4007d8:   0x00000018      0x00000024      0x00000010      0x00000024  
  ; 0x4007e8:   0x00000024      0x00000024      0x0000001c      0x00000004  
  ; 0x4007f8:   0x00000024      0x00000000  
  ;  
  ; Offset:  
  ;  00 --> z  
  ;  04 --> x  
  ;  08 --> c  
  ;  0c --> a  
  ;  10 --> s  
  ;  14 --> d  
  ;  18 --> q  
  ;  1c --> w  
  ;  20 --> e  
  ;  24 --> b, f, g, h, i, j, k, l, m, n, o, p, t, u, v, y

  0x004004f0:   bgeiuc  a3,26,0x400546      ; if a3 >= 26 goto FAILURE  
  0x004004f4:   lapc    a2,0x400798         ; a2 = .rodata  
  0x004004f8:   lwxs    a2,a3(a2)           ; a2 = .rodata[a3] (dword)  
  0x004004fa:   brsc    a2                  ; goto 0x4004fe + a2*2 (switch)

CASE_OFF_00:  
  0x004004fe:   lw      a3,20(sp)               ;  
  0x00400500:   addiu   a3,a3,1             ; ++var_14  
  0x00400502:   sw      a3,20(sp)               ;  
  0x00400504:   bc      0x40054a                ; goto CASE_END

CASE_OFF_04:  
  0x00400506:   lw      a3,24(sp)               ;  
  0x00400508:   addiu   a3,a3,1             ; ++var_18  
  0x0040050a:   sw      a3,24(sp)               ;  
  0x0040050c:   bc      0x40054a                ; goto CASE_END

CASE_OFF_08:  
  0x0040050e:   lw      a3,28(sp)               ;  
  0x00400510:   addiu   a3,a3,1             ; ++var_1c  
  0x00400512:   sw      a3,28(sp)               ;  
  0x00400514:   bc      0x40054a                ; goto CASE_END

CASE_OFF_0C:  
  0x00400516:   lw      a3,32(sp)               ;  
  0x00400518:   addiu   a3,a3,1             ; ++var_20  
  0x0040051a:   sw      a3,32(sp)               ;  
  0x0040051c:   bc      0x40054a                ;

CASE_OFF_10:  
  0x0040051e:   lw      a3,36(sp)               ;  
  0x00400520:   addiu   a3,a3,1             ; ++var_24  
  0x00400522:   sw      a3,36(sp)               ;  
  0x00400524:   bc      0x40054a                ;

CASE_OFF_14:  
  0x00400526:   lw      a3,40(sp)               ;  
  0x00400528:   addiu   a3,a3,1             ; ++var_28  
  0x0040052a:   sw      a3,40(sp)               ;  
  0x0040052c:   bc      0x40054a                ;

CASE_OFF_18:  
  0x0040052e:   lw      a3,44(sp)               ;  
  0x00400530:   addiu   a3,a3,1             ; ++var_2c  
  0x00400532:   sw      a3,44(sp)               ;  
  0x00400534:   bc      0x40054a                ;

CASE_OFF_1C:  
  0x00400536:   lw      a3,48(sp)               ;  
  0x00400538:   addiu   a3,a3,1             ; ++var_30  
  0x0040053a:   sw      a3,48(sp)               ;  
  0x0040053c:   bc      0x40054a                ;

CASE_OFF_20:  
  0x0040053e:   lw      a3,52(sp)               ;  
  0x00400540:   addiu   a3,a3,1             ; ++var_34  
  0x00400542:   sw      a3,52(sp)               ;  
  0x00400544:   bc      0x40054a                ;

FAILURE:                                    ; or CASE_OFF_24:  
  0x00400546:   move    a3,zero             ; return 0  
  0x00400548:   bc      0x40057c                ;

CASE_END:  
  0x0040054a:   lw      a3,60(sp)               ;  
  0x0040054c:   addiu   a3,a3,1             ; var_3c += 1  
  0x0040054e:   sw      a3,60(sp)               ;

LOOP_END:  
  0x00400550:   lw      a3,60(sp)               ; a3 = var_3c  
  0x00400552:   bltic   a3,9,0x4004e4       ; if var_3c < 9 goto LOOP  
  0x00400556:   sw      zero,56(sp)             ; var_38 = 0  
  0x00400558:   bc      0x400574

LOOP_2:  
  0x0040055a:   lw      a3,56(sp)               ; a3 = var_38 = j  
  0x0040055c:   sll     a3,a3,2                 ; var_38 <<= 2 (j*4)  
  0x0040055e:   addiu   a2,sp,64            ;  
  0x00400560:   addu    a3,a2,a3            ; a3 = var_40[j] (dword)  
  0x00400562:   lw      a3,-44(a3)              ; a3 = 40[j] - 0x2c  
  0x00400566:   beqic   a3,1,0x40056e       ; if a3 == 1 goto NEXT_ITER  
  0x0040056a:   move    a3,zero             ; else return 0  
  0x0040056c:   bc      0x40057c                ;

NEXT_ITER:  
  0x0040056e:   lw      a3,56(sp)               ;  
  0x00400570:   addiu   a3,a3,1             ; ++var_38  
  0x00400572:   sw      a3,56(sp)               ;  
  0x00400574:   lw      a3,56(sp)               ;  
  0x00400576:   bltic   a3,9,0x40055a       ; if var_38 < 9 goto LOOP_2

SUCCESS:  
  0x0040057a:   li      a3,1                    ; return 1

RETURN:  
  0x0040057c:   move    a0,a3               ;  
  0x0040057e:   restore.jrc     80,fp,ra        ;

  ;
---------------------------------------------------------------------------  
  ; is_valid_double_perm()  
  ;  
  ; (gdb) x/100xb 0x420054 = tbl_B  (max val: 80)  
  ; 0x00        0x01    0x02    0x03    0x0a    0x0c    0x0d    0x0e    0x13  
  ; 0x04        0x05    0x06    0x0f    0x18    0x19    0x21    0x2a    0x33  
  ; 0x07        0x08    0x10    0x11    0x1a    0x22    0x23    0x2b    0x34  
  ; 0x09        0x12    0x1b    0x24    0x2d    0x36    0x37    0x3f    0x48  
  ; 0x0b        0x14    0x15    0x1c    0x1d    0x1e    0x25    0x2e    0x27  
  ; 0x16        0x17    0x1f    0x20    0x28    0x31    0x3a    0x42    0x43  
  ; 0x26        0x2f    0x30    0x38    0x39    0x40    0x41    0x49    0x4a  
  ; 0x29    0x32        0x3b    0x3c    0x3d    0x44    0x4b    0x4c    0x4d  
  ; 0x2c        0x35    0x3e    0x45    0x46    0x47    0x4e    0x4f    0x50  
  ;  
  ; (gdb) x/84xb 0x420000 = tbl_A  
  ; 0x00        0x00    0x77    0x00    0x00    0x00    0x73    0x00  
  ; 0x00        0x00    0x00    0x00    0x64    0x00    0x00    0x77  
  ; 0x00        0x00    0x64    0x00    0x00    0x00    0x00    0x00  
  ; 0x61        0x00    0x00    0x00    0x65    0x00    0x77    0x00  
  ; 0x71        0x00    0x61    0x00    0x65    0x00    0x00    0x00  
  ; 0x00        0x00    0x00    0x00    0x00    0x61    0x00    0x00  
  ; 0x7a        0x64    0x00    0x00    0x73    0x77    0x71    0x00  
  ; 0x00        0x00    0x00    0x77    0x00    0x00    0x73    0x78  
  ; 0x00        0x64    0x00    0x00    0x00    0x00    0x00    0x7a  
  ; 0x77        0x00    0x00    0x00    0x00    0x00    0x00    0x64  
  ; 0x78        0x00    0x00    0x00  
  ;  
  ; /** Decompiled Code **/  
  ; byte perm[9];  
  ;  
  ; for (int i=0; i<9; ++i) {  
  ;     for (int j=0; j<9; ++j) {  
  ;         perm[j] = tbl_A[tbl_B[9*i + j]];  
  ;     }  
  ;  
  ;     if (!is_valid_perm(perm))  
  ;         return 0;  
  ; }  
  ;  
  ; return 1;  
  ;
---------------------------------------------------------------------------  
  0x00400580:   save    48,fp,ra            ; prolog  
  0x00400584:   addiu   fp,sp,-4048         ;  
  0x00400588:   sw      zero,12(sp)             ;  
  0x0040058a:   sw      zero,16(sp)             ;  
  0x0040058c:   sb      zero,20(sp)             ;  
  0x00400590:   sw      zero,28(sp)             ;  
  0x00400592:   bc0x4005e0                ; goto LOOP_END:

LOOP:  
  0x00400594:   sw      zero,24(sp)             ; var_18 = 0 (j)  
  0x00400596:   bc      0x4005c6                ; goto INNER_LOOP_END

INNER_LOOP:  
  0x00400598:   lw      a2,28(sp)               ; a2 = var_1c (i)  
  0x0040059a:   move    a3,a2               ; a3 = i  
  0x0040059c:   sll     a3,a3,3                 ; a3 <<= 3  
  0x0040059e:   addu    a3,a3,a2            ; a3 = i*9  
  0x004005a0:   lapc    a2,0x420054         ; a2 = tbl_B  
  0x004005a4:   addu    a2,a3,a2            ; a2 = &tbl_B[9*i]  
  0x004005a6:   lw      a3,24(sp)               ;  
  0x004005a8:   addu    a3,a2,a3            ; a3 = &tbl_B[9*i + j]  
  0x004005aa:   lbu     a3,0(a3)                ; a3 = tbl_B[9*i + j] (byte)  
  0x004005ac:   move    a2,a3               ;  
  0x004005ae:   lapc    a3,0x420000         ; a3 = tbl_A  
  0x004005b2:   addu    a3,a2,a3            ;  
  0x004005b4:   lbu     a2,0(a3)                ; a2 = tbl_A[tbl_B[9*i + j]]

  0x004005b6:   lw      a3,24(sp)               ; a3 = var_18 (j)  
  0x004005b8:   addiu   a1,sp,32            ; a1 = var_20  
  0x004005ba:   addu    a3,a1,a3            ; a3 = &var_20[j]  
  0x004005bc:   sb      a2,-20(a3)              ; var_c[j] = tbl_A[tbl_B[9*i +
j]]

  0x004005c0:   lw      a3,24(sp)               ;  
  0x004005c2:   addiu   a3,a3,1             ; ++var_18 (j)  
  0x004005c4:   sw      a3,24(sp)               ;

INNER_LOOP_END:  
  0x004005c6:   lw      a3,24(sp)               ; a3 = var_18  
  0x004005c8:   bltic   a3,9,0x400598       ; if var_18 < 9 goto INNER_LOOP  
  0x004005cc:   addiu   a3,sp,12            ;  
  0x004005ce:   move    a0,a3               ;  
  0x004005d0:   balc    0x4004c6            ; retval = is_valid_perm(var_c)  
  0x004005d2:   move    a3,a0               ;  
  0x004005d4:   bnezc   a3,0x4005da         ; if retval != 0 goto NEXT_ITER  
  0x004005d6:   move    a3,zero             ;  
  0x004005d8:   bc      0x4005e8                ; return 0

NEXT_ITER:  
  0x004005da:   lw      a3,28(sp)               ;  
  0x004005dc:   addiu   a3,a3,1             ; ++var_1c (i)  
  0x004005de:   sw      a3,28(sp)               ;

LOOP_END:  
  0x004005e0:   lw      a3,28(sp)               ;  
  0x004005e2:   bltic   a3,9,0x400594       ; if var_1c < 9 goto LOOP  
  0x004005e6:   li      a3,1                    ;  
  0x004005e8:   move    a0,a3               ; return 1  
  0x004005ea:   restore.jrc     48,fp,ra        ;

  ;
---------------------------------------------------------------------------  
  ; is_valid_col_perm()  
  ;  
  ; /** Decompiled Code **/  
  ; for (int i=0; i<9; ++i) {  
  ;     for (int j=0; j<9; ++j) {  
  ;         perm[j] = tbl_A[9*j + i];  
  ;     }  
  ;  
  ;     if (!is_valid_perm(perm))  
  ;         return 0;  
  ; }  
  ;  
  ; return 1;  
  ;
---------------------------------------------------------------------------  
  0x004005ee:   save    48,fp,ra            ; prolog  
  0x004005f2:   addiu   fp,sp,-4048         ;  
  0x004005f6:   sw      zero,12(sp)             ;  
  0x004005f8:   sw      zero,16(sp)             ;  
  0x004005fa:   sb      zero,20(sp)             ;  
  0x004005fe:   sw      zero,28(sp)             ;  
  0x00400600:   bc      0x400644                ; goto LOOP_END  
LOOP:  
  0x00400602:   sw      zero,24(sp)             ; var_18 = 0 (j)  
  0x00400604:   bc      0x40062a                ; goto INNER_LOOP_END

INNER_LOOP:  
  0x00400606:   lw      a2,24(sp)               ;  
  0x00400608:   move    a3,a2               ;  
  0x0040060a:   sll     a3,a3,3                 ;  
  0x0040060c:   addu    a2,a3,a2            ; a2 = 9*j  
  0x0040060e:   lw      a3,28(sp)               ; a3 = i  
  0x00400610:   addu    a2,a2,a3            ;  
  0x00400612:   lapc    a3,0x420000         ;  
  0x00400616:   addu    a3,a2,a3            ;  
  0x00400618:   lbu     a2,0(a3)                ; a2 = tbl_A[9*j + i] (byte)  
  0x0040061a:   lw      a3,24(sp)               ;  
  0x0040061c:   addiu   a1,sp,32            ;  
  0x0040061e:   addu    a3,a1,a3            ;  
  0x00400620:   sb      a2,-20(a3)              ; var_c[j] = tbl_A[9*j + i]

  0x00400624:   lw      a3,24(sp)               ;  
  0x00400626:   addiu   a3,a3,1             ; ++j  
  0x00400628:   sw      a3,24(sp)               ;

INNER_LOOP_END:  
  0x0040062a:   lw      a3,24(sp)               ;  
  0x0040062c:   bltic   a3,9,0x400606       ; if j < 9 goto INNER_LOOP

  0x00400630:   addiu   a3,sp,12            ;  
  0x00400632:   move    a0,a3               ;  
  0x00400634:   balc    0x4004c6            ; retval = is_valid_perm(var_c)  
  0x00400636:   move    a3,a0               ;  
  0x00400638:   bnezc   a3,0x40063e         ; if retval == 0 goto
NEXT_INNER_ITER  
  0x0040063a:   move    a3,zero             ;  
  0x0040063c:   bc      0x40064c                ; goto FUNC_EPILOG & return 0

NEXT_INNER_ITER:  
  0x0040063e:   lw      a3,28(sp)               ;  
  0x00400640:   addiu   a3,a3,1             ; ++i  
  0x00400642:   sw      a3,28(sp)               ;

LOOP_END:  
  0x00400644:   lw      a3,28(sp)               ;  
  0x00400646:   bltic   a3,9,0x400602       ; if i < 9 goto LOOP  
  0x0040064a:   li      a3,1                    ; return 1

FUNC_EPILOG:  
  0x0040064c:   move    a0,a3               ; epilog  
  0x0040064e:   restore.jrc     48,fp,ra        ;

  ;
---------------------------------------------------------------------------  
  ; is_valid_row_perm()  
  ;  
  ; /** Decompiled Code **/  
  ; for (int i=0; i<9; ++i) {  
  ;     for (int j=0; j<9; ++j) {  
  ;         perm[j] = tbl_A[9*i + j];  
  ;     }  
  ;  
  ;     if (!is_valid_perm(perm))  
  ;         return 0;  
  ; }  
  ;  
  ; return 1;  
  ;
---------------------------------------------------------------------------  
  0x00400652:   save    48,fp,ra            ; prolog  
  0x00400656:   addiu   fp,sp,-4048         ;  
  0x0040065a:   sw      zero,12(sp)             ;  
  0x0040065c:   sw      zero,16(sp)             ;  
  0x0040065e:   sb      zero,20(sp)             ;  
  0x00400662:   sw      zero,28(sp)             ;  
  0x00400664:   bc      0x4006a8                ; goto LOOP_END

LOOP:  
  0x00400666:   sw      zero,24(sp)             ; j = 0  
  0x00400668:   bc      0x40068e

INNER_LOOP:  
  0x0040066a:   lw      a2,28(sp)               ;  
  0x0040066c:   move    a3,a2               ;  
  0x0040066e:   sll     a3,a3,3                 ;  
  0x00400670:   addu    a2,a3,a2            ; a2 = 9*i  
  0x00400672:   lw      a3,24(sp)               ;  
  0x00400674:   addu    a2,a2,a3            ; a2 = 9*i + j  
  0x00400676:   lapc    a3,0x420000         ;  
  0x0040067a:   addu    a3,a2,a3            ;  
  0x0040067c:   lbu     a2,0(a3)                ; a2 = tbl_A[9*i + j] (byte)  
  0x0040067e:   lw      a3,24(sp)               ;  
  0x00400680:   addiu   a1,sp,32            ;  
  0x00400682:   addu    a3,a1,a3            ;  
  0x00400684:   sb      a2,-20(a3)              ; var_c[j] = tbl_A[9*i + j]  
  0x00400688:   lw      a3,24(sp)               ;  
  0x0040068a:   addiu   a3,a3,1             ; ++j  
  0x0040068c:   sw      a3,24(sp)               ;

INNER_LOOP_END:  
  0x0040068e:   lw      a3,24(sp)               ;  
  0x00400690:   bltic   a3,9,0x40066a       ; if j < 9 goto INNER_LOOP

  0x00400694:   addiu   a3,sp,12            ;  
  0x00400696:   move    a0,a3               ;  
  0x00400698:   balc    0x4004c6            ; retval = is_valid_perm(var_c)  
  0x0040069a:   move    a3,a0               ;  
  0x0040069c:   bnezc   a3,0x4006a2         ; if retval != 0 goto
NEXT_INNER_ITER  
  0x0040069e:   move    a3,zero             ;  
  0x004006a0:   bc      0x4006b0                ; else return 0 & goto
FUNC_EPILOG

NEXT_INNER_ITER:  
  0x004006a2:   lw      a3,28(sp)               ;  
  0x004006a4:   addiu   a3,a3,1             ; ++i  
  0x004006a6:   sw      a3,28(sp)               ;

LOOP_END:  
  0x004006a8:   lw      a3,28(sp)               ;  
  0x004006aa:   bltic   a3,9,0x400666       ; if i < 9 goto LOOP  
  0x004006ae:   li      a3,1                    ;

FUNC_EPILOG:  
  0x004006b0:   move    a0,a3               ;  
  0x004006b2:   restore.jrc     48,fp,ra        ;

  ;
---------------------------------------------------------------------------  
  ; check_permutations()  
  ;  
  ; /** Decompiled Code **/  
  ; return (gen_valid_double_perm() &&  
  ;         gen_valid_col_perm() &&  
  ;         get_valid_row_perm());  
  ;
---------------------------------------------------------------------------  
  0x004006b6:   save    16,fp,ra            ; prolog  
  0x004006ba:   addiu   fp,sp,-4080         ;  
  0x004006be:   balc    0x400580            ; rval1 = is_valid_double_perm()  
  0x004006c0:   move    a3,a0               ;  
  0x004006c2:   bnezc   a3,0x4006c8         ; if rval1 != 0 goto CHECK_2  
  0x004006c4:   move    a3,zero             ;  
  0x004006c6:   bc      0x4006de                ; else return 0

CHECK_2:  
  0x004006c8:   balc    0x4005ee            ; rval2 = is_valid_col_perm()  
  0x004006ca:   move    a3,a0               ;  
  0x004006cc:   bnezc   a3,0x4006d2         ; if rval2 != 0 goto CHECK_3  
  0x004006ce:   move    a3,zero             ;  
  0x004006d0:   bc      0x4006de                ; else return 0

CHECK_3:  
  0x004006d2:   balc    0x400652            ; rval3 = is_valid_row_perm()  
  0x004006d4:   move    a3,a0               ;  
  0x004006d6:   bnezc   a3,0x4006dc         ; if rval3 != 0 goto SUCCESS  
  0x004006d8:   move    a3,zero             ;  
  0x004006da:   bc      0x4006de                ; else return 0

SUCCESS:  
  0x004006dc:   li      a3,1                    ; retval = 1

RETURN:  
  0x004006de:   move    a0,a3               ;  
  0x004006e0:   restore.jrc     16,fp,ra        ; epilog

  ; --------------------------------------------------------------------------  
  ; main  
  ;  
  ; /** Decompiled Code **/  
  ;  
  ; memset(flag, 0, 0x5A);  
  ; read(0, flag, 0x3E);  
  ; if (flag[0x3D] != '}' || strncmp("flag{", flag, 5)) {  
  ;     puts("Wrong");  
  ; }  
  ;  
  ; j = -1;  
  ; for (int i=5; i<0x3D; ++i) {  
  ;     while (tbl_A[++j]);  
  ;  
  ;     tbl_A[j] = flag[i];  
  ; }  
  ;  
  ; if (check_permutations()) {  
  ;     puts("Right");  
  ; } else {  
  ;     puts("Wrong");  
  ; }  
  ; --------------------------------------------------------------------------  
  0x004006e4:   save    128,fp,ra,gp        ; prolog  
  0x004006e8:   addiu   fp,sp,-3968         ;  
  0x004006ec:   lapc    gp,0x4200ac         ; gp = .got  
  0x004006f0:   addiu   a3,sp,12            ; a3 = sp + 0xc = var_c = flag  
  0x004006f2:   li      a2,90                   ; a2 = 0x5A  
  0x004006f4:   movep   a0,a1,a3,zero       ; a0 = a3, a1 = 0  
  0x004006f6:   lw      a3,48(gp)               ; a3 = .got[0x30] = memset  
  0x004006fa:   jalrc   a3                  ; memset(flag, 0, 0x5A)  
  0x004006fc:   addiu   a3,sp,12            ; a3 = flag  
  0x004006fe:   li      a2,62                   ; a2 = 0x3E  
  0x00400700:   movep   a0,a1,zero,a3       ; a0 = 0, a1 = a3  
  0x00400702:   lw      a3,36(gp)               ; a3 = .got[0x24] = read  
  0x00400706:   jalrc   a3                  ; read(0, flag, 0x3E)  
  0x00400708:   lbu     a3,73(sp)               ; a3 = flag[-1]  
  0x0040070c:   bneic   a3,125,0x40077c     ; if a3 != 0x7D ('}') goto
BAD_BOY_2

BASE_CHECK_1:  
  0x00400710:   addiu   a3,sp,12            ; a3 = flag  
  0x00400712:   li      a2,5                    ; a2 = 5  
  0x00400714:   lapc    a1,0x400800         ; a1 = "flag{"  
  0x00400718:   move    a0,a3               ;  
  0x0040071a:   lw      a3,40(gp)               ; a3 = .got[0x28] = strncmp  
  0x0040071e:   jalrc   a3                  ; strncmp("flag{", flag, 5)  
  0x00400720:   move    a3,a0               ; a3 = retval  
  0x00400722:   bnezc   a3,0x40077c         ; if retval != 0 goto BAD_BOY_2

MAIN_ALGO:  
  0x00400724:   sw      zero,108(sp)            ; v_108 = 0 (j)  
  0x00400726:   li      a3,5                    ; a3 = 5  
  0x00400728:   sw      a3,104(sp)              ; v_104 = a3  
  0x0040072a:   bc      0x400758                ; goto LOOP_END

LOOP_INC_J:  
  0x0040072c:   lw      a3,108(sp)              ; a3 = v_108 = j  
  0x0040072e:   addiu   a3,a3,1             ; ++a3  
  0x00400730:   sw      a3,108(sp)              ; v_108 = a3  (++j)

INNER_LOOP:  
  0x00400732:   lapc    a2,0x420000         ; a2 = tbl_A  
  0x00400736:   lw      a3,108(sp)              ;  
  0x00400738:   addu    a3,a2,a3            ;  
  0x0040073a:   lbu     a3,0(a3)                ; a3 = tbl_A[j]  
  0x0040073c:   bnezc   a3,0x40072c         ; if tbl_A[j] != 0 goto LOOP_INC_J

  0x0040073e:   lw      a3,104(sp)              ; a3 = i  
  0x00400740:   addiu   a2,sp,112           ;  
  0x00400742:   addu    a3,a2,a3            ;  
  0x00400744:   lbu     a2,-100(a3)             ; a2 = flag[i]  
  0x00400748:   lapc    a1,0x420000         ; a1 = tbl_A  
  0x0040074c:   lw      a3,108(sp)              ;  
  0x0040074e:   addu    a3,a1,a3            ;  
  0x00400750:   sb      a2,0(a3)                ; tbl_A[j] = flag[i] (BYTE)

  0x00400752:   lw      a3,104(sp)              ;  
  0x00400754:   addiu   a3,a3,1             ; ++i  
  0x00400756:   sw      a3,104(sp)              ;

LOOP_END:  
  0x00400758:   lw      a3,104(sp)              ;  
  0x0040075a:   bltic   a3,61,0x400732      ; if i < 0x3D goto INNER_LOOP  
  0x0040075e:   balc    0x4006b6            ; retval = check_permutations()  
  0x00400760:   move    a3,a0               ;  
  0x00400762:   beqzc   a3,0x400770         ; if retval == 0 goto BAD_BOY_1

GOOD_BOY:  
  0x00400764:   lapc    a0,0x400808         ; a0 = "Right"  
  0x00400768:   lw      a3,44(gp) ;             ; a3 = .got+0x2c = puts  
  0x0040076c:   jalrc   a3                  ; puts("Right")  
  0x0040076e:   bc      0x400786                ; goto END

BAD_BOY_1:  
  0x00400770:   lapc    a0,0x400810         ; a0 = "Wrong"  
  0x00400774:   lw      a3,44(gp)               ;  
  0x00400778:   jalrc   a3                  ; puts("Wrong")  
  0x0040077a:   bc      0x400786                ; goto END

BAD_BOY_2:  
  0x0040077c:   lapc    a0,0x400810         ; a0 = "Wrong"  
  0x00400780:   lw      a3,44(gp)               ;  
  0x00400784:   jalrc   a3                  ; puts("Wrong")  
END:  
  0x00400786:   move    a3,zero             ;  
  0x00400788:   move    a0,a3               ; return 0  
  0x0040078a:   restore.jrc     128,fp,ra,gp    ;  
```

The decompiled program (in **C**) is shown below:  
```C  
int is_valid_perm(char *perm) {  
   /* check if a string is a valid permutation of 'zxcasdqwe' */  
}

byte *tbl_B = {  
   0x00, 0x01, 0x02, 0x03, 0x0a, 0x0c, 0x0d, 0x0e, 0x13,  
   0x04, 0x05, 0x06, 0x0f, 0x18, 0x19, 0x21, 0x2a, 0x33  
   0x07, 0x08, 0x10, 0x11, 0x1a, 0x22, 0x23, 0x2b, 0x34  
   0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x37, 0x3f, 0x48  
   0x0b, 0x14, 0x15, 0x1c, 0x1d, 0x1e, 0x25, 0x2e, 0x27  
   0x16, 0x17, 0x1f, 0x20, 0x28, 0x31, 0x3a, 0x42, 0x43  
   0x26, 0x2f, 0x30, 0x38, 0x39, 0x40, 0x41, 0x49, 0x4a  
   0x29, 0x32, 0x3b, 0x3c, 0x3d, 0x44, 0x4b, 0x4c, 0x4d  
   0x2c, 0x35, 0x3e, 0x45, 0x46, 0x47, 0x4e, 0x4f, 0x50  
}

byte *tbl_A = {  
   0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x73, 0x00, 0x00,  
   0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x77, 0x00, 0x00,  
   0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00,  
   0x00, 0x65, 0x00, 0x77, 0x00, 0x71, 0x00, 0x61, 0x00,  
   0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
   0x61, 0x00, 0x00, 0x7a, 0x64, 0x00, 0x00, 0x73, 0x77,  
   0x71, 0x00, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x73,  
   0x78, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7a,  
   0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x78  
}

int is_valid_double_perm() {  
   byte perm[9];

   for (int i=0; i<9; ++i) {  
       for (int j=0; j<9; ++j) {  
           perm[j] = tbl_A[tbl_B[9*i + j]];  
       }

       if (!is_valid_perm(perm))  
           return 0;  
   }

   return 1;  
}

int is_valid_col_perm() {  
   byte perm[9];

   for (int i=0; i<9; ++i) {  
       for (int j=0; j<9; ++j) {  
           perm[j] = tbl_A[9*j + i];  
       }

       if (!is_valid_perm(perm))  
           return 0;  
   }

   return 1;  
}

int is_valid_row_perm() {  
   byte perm[9];

   for (int i=0; i<9; ++i) {  
       for (int j=0; j<9; ++j) {  
           perm[j] = tbl_A[9*i + j];  
       }

       if (!is_valid_perm(perm))  
           return 0;  
   }

   return 1;  
}

int check_permutations() {  
   return (gen_valid_double_perm() &&  
           gen_valid_col_perm() &&  
           get_valid_row_perm());  
}

int main(int argc, char* argv[])  
   memset(flag, 0, 0x5A);  
   read(0, flag, 0x3E);  
   if (flag[0x3D] != '}' || strncmp("flag{", flag, 5)) {  
       puts("Wrong");  
   }

   j = -1;  
   for (int i=5; i<0x3D; ++i) {  
       while (tbl_A[++j]);

       tbl_A[j] = flag[i];  
   }

   if (check_permutations()) {  
       puts("Right");  
   } else {  
       puts("Wrong");  
   }

   return 0;  
}  
```

### Cracking the code

Looking at the decompiled version, program reads a flag and fills the empty
cells of a `9x9` table.  
Then it runs 3 types of checks:  
* Check #1: All rows must have the letters `zxcasdqwe` exactly once.  
* Check #2: All columns must have the letters `zxcasdqwe` exactly once.  
* Check #3: A set of 9 random subset that do not intersect must have the letters `zxcasdqwe` exactly once.

Since there are too many restrictions to fill up this table, we can do a DFS
brute-force with  
backtracking. After few seconds, we get the flag:  
```  
flag{zacedxqsxaqezcscxwzqeczsxddqsxczwaqexczxacdeweasqccsqzae}  
```

For more details please take a look at
[babymips_crack.py](./babymips_crack.py)

___

Original writeup (https://github.com/ispoleet/ctf-
writeups/tree/master/0ctf_quals_2020/babymips).# babymips (122 solves)

Description:

> what's the flag?  
>  
> by Dan

Looking at the main function we can see the binary asks for flag, then calls
check function.

```c++  
undefined4 main(void)

{  
 basic_ostream *this;  
 basic_string<char,std--char_traits<char>,std--allocator<char>> abStack152
[24];  
 basic_string<char,std--char_traits<char>,std--allocator<char>> input [24];  
 undefined encoded_flag [84];  
 int iStack20;  
  
 iStack20 = __stack_chk_guard;  
 basic_string();  
 this = operator<<<std--char_traits<char>>((basic_ostream *)&cout,"enter the
flag");  
 operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--
char_traits<char>>);  
 operator>><char,std--char_traits<char>,std--allocator<char>>  
           ((basic_istream *)&cin,(basic_string *)abStack152);  
 memcpy(encoded_flag,&UNK_004015f4,0x54);  
 basic_string((basic_string *)input);  
 check_flag(encoded_flag,input);  
 ~basic_string(input);  
 ~basic_string(abStack152);  
 return 0;  
}  
```

The **check_function** takes 2 arguments. First one being actual encoded flag,
the second being our input string.

```c++  
void check_flag(int encoded_flag,  
              basic_string<char,std--char_traits<char>,std--allocator<char>> *input)

{  
 int iVar1;  
 basic_ostream *this;  
 uint uVar2;  
 char *c;  
 uint i;  
  
 iVar1 = size();  
 if (iVar1 == 0x4e) {  
   i = 0;  
   while (uVar2 = size(), i < uVar2) {  
     c = (char *)operator[](input,i);  
     if (((int)*c ^ i + 0x17) != (int)*(char *)(encoded_flag + i)) {  
       this = operator<<<std--char_traits<char>>((basic_ostream *)&cout,"incorrect");  
       operator<<((basic_ostream<char,std--char_traits<char>> *)this,  
                  endl<char,std--char_traits<char>>);  
       return;  
     }  
     i = i + 1;  
   }  
   this = operator<<<std--char_traits<char>>((basic_ostream
*)&cout,"correct!");  
   operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std
--char_traits<char>>)  
   ;  
 }  
 else {  
   this = operator<<<std--char_traits<char>>((basic_ostream
*)&cout,"incorrect");  
   operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std
--char_traits<char>>)  
   ;  
 }  
 return;  
}  
```

The algorithm is straightforward. We take one byte from out input, xor it with
**i** and add 0x17

Solution:

```python  
import binascii  
from z3 import *  
flag = '62 6C 7F 76 7A 7B 66 73 76 50 52 7D 40 54 55 79 40 49 47 4D 74 19 7B
6A 42 0A 4F 52 7D 69 4F 53 0C 64 10 0F  1E 4A 67 03 7C 67 02 6A 31 67 61 37 7A
62 2C 2C 0F 6E 17 00 16 0F 16 0A 6D 62 73 25 39 76 2E 1C 63 78 2B 74 32 16 20
22 44 19'.replace(' ','')  
flag = binascii.unhexlify(flag)

def encode(inp, i):  
   return (inp ^ i + 0x17) & 0xff

def find_all_posible_solutions(s):  
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
   flag_len = len(flag)  
   for i in range(flag_len):  
       globals()['b%d' % i] = BitVec('b%d' % i, 8)  
       s.add(globals()['b%d' % i] >= 32)  
       s.add(globals()['b%d' % i] <= 126)  
       s.add(encode(globals()['b%d' % i], i) == flag[i])  
  
   find_all_posible_solutions(s)  
  
if __name__ == "__main__":  
   main()  
```

The script yields one solution:

```  
utflag{mips_cpp_gang_5VDm:~`N]ze;\)5%vZ=C'C(r#$q=*efD"ZNY_GX>6&sn.wF8$v*mvA@'}  
```

Original writeup (https://github.com/archercreat/CTF-
Writeups/blob/master/utctf/rev/babymips/README.md).