# shallweplayagame - BalCCon2k20 CTF (rev, 476p, 8 solved)  
## Introduction

shallweplayagame is a reversing task.

A Linux ELF file is provided. This program asks for a choice among a list of 5  
games inspired from the movie *Wargames*. Every response causes the program to  
answer `The only winning move is not to play.`.

## Reverse engineering

Importing the binary in Ghidra shows a simple main function that calls 3  
functions. Each of those contain a different check and exit if this check did  
not pass.

Debugging the binary shows a different message : `Mess with the best, die like  
the rest.`, hinting an anti-debug mechanism.

### Bypass anti-debugs

The most basic way to prevent a program from being debugged on Linux is the  
`ptrace` syscall. A program can only be attached by one debugger. As a result,  
calls to `ptrace` with request `PTRACE_TRACEME` will fail if a binary is
already  
debugged.

gdb can be configured to break when a syscall is executed :  
```  
(gdb) catch syscall ptrace  
Catchpoint 1 (syscall 'ptrace' [101])

(gdb) r  
Starting program: ./shallweplayagame

Catchpoint 2 (call to syscall ptrace), 0x00000001000014ad in ?? ()  
=> 0x00000001000014ad:  48 89 44 24 10  mov    QWORD PTR [rsp+0x10],rax  
(gdb) set $rax = 0  
(gdb) c  
Continuing.

Catchpoint 2 (returned from syscall ptrace), 0x00000001000014ad in ?? ()  
=> 0x00000001000014ad:  48 89 44 24 10  mov    QWORD PTR [rsp+0x10],rax  
(gdb) set $rax = 0  
(gdb) c  
Continuing.

SHALL WE PLAY A GAME?  
1 TIC-TAC-TOE  
2 CHESS  
3 POKER  
4 FIGHTER COMBAT  
5 GLOBAL THERMONUCLEAR WAR  
YOUR CHOICE [1-5]:  
Program terminated with signal SIGALRM, Alarm clock.  
The program no longer exists.  
```

This works, but the program is quickly killed by `SIGARLM`. gdb can also
ignore  
certain signals :  
```  
(gdb) handle SIGALRM ignore  
Signal        Stop      Print   Pass to program Description  
SIGALRM       No        No      No              Alarm clock  
```

### First check

The first function prints the menu with the 5 games.

The condition here is quite simple : the user's input multiplied by `42` must
be  
equal to `1316154`.

```assembler  
// sscanf(buffer, "%d", &choice);  
LEA  RAX, [RSP + 0x0C]  
MOV  RDX, RAX  
LEA  RSI, "%d"  
LEA  RDI, [0x46c0]  
MOV  EAX, 0x0  
CALL __isoc99_sscanf

// if(choice * 0x2A == 0x14153A)  
MOV  EAX, dword ptr [RSP + 0x0C]  
IMUL EAX, EAX, 0x2a  
CMP  EAX, 0x14153a  
JNZ  LAB_00001cda  
```

The number to pass the first check is `31337`.

```  
SHALL WE PLAY A GAME?  
1 TIC-TAC-TOE  
2 CHESS  
3 POKER  
4 FIGHTER COMBAT  
5 GLOBAL THERMONUCLEAR WAR  
YOUR CHOICE [1-5]: 31337  
OK....  
Well done!  
```

## Second check

The second function xors a buffer of size 32 and read the user's input. It
then  
checks the user's input with this buffer using `strncmp`.

Setting a breakpoint on `strncmp` will show what the expected input is :  
```  
(gdb) b *0x100000000 + 0x00001ac4  
Breakpoint 2 at 0x100001ac4

(gdb) c  
Continuing.  
test

Breakpoint 2, 0x0000000100001ac4 in ?? ()  
=> 0x0000000100001ac4:  e8 a7 f5 ff ff  call   0x100001070

(gdb) x/s $rdi  
0x1000046c0:    "test"

(gdb) x/s $rsi  
0x100004120:    "Are you, like, a crazy person?"  
```

The passphrase to pass the second check is `Are you, like, a crazy person?`

## Third check

The last function calls `strlen` on a buffer located at `0x4740`. This buffer
is  
a priori never written to and therefore empty. Using a breakpoint shows that  
this assumption is true.

```  
(gdb) x/s 0x100000000 + 0x4740  
0x100004740:    ""  
```

It then computes the MD5 hash of this buffer of size 0 and passes the result
to  
a function generated dynamically :  
```assembler  
  0x7ffff7fc9000:       push   rbp  
  0x7ffff7fc9001:       mov    rbp,rsp  
  0x7ffff7fc9004:       sub    rsp,0x20  
  0x7ffff7fc9008:       mov    rax,0x10  
  0x7ffff7fc900f:       mov    rcx,rdi  
  0x7ffff7fc9012:       lea    rdx,[rip+0x72]        # 0x7ffff7fc908b  
  0x7ffff7fc9019:       dec    rax  
  0x7ffff7fc901c:       mov    r8b,BYTE PTR [rcx+rax*1]  
  0x7ffff7fc9020:       mov    r9b,BYTE PTR [rdx+rax*1]  
  0x7ffff7fc9024:       xor    r8b,r9b  
  0x7ffff7fc9027:       jne    0x7ffff7fc9040  
  0x7ffff7fc9029:       dec    rax  
  0x7ffff7fc902c:       jne    0x7ffff7fc901c  
  0x7ffff7fc902e:       mov    r8b,BYTE PTR [rcx+rax*1]  
  0x7ffff7fc9032:       mov    r9b,BYTE PTR [rdx+rax*1]  
  0x7ffff7fc9036:       xor    r8b,r9b  
  0x7ffff7fc9039:       jne    0x7ffff7fc9040  
  0x7ffff7fc903b:       xor    rax,rax  
  0x7ffff7fc903e:       leave  
  0x7ffff7fc903f:       ret  

  // write(STDOUT_FILENO, "UNAUTHORIZED ACCESS DETECTED\n", 0x1c);  
  0x7ffff7fc9040:       mov    rax,0x1  
  0x7ffff7fc9047:       mov    rdi,0x1  
  0x7ffff7fc904e:       lea    rsi,[rip+0x19]        # 0x7ffff7fc906e  
  0x7ffff7fc9055:       mov    rdx,0x1c  
  0x7ffff7fc905c:       syscall

  // exit(1);  
  0x7ffff7fc905e:       mov    rax,0x3c  
  0x7ffff7fc9065:       mov    rdi,0x1  
  0x7ffff7fc906c:       syscall  
```

This function checks the hashes with a buffer located at `0x7ffff7fc908b`.  
```  
(gdb) x/16bz 0x7ffff7fc908b  
0x7ffff7fc908b: 0xc9    0xf4    0x1e    0x6d    0x2b    0x50    0x32    0x16  
0x7ffff7fc9093: 0xe7    0x72    0xb8    0xe5    0xfd    0x00    0xad    0xfe  
```

This buffer contains `c9f41e6d2b503216e772b8e5fd00adfe`, which is the MD5 hash  
for `JOSHUA`.

Given that this program contained anti debug code that runs ptrace, it means  
there has to be code run before main. In other words : constructors.

There are 5 constructors. The 4th one (`_INIT_3`) contains code that opens a  
file, and read its content in a buffer located at `0x4740`.  The name of this  
file is `lic`.

The file to pass the third check is called `lic` and should contain `JOSHUA`.

```sh  
$ echo -n JOSHUA > lic  
$ ./shallweplayagame  
SHALL WE PLAY A GAME?  
1 TIC-TAC-TOE  
2 CHESS  
3 POKER  
4 FIGHTER COMBAT  
5 GLOBAL THERMONUCLEAR WAR  
YOUR CHOICE [1-5]: 31337  
OK....  
Well done!  
Are you, like, a crazy person?  
I'm quite sure they will say so.

BCTF{Ain't_n0_brakes_0n_the_reversing_train!}  
```

**Flag**: `BCTF{Ain't_n0_brakes_0n_the_reversing_train!}`

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-09-25-BalCCon/shallweplayagame/README.md).