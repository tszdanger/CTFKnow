## Overview

This challenge allows the management of movies and friends. You can add or
remove friends. You can create or delete a movie, and you can share a movie to
an existing friend.  There is also a way to create or delete feedback with
contact details if you select to delete your account. These items are all
managed using malloc.

We discovered two bugs:  
* When friends are removed and freed, they are not removed from a movie that was shared, causing a use-after-free  
   * Using this, we obtained heap and libc address leaks by displaying movies that had their associated friend removed  
* Pointers to deleted feedback are not removed, allowing for them to freed multiple times  
   * There may be multiple ways to exploit this, but we chose to use it to create misaligned heap chunks to modify a tcache entry

The heap address we leaked was actually encoded through `safe linking`, a new
feature added in glibc version 2.32.  Essentially, it performs an xor on a
pointer with that pointers' location shifted left by 12.  This is basically
performing something like this: `ptr ^ (&ptr >> 12)`.

The glibc library runs a macro called `REVEAL_PTR` to decode these values.  
```c  
#define PROTECT_PTR(pos, ptr) \  
 ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))  
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)  
```  
Source:
[https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=e2d7b1b58396906375ba0e953a20ac57f0904378#l344](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=e2d7b1b58396906375ba0e953a20ac57f0904378#l344)

More on safe linking can be read here:
[https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-
malloc-exploit-primitive/](https://research.checkpoint.com/2020/safe-linking-
eliminating-a-20-year-old-malloc-exploit-primitive/)

We uncovered 2 techniques to bypass this feature to convert the leak to valid
heap addresses.  One technique involves finding a NULL value that has gone
through safe linking.  With this, we could simply shift the value right by 12
and potentially obtain the heap base.  Another method involved using a SMT
solver to find the original pointer.  We decided to use the 2nd option to
convert our leaks to valid heap addresses.

With a valid leaked address, we could then use the 2nd bug above to cause
chunk misalignment with an unsorted bin and a tcache entry.  This allowed us
to modify that tcache entry to have control over it's forward and back
pointers. We overwrote these pointers with `__free_hook`, allowing us to
overwrite the `__free_hook` offset with the address of `system()`.  We then
forced a call to `free()` with `/bin/sh` to spawn a shell.

## Heap Leak

To obtain a heap leak, we added 2 friends, shared a new movie with the 2nd
friend, and then removed both friends.  This sent both of the friend chunks
into tcache, setting their forward and back pointers to heap addresses.  We
then can show a movie to read from the 2nd friend chunk's forward pointer.  As
stated earlier, this heap pointer was encoded with safe linking and we needed
to decode it to a valid address to obtain a valid heap address leak.

### Safe Linking

To reveal the real heap pointer, we decided to use a SMT solver using two
conditions. Since we know the higher bits of the address, our first constraint
was to verify the resulting pointer to match these high bits. For our second
constraint, we verify the "safe link" form of the pointer is our leak.

The function below will return the valid address when given a safe linked
value:  
```python  
def unsafe_link(e):  
   high_e = e & 0xfffffff000000000  
   x = BitVec('x',64)  
   s = Solver()  
   s.add(x & 0xfffffff000000000 == high_e)  
   s.add(x ^ (x >> 12) == e)  
   s.check()  
   return s.model()[x].as_long()  
```

From this function, we can pass the leaked safe link value and obtain a valid
heap leak.

After the CTF ended, we discovered other solutions that are likely more
efficient:

hkraw's -
[https://gist.github.com/hkraw/0576a28c5436734d0fbe6d8ddd378143#file-plaidctf-
plaidflix-
py-L8](https://gist.github.com/hkraw/0576a28c5436734d0fbe6d8ddd378143#file-
plaidctf-plaidflix-py-L8)  
```python  
def demangle(obfus_ptr):  
   o2 = (obfus_ptr >> 12) ^ obfus_ptr  
   return (o2 >> 24) ^ o2  
```

MaherAzzou1zi's -
[https://github.com/MaherAzzouzi/LinuxExploitation/blob/master/PlaidCTF-
plaidflix/solve.py#L83](https://github.com/MaherAzzouzi/LinuxExploitation/blob/master/PlaidCTF-
plaidflix/solve.py#L83)  
```python  
def defu(p):  
   d = 0  
   for i in range(0x100,0,-4):  
     pa = (p & (0xf << i )) >> i  
     pb = (d & (0xf << i+12 )) >> i+12  
     d |= (pa ^ pb) << i  
   return d  
```

## Libc leak

To obtain a libc leak, we did something similar to the heap leak, except we
filled the corresponding tcache bin.  We added 8 friends, shared a new movie
with the 8th friend, and then removed all 8 friends.  After the first 7
friends are freed, the corresponding tcache bin will be filled, so that when
the 8th friend is freed, it will be sent to an unsorted bin.  We then forced
this chunk to be sorted into a small bin by adding a new friend of another
size.

Now that the 8th friend is in a small bin, it's forward pointer is a pointer
to somewhere in libc.  On Ubuntu 20.04, this chunk could remain in the
unsorted bin to have a valid libc address, but the challenge was running on
ubuntu 20.10 and did not have a libc address when it was in the unsorted bin.

We then show that movie and obtain a libc leak to use in our future exploit
chain.

## Chunk Misalignment to Overwrite Tcache

With the heap and libc leaks, we could abuse the double free vulnerability in
feedback messages when we choose to delete our account.  This exploit is
possible because pointer to feedback messages are not removed from the
feedback list when they are freed, allowing us to access them (performing a
free in this case) after they were "deleted".

After we opted to delete our account, we filled the 0x110 tcache bin and then
freed two other adjacent chunks so they would consolidate with each other.  
To do this, we created 9 feedback messages and then deleted the first 6 and
the 8th entries.  Each feedback message allocates a size 0x110 chunk, so this
filled the 0x110 tcache bin.  We removed the 7th message so that it would be
sent to the unsorted bin.  Next, we removed the chunk above, the 6th feedback,
in order to force the 6th entry to consolidate with the 7th to create a single
chunk.

The 0x100 size tcache bin looked something like this:  
```  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     +-+-+-+-+-+-+-+  
| feedback #8 | feedback #5 | feedback #4 | ... | feedback #0 |  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     +-+-+-+-+-+-+-+  
```

The heap then looked like the following:  
```  
...  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0x110 - feedback #0  | <- stored in tcache bin (0x110)  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
...  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0x110 - feedback #5  | <- stored in tcache bin (0x110)  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0x220 - feedback #6  | <- stored in unsorted bin  
+                           +  
|              feedback #7  | <- at offset 0x110 in this chunk  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0x110 - feedback #8  | <- stored in tcache bin (0x110)  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
|         top chunk         |  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
```

When you add a contact detail, it allocates a chunk size of 0x130.  This
allowed it so when we created a contact detail at this point, it would store
the message at the above unsorted chunk, as it is greater than or equal to the
requested size. The contact detail message will overlap the 7th feedback
message by 0x20 bytes, which would allow us to control the chunk's header and
bin pointers. We found this to not matter much with the heap in its current
state, as `feedback #7` is not in a tcache bin. If we previously aligned the
heap such that the overlapped chunk was currently in tcache, we could skip the
next few steps.

The heap layout now looked like this:  
```  
...  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0x110 - feedback #0  | <- stored in tcache bin (0x110)  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
...  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0x110 - feedback #4  | <- stored in tcache bin (0x110)  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0x110 - feedback #5  | <- stored in tcache bin (0x110)  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0x130 contact detail |  
+                           +  
|              feedback #7  | <- at offset 0x110 in this chunk  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0xf0- unsorted chunk | <- stored in unsorted bin  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0x110 - feedback #8  | <- stored in tcache bin (0x110)  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
|         top chunk         |  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
```

Our current goal is to write a feedback message into the above `feedback #7`
so that it overflows into the `0xf0` unsorted chunk. We will then overwrite
that unsorted chunks header with a new size of `0x1f0`, so that the next
feedback message will be allocated from this chunk. We then will write to this
new chunk in order to overwrite the tcache entry at the above `feedback #8`.

Our first step was to clear the 0x110 tcache so we were using the tcache for
messages instead of the unsorted bin. For this, we created 7 new feedback
messages.  The first message allocation will be the location of the above
`feedback #8`, located immediately after the unsorted bin.  We then wrote the
value `0x1f0` for the `prev_size` value of a new fake chunk located after the
unsorted bin (0x1f0 bytes after).  This was to bypass a security check.  The
other feedback message values did not matter.

After tcache was flushed, we freed the above `feedback #7` so it will be
pushed into tcache. We then created a new feedback message that will pop off
`feedback #7` from tcache and write its message to it.  Since `feedback #7`
overlaps with the unsorted chunk, we overwrote the unsorted chunk header with
a new size of `0x1f0` so it will overflow into `feedback #8`. We also set the
unsorted chunk's forward and back pointer values to their original values in
the main area.

The 0x110 tcache bin was empty, so there is nothing to show.

The heap layout now looked something like this:  
```  
...  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0x110 - feedback #0  |  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
...  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0x110 - feedback #4  |  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0x110 - feedback #5  |  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0x130 contact detail |  
+- - - - - - - - - - - - -  + <- feedback #7 chunk start  
| size 0x110 - feedback #7  | --- chunk overlapped by contact detail  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <- unsorted chunk start  
| size 0x1f0 -unsorted chunk| --- modified chunk size to 0x1f0  
+- - - - - - - - - - - - -  + <- feedback #7 chunk end  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <- unsorted chunk previous end  
| size 0x110 - feedback #8  |  
+- - - - - - - - - - - - -  + <- unsorted chunk new end  
| 0x1f0 ( prev_size )       | --- set prev_size for unsorted chunk  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
|         top chunk         |  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
```

For the next steps, we performed some heap grooming so that `feedback #8` is
in the tcache when we write to the unsorted chunk.

We created a feedback message to hold a pointer to the modified unsorted
chunk. Lets just call this `feedback #9`. We created one more feedback message
to force a sort on the unsorted bin so the leftover chunk is placed into the
small bin.  This allowed us to bypass an unsorted bin check we were hitting.  
We then deleted 2 feedback values we weren't using to tcache to allow us to
create more feedback, as we have hit the maxed allowed feedback messages at
this point (10).  
We freed `feedback #8` and then `feedback #9` to push them into tcache.

The tcache looked like this:  
```  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| feedback #9 | feedback #8 | feedback #2 | feedback #1 |  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
```

### Tcache Overwrite

We popped off `feedback #9` from tcache by creating another feedback.  In this
feedback message, we overwrite `feedback #8`'s forward and back pointers with
the safe linked address of `__free_hook`.  For our safe linking here, we just
xor'd the address with the heap base address shifted left by 12.  We then
needed to add 1 to this result due the dereferenced address (`pos`) being
0x1000 higher than the base.

The tcache now looked like this:  
```  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| feedback #8 | __free_hook |  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
```

The heap layout now looked something like this:  
```  
...  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0x110 - feedback #0  |  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
...  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0x110 - feedback #4  |  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0x110 - feedback #5  |  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0x130 contact detail |  
+- - - - - - - - - - - - -  + <- feedback #7 chunk start  
| size 0x110 - feedback #7  |  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <- feedback #9 chunk start  
| size 0x110 - feedback #9  |  
+- - - - - - - - - - - - -  + <- feedback #7 chunk end  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0x110 - feedback #8  | <- in tcache  
| flink=> __free_hook       | --- overwritten forward and back pointers  
| blink=> __free_hook       |  
+- - - - - - - - - - - - -  + <- feedback #9 chunk end  
|                           |  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0xe0 - small chunk   | <- previous unsorted chunk, sorted into small bin  
| 0xe0 ( prev_size )        |  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
| size 0x110 - feedback  X  | <- unused feedback created to sort unsorted chunk  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
|         top chunk         |  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
```

We popped off `feedback #8` by creating a new feedback with a message of
`/bin/sh\x00`.  We then popped off the `__free_hook` value from tcache by
creating yet another feedback.  This message wrote the address of `system()`
to the `__free_hook` address.  We then deleted `feedback #8` again to trigger
`system("/bin/sh")` and spawn a shell to read the flag.

```  
[+] Opening connection to plaidflix.pwni.ng on port 1337: Done  
heap_leak: 0x55a77e6b62c0  
heap_base: 0x55a77e6b6000  
libc_leak: 0x7feb0d18fc80  
libc_base: 0x7feb0cfac000  
free_hook: 0x7feb0d192e40  
[*] Switching to interactive mode  
$ cat flag.txt  
PCTF{N0w_YOu_Kn0w_S4f3_L1nk1ng!}  
```  

Original writeup (https://github.com/x64x6a/ctf-
writeups/tree/master/PlaidCTF_2021/pwnable/plaidflix).