# Description

the filesystem is mounted on the test\_dir folder in the home folder of the
user

PSA: the filesystem is not meant to be a production grade filesystem and only
supports basic operations, as such don't expect to do anything more than
really basic things on it :)

you can connect to remote using socat tcp4:178.63.8.31:4242 -,raw,echo=0

the flag is at the root of the home folder

Create the basebox using  
   cd basebox  
   ./build.sh

and spawn a victim vm using  
   cd victimbox  
   vagrant up  
   vagrant ssh

# Writeup

this challenge was an idea that we talked extensively about before I started
implementing it, the initial idea was that we wanted to do a challenge where
the vulnerability was a double-fetch.

The "problem" with double fetch is that if you know about this class of bug,
they can be super easy to spot so we needed a context where we could maybe
hide it a bit.

On top of that most kernel challenges usually work by registering a character
device and defining a set of `ioctl`'s operations, so we wanted to break out
of that model

Therefore we had the idea of making a challenge based around a virtual file
system (which was great before I knew nothing about how to implement one and
still wouldn't hire me to write one but I learned a lot :))

The idea was that the filesystem would basically be really similar to ramfs
except data would be compressed.

# Bug(s)

So I will first talk about the intended bug and then highlight two others
(writing a filesystem is not a simple task hehe).

The compression algorithm is a really naive Huffman encoding scheme where the
data is stored as follow:  
* a uint32\_t storing the real length of the string  
* the huffman tree encoded  
* the data encoded

The double fetch happens between the time the tree is created and the data is
actually compressed. When the tree is created it will call `copy_from_user` to
get a kernel copy of the buffer as SMEP/SMAP were enabled and work on it, then
based on the tree it will computed the length needed for the allocation

However, when the function that writes the data is called, it will once again
call `copy_from_user`. If we replaced a character in between with one that was
not in the string originally, it will simply be ignored so no overflow
happens. But if we write a string that is represented with an unbalanced
huffman tree like `AAAAAAAAAAAABBBCC` where A will be represented by one bit
and B and C with 2 bits each and modify some of the A's with B's or C's then
we will overflow some bits.

# Exploit

The idea is then to trigger the double fetch in order to overflow into
something we want to proceed with the exploitation. I won't explain how the
SLUB allocator work but it is sufficient to know that objects are allocated in
pages based on their size. We have to deal with freelist randomization which
makes it a bit harder to predict the heap layout.

People were free to use real kernel objects to write an exploit but we could
make do with only the structures used by the kernel module. My exploit works
by first triggering the double fetch in order to increase the length
corresponding to a compressed file. By doing that we will be able to read out
of bound as well as write out of bounds.

In order to deal with freelist randomization, I use the following strategy:

* spray a lot of files, this gives us a lot of contiguous allocations  
* free one out of every 10 files so that we are confident holes are created right before our data structures  
* trigger the double fetch to overflow the size

Now we can read from each file with a value larger than the original length
and if we get the same value as a return value from a read syscall we have
found the corrupted file.

Now we delete all the files except the corrupted one to clean the memory and
we create a lot of files so that they are stored uncompressed because the
coding scheme will store the data uncompressed if compression would actually
make the data bigger.

The reason we want to do that is that the filesystem (for analytical purposes
when I decide to sell it probably :P) use a meta data structure which contains
among other things the following things:

* the name of the calling process that created the file  
* a pointer to the actual data (compressed or not) which is the pointer returned by the `deflate` API  
* the effective length of the data (i.e for a file successfully compressed this would hold the compressed data length, but if the file is uncompressed, this value is the same as the one stored in the first 4 bytes of the data)

When a read syscall is issued, the file system will check if the size
requested is larger than the length of the file, in the case of a compressed
file we need to dereference the pointer to get the first 4 bytes however in
the case of an uncompressed file, the filesystem retrives it from the metadata
without dereferencing the pointer

Now it is pretty clear that with our corrupted file which lets us read and
write out of bound, we want to overwrite the pointer of an uncompressed file
which should give us an arbitrary R/W.

In the presence of SMEP and SMAP. The most simple way to solve this is
probably to carry a data only attack by overwriting the content of the `cred`
structure of our process.

As `copy_to_user` is a safe function, we should now be able to scan the heap
but this is tedious and long on 64bits and totally uninteresting so I wanted
to avoid any problem with that and put a special case where if the process
would read from a file called `christmas_gift` with length `0x1337` the
filesystem would just give the `task_struct` of the current process

So now all is left is to leak the value of the `real_cred` member of the
`task_struct` structure and overwrite the relevant fields with 0 and we should
be elevated to `root`

# Unintended bugs

There are actually two unintended bugs in the file-mmu.c file which I will let
people find as an exercise. You can always hit me up on twitter. They are
actually I think cool bugs and much respect to pasten for finding them and
crushing my filesystem as they did.  

Original writeup (https://github.com/bkth/34c3ctf/tree/master/esprfs).