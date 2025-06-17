# Machbook

OSX Heap Exploitation in Small Heap

Description:

```  
Mach Apple Great Again!!!  
https://drive.google.com/open?id=1-8IauoBTbeuoCS_HN8ngxNtaXhxjsuLO  
nc machbook.balsnctf.com 19091

download link: here

Author: how2hack

Hint: OSX library offset will not change if system is still up  
```

Solves: 1/728

## Inspiration

`Machbook` challenge is inspired by 0CTF 2019 Quals Challenge `applepie`,
which focus on OSX Heap Exploitation in Tiny Heap. I tried to solve that
challenge but I wasn't able to solve it on time. So I took some time to review
the heap structure and memory allocator mechanism in OSX after the contest
with [@scwuaptx](https://twitter.com/scwuaptx) help, a very big thanks to him!

If you are interested in OSX Heap Structure and Memory Allocator Mechanism,
you can check this [slide](https://www.slideshare.net/AngelBoy1/macos-memory-
allocator-libmalloc-exploitation) created by Angelboy.

## OSX Small Heap

The idea of this challenge is to exploit OSX Small Heap Mechanism. You can
forge a fake heap structure and perform unlink to overwrite a pointer. This
trick is similar to glibc unsafe unlink, but with different offset. The
previous pointer is `ptr` and next pointer is `ptr+0x10`.

The freed Small Heap chunk data header:  
```  
   +--------+--------+  
   |  prev  |checksum|  
   +--------+--------+  
   |  next  |checksum|  
   +--------+--------+  
```

When you try to malloc a freed chunk, it will check `ptr->prev->next == ptr`
and `ptr->next->prev == ptr`. Then, it will set `ptr->prev->next = ptr->next`
and `ptr->next->prev = ptr->prev`. Therefore, you need to forge a correct heap
structure.

Some notes (also the tricky part for this challenge) worth to mention:

1. You need to calculate the correct checksum, invalid checksum will abort the program. The checksum is `SumOfEveryBytes(ptr ^ small-rack-cookie ^ small-rack-ptr)`.  
2. Library offset will not change if the system is still online.  
3. Thread may wake up at different core, so you might not get the allocated address in the same magazine.

## Challenge

In this challenge, the program consists of one memory corruption that may lead
to arbitrary read and arbitrary free. Your goal is to create a arbitrary write
to ovewrite `GOT` address to `system` and get RCE.

```  
 user1 --> +--------+--------+  
           | pw_ptr |        |  
           +--------+        |  
           |                 |  
           |     name[40]    |  
           |                 |  
           +-----------------+  
           |                 |  
           |                 |  
           |     *post[7]    |  
           |                 |  
           |        +--------| <-- user2  
           |        | pw_ptr |  
           +--------+--------+  
           |       ...       |  
           +-----------------+  
```

### Vulnerability

The bug is very trivial, it will directly replace `\` to `\\` in `name`, so
the data will overflow to `post`. You can use this bug to trigger arbitrary
read and arbitrary free.

### Information Leak

To perform unsafe unlink attack, you need to have `small-rack-cookie` and
`small-rack-ptr` to be able to calculate the checksum. Despite the fact that
you have arbitrary read and arbitrary free, but you have no information about
what address to overflow because `PIE` is enabled.

#### Note: OSX Heap Initializaion

When I was solving the challenge `applepie`, i noticed that OSX will allocate
a memory to perform heap initialization (I am not sure about this, but it
looks like some kind of initialization). In that memory, you can get some
interesting values such as code address (only in tiny heap) and library
address.

#### Leak library offset and get everything!

In this challenge, you can create a user and post something. Now you have one
small heap address in `post[0]`. You can overflow and partial overwrite last 3
bytes of `post[0]`, then you can leak library address from the heap
initialization memory.

With library address, you can calculate offset to get the base address of
`libmalloc`. Then, you can leak `malloc_zone` address from `libmalloc`. With
`malloc_zone` address, you can calculate offset to get `code` address, `small-
rack-ptr` and also `small-rack-cookie`. Now you can calculate checksum!

### Unsafe Unlink

With the ability to forge checksum, then you can forge a fake heap structure
to perform unsafe unlink attack. The idea is totally same as glibc unsafe
unlink attack, but with the checksum protection. Using this attack, you can
overwrite `user1->pw_ptr` to `post[3]` address, then you can overwrite
`user2->pw_ptr` to something else to create arbitrary write.

#### Note: Allocation may not be in the same Magazine

When you are trying your exploit, you may notice that your exploit may not
bahave the same each time. For instance, your allocation memory may not be in
the same region (not in the same Magazine to be precise, offset will be
0x800000\*number-of-core). I had this problem when I was solving the challenge
`applepie` and I was very confused. I took a research and found this
[slide](https://papers.put.as/papers/macosx/2016/Summercon-2016.pdf), it
mentioned that in OSX, each Magazine is mantained by a single core, however,
you might not wake up in the same core during the same process, which may
cause you not getting the small heap address in the same Magazine.

To bypass this, we can write a small check to keep malloc until we get the
small heap address in the same Magazine. This can be easily done by arbitrary
read.

### Hijack `la_symbol_ptr`

Now you have arbitrary write, you can overwrite `user2->pw_ptr` to
`atoi@la_symbol_ptr` (similar to `GOT` in glibc). Then you can overwrite
`atoi@_la_symbol_ptr` to `system` libsystem address. You can call `system` by
calling `atoi`.

You can find my exploit [here](script.py).

## Thanks for playing Balsn CTF 2019

Congratulation to [@howzinuns](https://twitter.com/howzinuns) to be the only
one who successfully pwned this challenge during the contest. I took about 3
weeks to understand the Small Heap Mechanism in OSX and create this challenge
but he only used about 21 hours to solve it.

If you are interested in his exploit, you can find it
[here](https://github.com/hOwD4yS/CTF/blob/master/2019/balsn/machbook_exploit.py).  

Original writeup (https://github.com/how2hack/my-ctf-
challenges/tree/master/balsnctf-2019/machbook).