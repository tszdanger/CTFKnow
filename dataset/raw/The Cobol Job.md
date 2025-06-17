## Overview

This challenge allowed a user to create, open, read, write, close, and copy
files inside of a container. Permissions were set in the container so that
this challenge wasn't as simple as reading the flag file. The goal was to gain
shell access and execute the setuid bit binary, `/freader`, to obtain the
flag.

Our solution to this challenge can be broken up into three steps:  
* Obtaining libc base from `/proc/self/maps`  
* Copy a file to trigger use-after-free to overwrite tcache entry with `__free_hook`  
* Write one_gadget to `__free_hook` and trigger a free to obtain a system shell

## Libc leak

We can leak segment mappings by reading from `/proc/self/maps`, however, we
are not able to read directly from the file as it will trigger a `O_RDWR` and
fail.  We can instead copy the `/proc/self/maps` file to `/dev/stdout` to read
the segment mapping.

```python  
do_copy("/proc/self/maps", "/dev/stdout")  
```

## Use-After-Free

We eventually found a use-after-free vulnerability in `libcob` inside of the
copy file function, `CBL_COPY_FILE()`.  On line 4691 of `fileio.c`, it
retrieves an allocation, `fn1`, from `cob_str_from_fld()`. On line 4698, the
pointer is passed to `free()`. Then on line 4710, it triggers the UAF by
reading the source file's contents into it.

```c  
fn1 = cob_str_from_fld (cob_current_module->cob_procedure_parameters[0]);  
...  
free (fn1);  
...  
while ((i = read (fd1, fn1, sizeof(fn1))) > 0) {  
...  
}  
```

Source reference: https://github.com/cooljeanius/open-
cobol/blob/6391bcc51b26672d482e768cafc69d16a12036d5/libcob/fileio.c#L4710

## Modifying Tcache

The freed value above will be pushed into a tcache bin if that tcache bin is
not full.  We can control which tcache bin is used here through the size of
the source's filename, as the same buffer for the source's filename is also
used for the source's contents.

We created and opened a file with a filename length of 0x30 with some
arbitrary file size that differs.  The length of 0x30 is used so we fall into
the 0x40 size tcache bin. We then wrote the address of `__free_hook` into the
file such that it would overwrite the freed memory's forward and back
pointers.  We then copy this file with a new file with a different filename
size.  This will allocate the first filename, load it into the 0x40 tcache by
freeing it, and then set the `__free_hook` address as the chunk's forward and
back pointers.  This will manipulate the 0x40 tcache bin such that the 2nd
0x40 allocation request will return the address to `__free_hook`.  The next
0x40 allocation will return the freed address.

The 0x40 tcache bin will now look something like this:  
```c  
0x40 [  3]: 0x559497863700 —▸ 0x7f994e3368d8 (__free_hook-16) —▸
0x7f994e9fd340 ◂— 0x7f994e9fd340  
```

We then created and opened a new file with some other filename length and a
file size of 0x38 for the 0x40 bin.  The create will pop off the 1st 0x40
entry and the open will pop off the 2nd 0x40 entry, `__free_hook`, into a data
buffer.  We then write into this buffer by writing to the newly open file the
magic one_gadget.  We then close this file to trigger a call to `free()` and
in turn jumping to our one_gadget value in `__free_hook`.  We ran `/freader`
to obtain the flag.

```  
[+] Opening connection to cobol.pwni.ng on port 3083: Done  
elf_base: 0x560792499000  
heap_base: 0x5607945f9000  
libc_base: 0x7f3a5e452000  
Run `/freader` for flag  
[*] Switching to interactive mode  
$ /freader  
PCTF{l3arning_n3w_languag3_sh0uld_start_with_g00d_bugs_99d4ec917d097f63107e}  
```  

Original writeup (https://github.com/x64x6a/ctf-
writeups/tree/master/PlaidCTF_2021/pwnable/the_cobol_job).