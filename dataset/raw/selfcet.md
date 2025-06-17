# selfcet

## Vulnerability

The program contains a buffer overflow related to the following struct:

```c  
typedef struct {  
 char key[KEY_SIZE];  
 char buf[KEY_SIZE];  
 const char *error;  
 int status;  
 void (*throw)(int, const char*, ...);  
} ctx_t;  
```

where one can write `sizeof(ctx_t)` bytes first into `key` and then into
`buf`.  
After each of these two writes, the program checks `status` and calls  
`throw()`:

```  
 if (ctx->status != 0)  
   CFI(ctx->throw)(ctx->status, ctx->error);  
```

Furthermore, the binary is compiled without PIE:

```  
   RELRO:    Full RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
```

so it should surely be easy to do `write@PLT(&write@GOT)` to leak the libc
base  
followed by [one_gadget](https://github.com/david942j/one_gadget)? Not quite.

## CFI

`CFI()` macro is part of the challenge; it checks whether a function pointer  
points to an `endbr64` instruction. CFI stands for [Control Flow Integrity](  
https://en.wikipedia.org/wiki/Control-flow_integrity), which is a generic term  
for various mitigations that prevent an attacker from redirecting the control  
flow. Intel's implementation of CFI is called CET ([Control Flow Enforcement  
Technology](  
https://en.wikipedia.org/wiki/Control-flow_integrity#Intel_Control-
flow_Enforcement_Technology  
)), hence the name of this challenge.

By itself `endbr64` is just a nop. But CPUs implementing CET require that when  
an indirect jump or an indirect call is executed, it must target an `endbr64`,  
otherwise a `#CP` exception is raised. `endbr64` was given such an encoding,  
that it has a very low change of occurring in the middle of a different  
instruction.

GCC and Clang insert `endbr64` instructions when `-fcf-protection=branch` is  
specified. In preparation for CET deployment, many binaries in Linux distros,  
including libc, were rebuilt with this flag.

Therefore, `one_gadget` will not work. We can call only function entry points.

Furthermore, the challenge was compiled with something like  
`-fno-pie -Wl,-no-pie -fno-plt`, and as a result there is only GOT, but no
PLT.

Finally, the challenge was compiled without `-fcf-protection=branch`, so we  
cannot even call `main`, which may be useful for writing more than two times.

## Partial overwrite

We can overwrite two least significant bytes of `throw`, so that the result  
still points into libc. Initially it points to `err`, and there is

```  
void warn(const char *fmt, ...);  
```

not far from it:

```  
$ nm -CD libc.so.6 | sort | grep -w err -C 4  
0000000000121010 T warn@@GLIBC_2.2.5  
00000000001210d0 T warnx@@GLIBC_2.2.5  
0000000000121190 T verr@@GLIBC_2.2.5  
00000000001211b0 T verrx@@GLIBC_2.2.5  
00000000001211d0 T err@@GLIBC_2.2.5  
0000000000121270 T errx@@GLIBC_2.2.5  
00000000001214e0 W error@@GLIBC_2.2.5  
0000000000121700 W error_at_line@@GLIBC_2.2.5  
00000000001217b0 T ustat@GLIBC_2.2.5  
```

It doesn't quite match the `throw()` signature, but the binary's base is  
`0x400000`, so `write@GOT` fits into an `int`. With that, we leak libc base.

## GDB Python API

Note that ASLR granularity is one page (12 bits), so from the 4 hex nibbles we  
overwrite we know only 3. Therefore, this has 1/16 chance of succeeding. One  
can live with that on the remote, but during debugging that's annoying.

For debugging, we can get the `warn` address using the pwntools' [GDB Python  
API](https://docs.pwntools.com/en/dev/gdb.html#using-gdb-python-api):

```  
tube = gdb.debug(["selfcet/xor"], stdin=PTY, stdout=PTY, stderr=PTY, api=True)  
warn_libc = int(tube.gdb.parse_and_eval("&warn"))  
tube.gdb.continue_nowait()  
```

## Digression - pwntools and sockets

Initially I wanted to do `send(0, &write@GOT, ...)`. There are many problems  
with it, and since I spent some time fighting them, I will write them down.

First, we cannot use `0` as the first argument, because the `status` check
will  
succeed and `throw()` will not be called. Fortunately, the challenge runs
under  
xinetd, so file descriptors 0, 1 and 2 refer to the same thing: the client  
socket. With that, one can do `send(1, ...)` on the remote instead. Locally  
with pwntools we can use the `PTY` constant to achieve roughly the same
effect.

Well, not exactly the same. `send()` wants a socket, not a PTY. So one needs
to  
create a `socketpair()` and use it when starting a process. Apparently  
neither pwntools nor subprocess support this, so I [monkey-patched](  
https://github.com/mephi42/ctf/blob/master/2023.09.16-SECCON_CTF_2023_Quals/selfcet/pwntools-
sockets.py) that in.

After all this I realized that the third argument was always the same as the  
second one:

```  
 4011a5:       48 89 d6                mov    %rdx,%rsi  
 4011a8:       89 c7                   mov    %eax,%edi  
 4011aa:       b8 00 00 00 00          mov    $0x0,%eax  
 4011af:       ff d1                   call   *%rcx  
```

and `send()` always returned an `EFAULT` because of that, so the effort had to  
be scrapped.

## Looping

Since `one_gadget` is out of the question, we need to do `system("/bin/sh")`.  
The problem is that there is no string `"/bin/sh"` in the challenge binary,
and  
we cannot use the one from libc, because libc addresses do not fit into an  
`int`. Therefore, we need to read this string into the `.bss` section first,  
which uses up the second and the last write. So we need to find a way to loop  
back to `main()`.

For that, we use `atexit(main)`. After `main()` exits, it will be called
again.

## Exploitation

Similar to what I tried above with `send()`, do `read(1, bss, bss)`. This time  
a monstrous length is okay, since only a few bytes will be touched.

Send `b"/bin/sh\0"` and finally do `system(bss)`.

## Flag

`SECCON{b7w_CET_1s_3n4bL3d_by_arch_prctl}`

The intended solution was to `prctl(ARCH_SET_FS, bss)`, which effectively sets  
the security cookie to 0. Since the overflow is big enough, one can reach the  
return address from `main()` and start ROPping.  

Original writeup
(https://github.com/mephi42/ctf/tree/master/2023.09.16-SECCON_CTF_2023_Quals/selfcet).