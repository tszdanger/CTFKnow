# umemo

## Goal

This is the first challenge out of three in the fullchain challenge series. We  
are given a QEMU VM, into which we can log in using the `ctf` user, but
instead  
of a shell we get a memo app. The goal is to get a shell and read the first  
flag.

The author has provided the source code for the memo app and for the subset of  
the driver that the app talks so.

## App

The app opens the device and `mmap()`s the first page. It splits the page into  
16 256-byte parts. The first part contains the pointers to the other 15 parts.  
The user can read and write into the other parts.

The user can also read and write into the device by specifying an offset and a  
size. The first page is excluded from this with the following check:

```  
if((offset = getint() + 0x1000) < 0x1000 || lseek(fd, offset, SEEK_SET) < 0){  
       puts("Out of range");  
```

If we are somehow able to circumvent this and access the first page anyway, we  
get the arbitrary read/write capability.

## Vulnerability

The maximum amount of data that the device can hold is `MEMOPAGE_SIZE_MAX`,  
which is 1G. If we start the access from the last byte, the offset will wrap  
around and start referencing the first page.

The module stores the data with page granularity. The functions
`get_memo_ro()`  
and `get_memo_rw()` return the pointer to the page associated with a given  
offset. `chrdev_read()` and `chrdev_write()` loop over pages and perform the  
respective operation. Unlike `chrdev_seek()`, they don't have any bounds  
checks, so it's only natural to wonder what would happen if the loop starts in  
bounds, but goes out of bounds.

Unfortunately one cannot see this in the provided `char.c` file. One can,  
however, either reverse the module, or get the `memo.c` file from the next  
kmemo challenge.

Ultimately the problem is that `__pgoff_to_memopage()` looks only at the lower  
30 bits of the offset and ignores the others, so `MEMOPAGE_SIZE_MAX` is
treated  
the same way as 0.

## Exploitation plan

There are many ways to leverage the arbitrary read-write capability for
getting  
code execution. The leaked part addresses point to the mmap area, which also  
contains libc. We don't know where the binary, the heap and the stack are.

I chose faking an `atexit()` descriptor. libc's `__exit_funcs` variable points  
to a `struct exit_function_list`:

```  
struct exit_function_list  
 {  
   struct exit_function_list *next;  
   size_t idx;  
   struct exit_function fns[32];  
 };  
```

For our purposes `next` needs to be `NULL` and `idx` needs to be 1 (the number  
of elements in the following array). `struct exit_function` is defined as  
follows:

```  
struct exit_function  
 {  
   /* `flavour' should be of type of the `enum' above but since we need  
      this element in an atomic operation we have to use `long int'.  */  
   long int flavor;  
   union  
     {  
       void (*at) (void);  
       struct  
         {  
           void (*fn) (int status, void *arg);  
           void *arg;  
         } on;  
       struct  
         {  
           void (*fn) (void *arg, int status);  
           void *arg;  
           void *dso_handle;  
         } cxa;  
     } func;  
 };  
```

There are 3 different function pointer types that one can call, distinguished  
by the `flavor` value: without arguments (`ef_at == 3`), with `int, void *`  
arguments (`ef_on == 2`) and with `void *, int` arguments (`ef_cxa == 4`).

The easiest would be to use any of them with one_gadget. Unfortunately we have  
no means to satisfy the one_gadget constraints in this challenge. An  
alternative is to use `ef_cxa` with `system()` and `"/bin/sh"`.

Using arbitrary write, one can craft an `exit_function_list` instance in
libc's  
`.bss` and overwrite `__exit_funcs` with a pointer to it.

## TTY problems

We don't interface with the memo application's stdin/stdout directly. Between  
us sits the TTY layer, which does ugly things to the data we send. As long as  
we deal with printable characters, everything is fine and dandy. But we need
to  
send binary data in order to fake the part pointers and the `atexit()`  
descriptor. And some of that data may be treated as terminal control  
characters.

[`man 3 termios`](https://man7.org/linux/man-pages/man3/termios.3.html) is our  
best friend here. From that we learn that `0x7f` aka `0177` is a control  
character called `VERASE`, which is essentially a backspace. This one is very  
important, because it occurs in all the `mmap()`ped addresses. This handicaps  
us severely: instead of directly crafting what we need, we need to do partial  
overwrites on data that already contains `0x7f`. For example, the first part  
pointer already has it. Therefore, it's sufficient to overwrite only its
lowest  
5 bytes.

Here comes the next problem: it appears that any data we send must end with a  
newline, or the TTY layer won't forward it to the app. Of course, we could try  
sending a lot and exhaust some internal buffer, which would force a flush, but  
we need to send exactly 5 bytes. Fortunately for us, the manual points to the  
`VEOF` control character, aka `0x4`, aka `Ctrl-D`, which forces a flush. The  
downside is, of course, that we cannot use `0x4` in our payloads as well.

How many more characters are there that we can't use? I counted these:

```  
BAD_CHARS = b"\x03\x04\x0a\x11\x13\x7f"  
```

This means we have to restart the app until ASLR gives us an address without  
any of them. An easy fix, by the way, would be to use the `VLNEXT` aka `0x16`  
aka `026` control character, which escapes the next character after it.  
Unfortunately it's recognized only when `IEXTEN` is set, and it's not. This
can be confirmed  
by getting the shell in the local setup and running:

```  
$ stty -a  
[...]  
isig icanon -iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt  
echoctl echoke -flusho -extproc  
```

Back to `0x4`, it's `ef_cxa`, which we need for our exploitation. So we need
to  
find an existing writable memory region, which contains:

```  
04 .. .. .. .. .. .. ..  
.. .. .. .. .. .. .. ..  
.. .. .. .. .. 7f .. ..  
```

and fill the blanks with the `struct exit_function_list` contents. I ended up  
eyeballing the `.data` and `.bss` sections and found such a location
relatively  
quickly.

Finally, the initial `__exit_funcs` value is `&initial`, which is inside libc,  
so a partial overwrite works for it as well.

## Debugging

The challenge runs in a VM with quite a primitive userspace. The debugger is  
not available and building one is a hassle. How to debug crashes and eyeball  
section contents?

I used the [initramfs-wrap](https://github.com/mephi42/initramfs-wrap/)
script,  
which adds a Debian root that contains GDB (and anything else one can wish
for)  
and moves the original contents into a chroot. It allowed me to run the  
challenge in one tmux tab and GDB in the other. It was also possible to run  
GDB on the host and connect it to the gdbserver in the guest, since the guest  
kernel was compiled with network support.

## Flag

`SECCON{k3rn3l_bug5_5p1ll_0v3r_1n70_u53r_pr0gr4m5}`

The code uses nested C functions (a GNU extension), which makes the stack  
executable. One can find the location of the stack by looking at the `environ`  
variable, which is located inside libc. This opens up an alternative  
exploitation direction: write the shellcode to the stack.  

Original writeup
(https://github.com/mephi42/ctf/tree/master/2023.09.16-SECCON_CTF_2023_Quals/umemo).