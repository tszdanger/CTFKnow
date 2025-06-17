## TL;DR  
We're given a binary with all protections enabled (notably PIE and full RELRO)
that allows us to do basic arithmetic in integer mode using mmx registers and
floating point mode using x87 registers. The main trick is that on modern x64
processors, mmx registers maps the 64 lsb of the x87 80bit registers. In
particular, this program uses mm7 as a pointer to load and save mmx values. We
have full control on mm7 by storing carefully crafted floating point numbers
and we leverage that for arbitrary read/write.

## interface & mechanisms  
### menu  
```  
Welcome to the frog math calculation facility  
Here we provide state of the art processors for fp and integer math  
0) exit  
1) floating point  
2) integer  
>  
```  
### floating point mode  
```  
fp processing  
0) finish  
1) push  
2) pop  
3) add  
4) sub  
5) mul  
6) div  
7) inspect  
>  
```  
x87 registers work as a stack, you can push values and the two top values are
used for operations. You can also print the top value as a float and as an int
using `inspect`.  
When you push a value on the fp stack, `st0` always holds the top of the
stack. This means that each time you push or pop, you move around the values
of the x87 registers that are on this stack.

### integer mode  
```  
integer processor  
0) finish  
1) set  
2) get  
3) add  
4) sub  
5) mul  
6) div  
7) load  
8) save  
9) clear  
>  
```  
- `load` loads `mm0-mm6` from the buffer on the heap pointed to by `mm7`, then frees and sets `mm7` to `null`.  
- `save` saves `mm0-mm6` to the buffer on the heap pointed to by `mm7` or if `null`, allocates a new buffer

Note that the program logic prevents us from directly setting/getting or doing
any operation on mm7 in integer mode

### Confusing quirk  
Operations on the mmx registers after pushing floating point values moves back
the floating point stack in a circular fashion so that if you set say register
`mm0` in integer mode then push a floating point, then switching back to int
mode and `get(0)` wont get you the floating point you just pushed but the
actual value you set for `mm0` beforehand. However, switching back to floating
point won't switch the stack back ! To get a better grasp of this, it's better
to see for yourself in gdb (use the `i r f` command to print x87 registers).
It is the reason why we cannot store an integer in `mm7`, from setting `mm6`
and then pushing a dummy float on the stack. We have to instead rely on
setting `st` registers in floating point mode.

## Heap leak  
Since PIE is enabled, we have to start from a leak to somewhere. Luckily it is
quite straight forward to leak `mm7`.  
- Push 7 values (`mm7` needs to be null to avoid crash when saving so pushing only 0s gaurantees that)  
- Save mmx registers (`mm7` now holds a heap pointer)  
- Pop 7 times (the stack is now empty so `st0` holds the pointer first stored in `mm7`)  
- Inspect, which will print the pointer

## Setting mm7  
Assuming the fp stack is empty, you push the desired value on the fp stack
then switch back to int mode and do any integer operation. Because of the
stack rolling back in a circular fashion, `mm7` will now hold the value you
pushed.

Easy right ? *NO !!!*

Info on floating point representation :  
- [x87 floats](https://en.wikipedia.org/wiki/Extended_precision#x86_extended_precision_format)  
- [IEEE 754](https://en.wikipedia.org/wiki/IEEE_754)

`mm7` corresponds to the mantissa of `st7` and the mantissa must almost always
start with a msb of 1 which is problematic to store addresses since they have
2 most significant null bytes (the exponent will be decreased, and the
mantissa will be shifted to the left and not correspond anymore to our
address). It took me a while to find a trick to accomodate for that. In fact,
[subnormal numbers](https://en.wikipedia.org/wiki/Subnormal_number), which
have an exponent of 1 (but stored as 0), can have leading null most
significant bits without being equal to 0. So to store value v in mm7 we need
to craft a subnormal number whose mantissa is v.

The cherry on top is that classic floats from python are not precise enough to
compute subnormal numbers in extended precision floating points. I thus used
the library [mp-math](https://mpmath.org/) to do the computations

## The *easy* part  
With a heap leak and full control of `mm7`,  there's arbitrary write and read
thanks to the `load` and `store` operations from integer mode.  
From there I got a libc leak from crafting and freeing a fake chunk in
unsorted bin range (`size > 0x410`), then loading from this chunk (which
contains a head pointer into libc)  
From the libc leak I leaked environ which is a stack pointer at constant
offset from stack frames, and from there it's just classic return to system to
pop a shell.

Note that since `load` calls `free` after loading `mm0-mm6`, a valid chunk
containing the values we want to leak is required to avoid a crash. Thus, I
crafted a 0x40 sized chunk near environ (just set the chunk size to something
in tcache range 8 bytes above environ, and make sure the chunk is aligned
since they are no additional checks when freeing to tcache).

## Flag  
```  
$ python3 exp3.py  
[*] '/home/skuuk/ama23/chal3'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[*] '/usr/lib/x86_64-linux-gnu/libc.so.6'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
Mpmath settings:  
 mp.prec = 200               [default: 53]  
 mp.dps = 59                 [default: 15]  
 mp.trap_complex = False     [default: False]  
[+] Opening connection to amt.rs on port 31171: Done  
[*] heap : 0x55a6e6ae6000  
[*] libc : 0x7f6f1ab56000  
[*] env : 0x7ffd045b8e88  
[*] Loaded 218 cached gadgets for '/usr/lib/x86_64-linux-gnu/libc.so.6'  
[*] Switching to interactive mode  
$ cat flag.txt  
amateurctf{n3v3r_m1x_x87_and_mmx_t0g3th3r}  
```

Original writeup (https://github.com/5kuuk/CTF-
writeups/blob/main/amateurs-2023/frogmath/README.md).