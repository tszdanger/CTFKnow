We all know this is actually a pwnable challenge in `HITPWN CTF`  ...

So this is an aarch64 executable and we'are able to `leak libc` and `overwrite
function pointer`.

At first, I want to overwrite one of the two pointers to `one_gadget` cause we
already have libc.address. But the registers and stack have been messed up by
data from `/dev/urandom`,  as a result, all `one_gadget` fails.

Then I think if we can set `x0 -> /bin/sh` using the first pointer, we can get
shell by making the second pointer to `system`!

So how to set `x0 -> /bin/sh` using one function pointer? I choose
`getusershell()`.  
```  
GETUSERSHELL(3)                            Linux Programmer's Manual
GETUSERSHELL(3)  
......  
DESCRIPTION  
      The getusershell() function returns the next line from the file /etc/shells, opening the file if neces‐  
      sary.  The line should contain the pathname of a valid user shell.  If /etc/shells does not exist or is  
      unreadable, getusershell() behaves as if /bin/sh and /bin/csh were listed in the file.  
```  
That's to say  
```bash  
HITCON2018_tooooo [master●] bat getusershell.c  
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────  
      │ File: getusershell.c  
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────  
  1   │ #include <unistd.h>  
  2   │ #include <stdio.h>  
  3   │  
  4   │ int main()  
  5   │ {  
  6   │         puts(getusershell());  
  7   │ }  
───────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────  
HITCON2018_tooooo [master●] ./getusershell  
/bin/sh  
```  
So the task becomes simple:  
1. overwrite the first pointer to `getusershell` to set `x0 -> /bin/sh`  
2. overwrite the second pointer to `system` to get shell.  
3. enjoy your shell!

Here is my
[exploit](https://github.com/bash-c/pwn_repo/blob/master/HITCON2018_tooooo/solve.py).

Follow [me](https://github.com/bash-c) if you like this writeup :)

Original writeup
(https://github.com/bash-c/pwn_repo/blob/master/HITCON2018_tooooo/solve.py).