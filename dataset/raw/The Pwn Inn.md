## The Pwn Inn

> **Points** 477  
>  
>  
>As we know that crypto is a hot potato right now, we wanted to welcome you to
a safe place, The Pwn Inn. We've had many famous faces stay in our Inn, with
gets() and printf() rating us 5 stars. We've decided to start making an app,
and wanted you guys to be our beta testers! Welcome!  
>  
>`EU instance: 161.97.176.150 2626`  
>  
>`US instance: 185.172.165.118 2626`  
>  
>author: Tango

## Challenge Overview

This was a 64-bit executable file that was dynamically linked and was not
stripped. The protections included `Partil RELRO` and `NO PIE`.  
The executable asked for some input and printed it back. Therefore I had to
check for a  `format string bug` :/ and boom there was a  
format string bug.

## Exploit Overview

I used the format string bug to overwrite the `exit()` function's `got` with
the address of `vuln` this was used to give me recursive calls to  
vuln and therefore recursive `reads` and `writes`.

I leaked the address of the `got entry` of `puts` to leak the libc address to
find the offset to `system` online. Finally to get a shell I overwrote the
`got`  
entry of `printf` with system.  
Therefore whenever we pass in our input via `fgets` it is passed through
`system` instead of `printf`.

The final exploit is @ [exploit](exploit.py)

## Flag

After spwaning a shell the flag is therefore

flag{GOTt4_b3_OVERWRITEing_th0s3_symb0ls_742837423}  

Original writeup (https://github.com/mutur4/CTF-
WRITEUPS-2021/blob/main/0x41414141%20CTF/The%20Pwn%20Inn/solution.md).