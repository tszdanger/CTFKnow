10 times you are given a number N (which is bigger each time) and your task is
to send over numbers a, b such that gcd(a,b)+lcm(a,b) = N, with a>b and a>0
and b>0. You have 1 second for each submission before it times out.

Steps:  
1. Figure out how to send data over; would need to be done with a script because of the time limits (used Python + pwntools for that)  
2. Get excited about the potential solver use; get frustrated when z3 and sympy aren't helpful.  
3. Go to sleep.  
4. Wake up and figure out that for an N > 2, you can write it down as N-1 + 1 and this fulfills both criteria.  
5. Finish coding.  
6. ???  
7. Profit.

And the flag was **ptm{as_dumb_as_a_sanity_check}** (savage!)

```  
from pwn import *  
from helpers import bytes_to_string  
import re

if __name__ == "__main__":  
   pattern = r'\d+'  
   try:  
       conn = remote('challs.m0lecon.it', 10000)  
       c = bytes_to_string(conn.recv())  
       num = int(re.findall(pattern, c)[-1])  
       conn.sendline('%s %s' % (num-1, 1))  
       for i in list(range(1,11)):  
           conn.recvline()  
           c = bytes_to_string(conn.recvline())  
           print(c)  
           num = int(re.findall(pattern, c)[-1])  
           conn.sendline('%s %s' % (num-1, 1))  
   except EOFError:  
       pass  
```