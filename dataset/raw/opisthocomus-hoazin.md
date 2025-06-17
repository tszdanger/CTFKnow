# opisthocomus-hoazin (376 solves, 300 points)  
## Description  
I started by running test values through the algorithm. Specifically,
``flag{`` turned out to be ``65639, 65645, 65632, 65638, 65658``. This is how
the flag output starts so  
once again we can create a key using the same method as in [aptenodytes-
forsteri](https://github.com/BASHing-thru-
challenges/HSCTF-2021-Writeups/tree/main/crypto/aptenodytes-forsteri).  
This time we have to use the entire ascii character set though.

The output was much longer than the first challenge so I took the time to read
it from a file and decode the flag using the created lookup table.

Here's the script to do so:  
```python3

import time  
from Crypto.Util.number import *  
import linecache  
keyText =
"abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()-=_+ABCDEFGHIJKLMNOPQRSTUVWXYZ[]{}`~'\"\\
/?.>,<"  
key = {}  
def encrypt():  
   p = getPrime(1024)  
   q = getPrime(1024)  
   e = 2**16+1  
   n=p*q  
   ct=[]  
   i = 0  
   for ch in keyText:  
       ct.append((ord(ch)^e)%n)  
       key[ch] = str(ct[i])  
       i += 1

encrypt()  
plainText = list(key.keys())  
cypherText = list(key.values())  
data = linecache.getline('hoazin.txt', 4)  
flag = data.split(', ')  
flag[-1] = flag[-1].rstrip()  
flagText = ""  
for ct in flag:  
   pos = cypherText.index(ct)  
   flagText += plainText[pos]  
print(flagText)

```  
## Flag  
``flag{tH1s_ic3_cr34m_i5_So_FroZ3n_i"M_pr3tTy_Sure_iT's_4ctua1ly_b3nDinG_mY_5p0On}``  

Original writeup (https://github.com/BASHing-thru-
challenges/HSCTF-2021-Writeups/tree/main/crypto/opisthocomus-hoazin).