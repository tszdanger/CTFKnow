## Farm

### Challenge

> Explore the Farm very carefully!  
> -
> [farm.txz](https://cryp.toc.tf/tasks/farm_0a16ef99ff1f979039cda1a685ac0344b927eee6.txz)

```python  
#!/usr/bin/env sage

from sage.all import *  
import string, base64, math  
from flag import flag

ALPHABET = string.printable[:62] + '\\='

F = list(GF(64))

def keygen(l):  
   key = [F[randint(1, 63)] for _ in range(l)]  
   key = math.prod(key) # Optimization the key length :D  
   return key

def maptofarm(c):  
   assert c in ALPHABET  
   return F[ALPHABET.index(c)]

def encrypt(msg, key):  
   m64 = base64.b64encode(msg)  
   enc, pkey = '', key**5 + key**3 + key**2 + 1  
   for m in m64:  
       enc += ALPHABET[F.index(pkey * maptofarm(chr(m)))]  
   return enc

# KEEP IT SECRET  
key = keygen(14) # I think 64**14 > 2**64 is not brute-forcible :P

enc = encrypt(flag, key)  
print(f'enc = {enc}')  
```

The key is the product of 14 random elements selected from $GF(64)$.

### Solution

Note that the product of two elements of $GF(64)$ is still an element of
$GF(64)$. Inductively, the key lies in $GF(64)$. That is, the key space is
just 64 and hence we are able to brute-force the key.

### Implementation

```python  
#!/usr/bin/env sage  
import string  
import base64

enc = "805c9GMYuD5RefTmabUNfS9N9YrkwbAbdZE0df91uCEytcoy9FDSbZ8Ay8jj"

ALPHABET = string.printable[:62] + '\\='  
F = list(GF(64))

def farmtomap(f):  
   assert f in F  
   return ALPHABET[F.index(f)]

def decrypt(msg, key):  
   dec, pkey = '', key**5 + key**3 + key**2 + 1  
   for m in msg:  
       dec += farmtomap(F[ALPHABET.index(m)] / pkey)

   return base64.b64decode(dec)

for possible_key in F:  
   try:  
       plaintext = decrypt(enc, possible_key)  
       if b"CCTF{" in plaintext:  
           print(plaintext.decode())  
   except:  
       continue  
```

##### Flag  
`CCTF{EnCrYp7I0n_4nD_5u8STitUtIn9_iN_Fi3Ld!}`

Original writeup (https://blog.cryptohack.org/cryptoctf2021-easy#farm).