> As part of his CTF101 class, Gerald needs to find the plaintext that his
> teacher encrypted. Can you help him do his homework? ( It's definetely not
> cheating ;) )

> Author: akth3n3rd

We're given p, q, n, e, ct. I adapted a script from stackoverflow that now
looks like this:  
```python  
# based on https://crypto.stackexchange.com/a/68732

import math  
import binascii

def getModInverse(a, m):  
   if math.gcd(a, m) != 1:  
       return None  
   u1, u2, u3 = 1, 0, a  
   v1, v2, v3 = 0, 1, m

   while v3 != 0:  
       q = u3 // v3  
       v1, v2, v3, u1, u2, u3 = (  
           u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3  
   return u1 % m

def main():  
   p = int(input('p: ').strip())  
   q = int(input('q: ').strip())  
   e = int(input('e: ').strip())  
   ct = int(input('ct (as hex): ').strip(), 16)

   n = p*q

   # compute n  
   n = p * q

   # Compute phi(n)  
   phi = (p - 1) * (q - 1)

   # Compute modular inverse of e  
   d = getModInverse(e, phi)

   print("n:  " + str(d))

   # Decrypt ciphertext  
   pt = pow(ct, d, n)  
   print()  # separate IO  
   print("pt (as hex): " + hex(pt)[2:])  
   print("pt (as string): " + binascii.unhexlify(hex(pt)[2:]).decode())

if __name__ == "__main__":  
   main()  
```

Here's the input/output:  
```  
p: 251867251891350186672194341006245222227  
q: 31930326592276723738691137862727489059  
e: 65537  
ct (as hex): b99efa97a6800b4a07f2ccb1ba0c02d8a1d07e538ac618d773d35a45cacee47

n:
4895611838388522487150697438371515909261488525071715048233750808546849654653  
pt (as hex): 6263616374667b5253415f49535f454153595f41465445525f414c4c7d  
pt (as string): bcactf{RSA_IS_EASY_AFTER_ALL}  
```  

Original writeup (https://eb-h.github.io/bcactf-2021/#easy-rsa).# Easy RSA  
> Points: 407

## Description  
> Just a easy and small E-RSA for you :)  
>  
>[File](https://mega.nz/file/600TkQbK#0o6mqJjLxReiBoP3HAtsYj8ulp9K99246EdzmeVNiS4)

## Solution

A very simple RSA form :) The modulo **N** isn't given. Why?

Because we don't need it!

Assuming the **N** to be a big 2048-bit number (general format) and my
plaintext (flag) to be relatively small it's clear that `(pt ^ e) < N`

This is the vulnerabilty as `a mod b = a when a < b` so ct = (pt ^ e) mod N
becomes equivalent to ct = (pt ^ e).

Taking e-th root of ciphertext will retrieve the plaintext (flag).

```py  
#!/bin/env python3

from Crypto.Util.number import long_to_bytes  
import gmpy2

ct =
70415348471515884675510268802189400768477829374583037309996882626710413688161405504039679028278362475978212535629814001515318823882546599246773409243791879010863589636128956717823438704956995941  
e = 3

# Calculating e-th root of ciphertext  
pt = gmpy2.iroot(ct,e)[0]  
print("Flag is : " + str(long_to_bytes(pt).decode()))  
```

## Flag  
> darkCTF{5m4111111_3_4tw_xD}  

Original writeup (https://github.com/t3rmin0x/CTF-
Writeups/tree/master/DarkCTF/Crypto/Easy%20RSA).