# **THC CTF 2021**  
--------------------------------------

## Crypto - Rsa Internal Attacker  
## Points: 206  


```  
I've found this rsa implementation, it is quite strange. I have a
public/private key and I've also intercepted a ciphertext  
but infortunately it was not for me, so I can't read it. But I'am really
curious, can you decrypt it ? :)

Files:

chall.py  
   output.txt  
```

We are given this code and some output to decrypt

``` python  
from Crypto.Util.number import getPrime, inverse, bytes_to_long  
import random  
from math import gcd

def init():  
   p = getPrime(1024)  
   q = getPrime(1024)  
   return p, q

def new_user(p, q):  
   phi = (p - 1) * (q - 1)  
   while True:  
       e = random.randint(2, 100000)  
       if gcd(e, phi) == 1:  
           break  
   d = inverse(e, phi)  
   return e, d

def encrypt(m, e, n):  
   return pow(m, e, n)

p, q = init()  
n = p * q  
e_a, d_a = new_user(p, q)  
e_b, d_b = new_user(p, q)

FLAG = b"THC2021{??????????????????????????????????????}"

c = encrypt(bytes_to_long(FLAG), e_b, n)

print(f"The public modulus : {hex(n)}")  
print(f"Your key pair : ({hex(e_a)}, {hex(d_a)})")  
print(f"Your boss public key : {hex(e_b)}")  
print(f"Intercepted message : {hex(c)}")

```

RSA cryptographic strength relies in the known difficulty of solving the
mathematical  
problem of big numbers factorization.  
From 2 primes P and Q, it is computed n (our modulo), and from there, public
key e  
is choosen. Finally, d is calculated.  
Two parties sharing the same modulo n, are practically sharing the same keys,
even  
choosing diferent e, because P and Q are the same for both.  
   
The great book "Serious Cryptography" by Aumasson, shares this smart code for  
retrieving P and Q from knowns n, e and d:

```python  
from math import gcd

kphi = d*e - 1  
t = kphi

while t % 2 == 0:  
   t = divmod(t, 2)[0]

a = 2  
while a < 100:  
    k = t  
    while k < kphi:  
            x = pow(a, k, n)  
            if x != 1 and x != (n - 1) and pow(x, 2, n) == 1:  
                p = gcd(x - 1, n)  
                break  
            k = k*2  
    a = a + 2

q = n//p  
assert (p*q) == n  
print('p = ', p)  
print('q = ', q)  
print('phi is ', (p-1)*(q-1))  
```

Knowing P and Q, it is trivial to derive d' from a different e', and later  
decrypt the ciphertext

```  
THCon21{coMm0n_m0duLus_wh1th_int3rn4l_aTt4ck3r}'  
```

Original writeup (https://github.com/SCH227/CTF-
WriteUps/blob/main/THC%20CTF%202021/THC_WriteUp.md).