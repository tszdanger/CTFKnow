We are given a sage script in this task:

```python  
from sage.all import *  
from Crypto.Util.number import bytes_to_long, getPrime

import random  
import time  
random.seed(time.time())

message = b'flag{REDACTED}' ## the flag has been removed  
F.<x> = PolynomialRing(GF(2), x)

p, q = [F.irreducible_element(random.randint(2 ** 10, 2 ** 12)) for _ in
range(2)]  
R.<y> = F.quotient_ring(p * q)

n = sum(int(bit) * y ** (len(bin(bytes_to_long(message))[2:]) - 1 - i) for i,
bit in enumerate(bin(bytes_to_long(message))[2:]))

e = 2 ** 256  
c = n ** e

print(e) ## to be given to the user  
print(c) ## to be given to the user  
print(p * q) ## to be given to the user  
```

Seems very scary: polynomials :( But do remember that factorization of a
polynomial is much simpler than factorizing a number $n = p * q$. What happens
here is that, 2 polynomails $p, q$ are generated. The flag is converted into a
binary stream. And based on that, a polynomail is built. That polynomial is
encrypted using $e = 2^{256}$ and $n=p*q$.

My idea was to take square root (`quadratic residue`) of the encrypted
polynomial a 256 times to get the original polynomial. But to do that, we need
to do that individually mod $p$ and mod $q$ and then combine the roots via
`CRT`. Taking the quadratic residue is easy as there are built in functions in
sagemath.

```python  
p, q = factor(n)  
p, q = p[0], q[0]  
p, q

Rp.<Y> = GF(2^p.degree(), modulus = p)  
poly1 = Rp(c)  
r1 = poly1  
for _ in range(256):  
   r1 = r1.sqrt()

print(r1)

Rq.<Y> = GF(2^q.degree(), modulus = q)  
poly2 = Rq(c)  
r2 = poly2  
for _ in range(256):  
   r2 = r2.sqrt()

print(r2)

res = [r1, r2]  
mod = [p, q]  
sol = crt(res, mod)

from Crypto.Util.number import long_to_bytes

coeff = [str(i) for i in sol.list()]  
msg = int(''.join(coeff[::-1]), 2)  
long_to_bytes(msg)  
```

Original writeup (https://tsumiiiiiiii.github.io/bdoorctf/#prsa).