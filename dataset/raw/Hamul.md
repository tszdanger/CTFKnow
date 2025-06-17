## Hamul

### Challenge

> RSA could be hard, or easy?  
> -
> [hamul_e420933a0655ea08209d1fe9588ba8a3a6db6bf5.txz.txz](https://cr.yp.toc.tf/tasks/hamul_e420933a0655ea08209d1fe9588ba8a3a6db6bf5.txz)

```python  
#!/usr/bin/env python3

from Crypto.Util.number import *  
from flag import flag

nbit = 64

while True:  
   p, q = getPrime(nbit), getPrime(nbit)  
   P = int(str(p) + str(q))  
   Q = int(str(q) + str(p))  
   PP = int(str(P) + str(Q))  
   QQ = int(str(Q) + str(P))  
   if isPrime(PP) and isPrime(QQ):  
       break

n = PP * QQ  
m = bytes_to_long(flag.encode('utf-8'))  
if m < n:  
   c = pow(m, 65537, n)  
   print('n =', n)  
   print('c =', c)

# n =
98027132963374134222724984677805364225505454302688777506193468362969111927940238887522916586024601699661401871147674624868439577416387122924526713690754043  
# c =
42066148309824022259115963832631631482979698275547113127526245628391950322648581438233116362337008919903556068981108710136599590349195987128718867420453399  
```

### Solution

Since we can see that the generation of $PP$ and $QQ$ is special:

```python  
while True:  
   p, q = getPrime(nbit), getPrime(nbit)  
   P = int(str(p) + str(q))  
   Q = int(str(q) + str(p))  
   PP = int(str(P) + str(Q))  
   QQ = int(str(Q) + str(P))  
   if isPrime(PP) and isPrime(QQ):  
       break  
```

If we let `x, y = len(str(p)), len(str(q))`, we will get:

$$  
P = 10^{x}p + q,\, Q = 10^{y}q + p  
$$

Also we let `x', y' = len(str(P)), len(str(Q))`, we will get:

$$  
PP = 10^{x'}P+Q,\, QQ=10^{y'}Q+P  
$$

After we put $P = 10^{x}p + q,\, Q = 10^{y}q + p$ into the above equation and
calculate

$$  
N=PP \cdot QQ  
$$

we will find $N$ looks like in this form:

$$  
N = 10^{x+x'+y+y'}pq + \ldots +pq  
$$

Since $x+x'+y+y'$ is big enough, so we know that `str(N)[:?]` is actually
`str(pq)[:?]` and as the same, `str(N)[?:]` is actually `str(pq)[?:]`.

After generating my own testcase, I find that `str(N)[:18] = str(pq)[:?]`,
`str(N)[-18:] = str(pq)[-18:]` and actually `len(str(p*q)) = 38` so we just
need brute force 2 number between the high-part and low-part.

So we can get $pq$ and factor it to get $p$ and $q$. The next is simple
decryption.

```python  
from Crypto.Util.number import *  
from tqdm import tqdm

def decrypt_RSA(c, e, p, q):  
   phi = (p-1) * (q-1)  
   d = inverse(e, phi)  
   m = pow(c, d, p*q)  
   print(long_to_bytes(m))

n =
98027132963374134222724984677805364225505454302688777506193468362969111927940238887522916586024601699661401871147674624868439577416387122924526713690754043  
c =
42066148309824022259115963832631631482979698275547113127526245628391950322648581438233116362337008919903556068981108710136599590349195987128718867420453399

low = str(n)[-18:]  
high = str(n)[:18]  
pq_prob = []

for i in range(10):  
   for j in range(10):  
       pq_prob.append(int(high + str(i) + str(j)+ low))  
  
for x in tqdm(pq_prob):  
   f = factor(x)  
   if (len(f) == 2 and f[0][0].nbits() == 64):  
       p, q = f[0][0], f[1][0]  
       break

P = int(str(p) + str(q))  
Q = int(str(q) + str(p))  
PP = int(str(P) + str(Q))  
QQ = int(str(Q) + str(P))  
N = PP * QQ  
print(N == n)  
decrypt_RSA(c, 65537, PP, QQ)  
```

##### Flag  
`CCTF{wH3Re_0Ur_Br41N_Iz_5uP3R_4CtIVe_bY_RSA!!}`

Original writeup (https://blog.cryptohack.org/cryptoctf2021-easy#hamul).