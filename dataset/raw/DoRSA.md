## DoRSA  
### Challenge

> Fun with RSA, this time [two
> times](https://cr.yp.toc.tf/tasks/DoRSA_17cab1318229a0207b1648615db1edc6497f8b62.txz)!

```python  
#!/usr/bin/env python3

from Crypto.Util.number import *  
from math import gcd  
from flag import FLAG

def keygen(nbit, dbit):  
   assert 2*dbit < nbit  
   while True:  
       u, v = getRandomNBitInteger(dbit), getRandomNBitInteger(nbit // 2 - dbit)  
       p = u * v + 1  
       if isPrime(p):  
           while True:  
               x, y = getRandomNBitInteger(dbit), getRandomNBitInteger(nbit // 2 - dbit)  
               q = u * y + 1  
               r = x * y + 1  
               if isPrime(q) and isPrime(r):  
                   while True:  
                       e = getRandomNBitInteger(dbit)  
                       if gcd(e, u * v * x * y) == 1:  
                           phi = (p - 1) * (r - 1)  
                           d = inverse(e, phi)  
                           k = (e * d - 1) // phi  
                           s = k * v + 1  
                           if isPrime(s):  
                               n_1, n_2 = p * r, q * s  
                               return (e, n_1, n_2)

def encrypt(msg, pubkey):  
   e, n = pubkey  
   return pow(msg, e, n)

nbit, dbit = 1024, 256

e, n_1, n_2 = keygen(nbit, dbit)

FLAG = int(FLAG.encode("utf-8").hex(), 16)

c_1 = encrypt(FLAG, (e, n_1))  
c_2 = encrypt(FLAG, (e, n_2))

print('e =', e)  
print('n_1 =', n_1)  
print('n_2 =', n_2)

print('enc_1 =', c_1)  
print('enc_2 =', c_2)  
```

```  
e =
93546309251892226642049894791252717018125687269405277037147228107955818581561  
n_1 =
36029694445217181240393229507657783589129565545215936055029374536597763899498239088343814109348783168014524786101104703066635008905663623795923908443470553241615761261684865762093341375627893251064284854550683090289244326428531870185742069661263695374185944997371146406463061296320874619629222702687248540071  
n_2 =
29134539279166202870481433991757912690660276008269248696385264141132377632327390980628416297352239920763325399042209616477793917805265376055304289306413455729727703925501462290572634062308443398552450358737592917313872419229567573520052505381346160569747085965505651160232449527272950276802013654376796886259  
enc_1 =
4813040476692112428960203236505134262932847510883271236506625270058300562795805807782456070685691385308836073520689109428865518252680199235110968732898751775587988437458034082901889466177544997152415874520654011643506344411457385571604433702808353149867689652828145581610443408094349456455069225005453663702  
enc_2 =
2343495138227787186038297737188675404905958193034177306901338927852369293111504476511643406288086128052687530514221084370875813121224208277081997620232397406702129186720714924945365815390097094777447898550641598266559194167236350546060073098778187884380074317656022294673766005856076112637129916520217379601  
```

Basically, we have

$$  
p = uv + 1, \quad q = uy + 1, \quad r = xy + 1, \quad s = kv + 1  
$$

where $p, q, r, s$ are all primes. Also, $\phi = (p-1)(r-1) = uvxy$ and $ed
\equiv 1 \pmod \phi$.  
$k$ is calculated by $k = (ed - 1)/\phi$. It is notable that $e$ is $256$
bits.

Our goal is to decrypt RSA-encrypted messages, so we need to find one of
$\phi(n_1)$ or $\phi(n_2)$.

### Solution

Not so long after starting this problem, rbtree suggested using continued
fractions with

$$  
n_2 / n_1 \approx k / x  
$$

Indeed, we see that

$$  
\frac{n_2}{n_1} = \frac{qs}{pr} = \frac{(uy+1)(kv+1)}{(uv+1)(xy+1)} \approx
\frac{uykv}{uvxy} = \frac{k}{x}  
$$

and their difference is quite small, as

$$  
\frac{n_2}{n_1} - \frac{k}{x} = \frac{(uy+1)(kv+1)x -
(uv+1)(xy+1)k}{x(uv+1)(xy+1)}  
$$

and the numerator is around $256 \times 3$ bits, and the denominator is around
$256 \times 5$ bits.

Note that $k/x$ has denominator around 256 bits, and it approximates $n_2/n_1$
with difference around $2^{-512}$. If you know the proof for Wiener's Attack
(highly recommend you study it!) you know that this implies that $k/x$ must be
one of the continued fractions of $n_2/n_1$. Now, we can get small number of
candidates for $k/x$. We also further assumed $\gcd(k, x) = 1$. If we want to
remove this assumption, it is still safe to assume that $\gcd(k, x)$ is a
small integer, and brute force all possible $\gcd(k, x)$ as well. Now we have
a small number of candidates for $(k, x)$.

I finished the challenge by noticing the following three properties.

First, $k \phi + 1 \equiv 0 \pmod{e}$, so that gives $256$ bit information on
$e$.

Second, $\phi \equiv 0 \pmod x$, so that gives another $256$ bit information
on $x$.

Finally,

$$  
|\phi - n_1| = |(p-1)(r-1) - pr| \approx p + r \le 2^{513}  
$$

Therefore, we can use the first two facts to find $\phi \pmod{ex}$.  
Since $ex$ is around $512$ bits, we can get a small number of candidates for
$\phi$ using the known bound for $\phi$. If we know $\phi$, we can easily
decrypt $c_1$ to find the flag.

```python  
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5  
from Crypto.PublicKey import RSA  
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime,
getPrime, GCD  
from tqdm import tqdm  
from pwn import *  
from sage.all import *  
import itertools, sys, json, hashlib, os, math, time, base64, binascii,
string, re, struct, datetime, subprocess  
import numpy as np  
import random as rand  
import multiprocessing as mp  
from base64 import b64encode, b64decode  
from sage.modules.free_module_integer import IntegerLattice  
from ecdsa import ecdsa

def inthroot(a, n):  
   if a < 0:  
       return 0  
   return a.nth_root(n, truncate_mode=True)[0]

def solve(n, phi):  
   tot = n - phi + 1  
   dif = inthroot(Integer(tot * tot - 4 * n), 2)  
   dif = int(dif)  
   p = (tot + dif) // 2  
   q = (tot - dif) // 2  
   if p * q == n:  
       return p, q  
   return None, None

e =
93546309251892226642049894791252717018125687269405277037147228107955818581561  
n_1 =
36029694445217181240393229507657783589129565545215936055029374536597763899498239088343814109348783168014524786101104703066635008905663623795923908443470553241615761261684865762093341375627893251064284854550683090289244326428531870185742069661263695374185944997371146406463061296320874619629222702687248540071  
n_2 =
29134539279166202870481433991757912690660276008269248696385264141132377632327390980628416297352239920763325399042209616477793917805265376055304289306413455729727703925501462290572634062308443398552450358737592917313872419229567573520052505381346160569747085965505651160232449527272950276802013654376796886259  
enc_1 =
4813040476692112428960203236505134262932847510883271236506625270058300562795805807782456070685691385308836073520689109428865518252680199235110968732898751775587988437458034082901889466177544997152415874520654011643506344411457385571604433702808353149867689652828145581610443408094349456455069225005453663702  
enc_2 =
2343495138227787186038297737188675404905958193034177306901338927852369293111504476511643406288086128052687530514221084370875813121224208277081997620232397406702129186720714924945365815390097094777447898550641598266559194167236350546060073098778187884380074317656022294673766005856076112637129916520217379601

c = continued_fraction(Integer(n_2) / Integer(n_1))

for i in tqdm(range(1, 150)):  
   k = c.numerator(i)  
   x = c.denominator(i)  
   if GCD(e, k) != 1:  
       continue  
   res = inverse(e - k, e)  
   cc = crt(res, 0, e, x)  
   md = e * x // GCD(e, x)

   st = cc + (n_1 // md) * md - 100 * md  
   for j in range(200):  
       if GCD(e, st) != 1:  
           st += md  
           continue   
       d_1 = inverse(e, st)  
       flag = long_to_bytes(pow(enc_1, d_1, n_1))  
       if b"CCTF" in flag:  
           print(flag)  
       st += md  
```

##### Flag

`CCTF{__Lattice-Based_atT4cK_on_RSA_V4R1aN75!!!}`

Original writeup (https://blog.cryptohack.org/cryptoctf2021-hard#dorsa).