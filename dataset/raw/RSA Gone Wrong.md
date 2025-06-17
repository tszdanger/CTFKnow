We are given a ciphertext `ct`, an exponent `e`, and a totient `phi` of `n`.

Problem is we can't decrypt because we need `n`. So now we're back to the
large number factoring problem.

We know that the totient, just like the modulus, is comprised of the primes
too: `phi(n) = (p-1) * (q-1)`.

---

Let's build a strategy:

1. Let S be the set of prime factors of `phi`.

2. For each possible combination C in S we do the following:

	i. Compute the product of C and add 1 — assign it to `p`.

	ii. If `p` is prime, compute `phi` ÷ (`p`-1) + 1 — assign it to `q`.

	iii. If `q` is prime, attempt to decrypt the ciphertext with the attained `p` and `q` values.

	iv. If the known flag part appears in the decryption, we're done!

---

```python  
from Crypto.Util.number import isPrime, long_to_bytes  
from itertools import combinations  
from functools import reduce

ct =
5130304507191400783541763470501911789653240155919651463963836982020864332865905486625179455227840365092388092655014361291395402708694164414365418338035119409356897221074  
phi =
1570359526390327795587604223560025824592946281228350983265345431626589603873455573705621383229629752655777215638492468516856414709455757436817470769139576283488712724422152  
e = 65537

# Combination of Factordb and YAFU  
factors = [2, 2, 2, 39479325013, 119942438633, 2052446000113,
10087727746606604573, 18499937136886921343, 64270985366629197191403244080553,
1683899661896976563424853785914753429323534430179719034228218351391]

# Work out which combination (product) of factors produce possible values for
P-1 and Q-1  
for n in range(1, len(factors)):  
   comb = combinations(factors, n)  
   for c in comb:  
       prod = reduce(int.__mul__, c)  
       if isPrime(prod+1) and isPrime(phi//prod+1):  
           p = prod+1  
           q = phi//(p-1) + 1  
           d = pow(e, -1, phi)  
           pt = pow(ct, d, p*q)  
           m = long_to_bytes(pt)  
           if b"RITSEC" in m:  
               exit(m.decode())  
```

---

Flag: `RITSEC{f4ctoring_1s_e3sy}`