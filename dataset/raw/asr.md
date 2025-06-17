As this challenge name implies, the problem comes from reversing the typical  
challenge of RSA. This time, rather than starting with a modulus and trying to  
discover the private exponent, we are given the private exponent, and trying
to  
find the modulus.

As a reminder, once we find $N$, we can simply evaluate $c^d \mod N$ to  
determine the final message.

First, we know that the relationship between $e$ and $d$ is that $ed \equiv 1  
\mod \phi(N)$. Translating this to plain algebra, this means $ed - 1 =
k\phi(N)$  
for some positive integer $k$. This tells us that $ed - 1$ must divide  
$\phi(N)$.

We use an [external factoring service] to factor $ed - 1$. Using the  
`gen_prime` method given to us, we are able to validate that our factorization  
ended up being what was expected: exactly 16 64-bit primes, and a handful of  
smaller primes. The only thing left is organizing the 16 primes into two
groups  
of 8.

[external factoring service]: https://www.alpertron.com.ar/ECM.HTM

Trusty old combinatorics tells us ${16 \choose 8} = 12870$, which is easily  
iterable within a matter of seconds. After picking 8 primes, we simply run  
through the same process as `gen_prime` in order to generate our $p$ and $q$:

```python  
for perm in tqdm(perms):  
 perm = set(list(perm))  
 p = prod(perm)  
 q = prod(bigprimes - perm)

 for i in range(7):  
   if isPrime(p + 1): break  
   p *= small_primes[i]  
 for i in range(7):  
   if isPrime(q + 1): break  
   q *= small_primes[i]

 p = p + 1  
 q = q + 1  
```

All that's left is to run $c^d \mod N$ and find strings that begin with  
`uiuctf{` to determine which of these organizations of prime factors is the  
correct one.

[solve
script](https://git.sr.ht/~mzhang/uiuctf-2022/tree/master/item/crypto/asr/solve2.py)

Original writeup
(https://mzhang.io/posts/2022-08-01-uiuctf-2022-writeups/#crypto-asr---
85-points).