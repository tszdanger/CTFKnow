# logloglog Writeup

### angstromCTF 2022 - crypto 110 - 98 solves

> What rolls down stairs, alone or in pairs? [Source](logloglog.sage)
> [Output](logloglog.txt)

#### Analysis

```python  
q =
127049168626532606399765615739991416718436721363030018955400489736067198869364016429387992001701094584958296787947271511542470576257229386752951962268029916809492721741399393261711747273503204896435780180020997260870445775304515469411553711610157730254858210474308834307348659449375607755507371266459204680043  
p = q * 2^1024 + 1

assert p in Primes()

nbits = p.nbits()-1

e = randbits(nbits-flagbits)  
e <<= flagbits  
e |= flag

K = GF(p)  
g = K.multiplicative_generator()  
a = g^e

print(hex(p))  
print(g)  
print(hex(a))  
print(flagbits)  
```

The problem asks use to find `e`'s lsbs, which is flag. I know `flagbits =
880`, so we need 880 lsbs of `e`. To find out `e`, I must solve the
DLP[(discrete logarithm
problem)](https://en.wikipedia.org/wiki/Discrete_logarithm) over modulo `p`
which is prime.

#### Pohlig Hellman Algorithm

Given DLP is defined over field modulo prime `p` with generator `g`, having
order `n = p - 1` since `p` is prime. We know the factorization of `n = p - 1
= q * 2 ** 1024`. We cannot apply [Pohlig Hellman
Algorithm](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm) for
every factor of `n` because `n` is not smooth, having factor as prime `q`
which size is 1024 bits.

Luckily we do not need to recover entire `e`, but only 880 lsbs of it. That
means only knowing the result of `e mod (2 ** 1024)` is enough to recover the
flag.

Only apply Pohlig Hellman algorithm for factor `2 ** 1024`(Pohlig Hellman for
prime-power order), which have complexity `O(1024 * sqrt(2))` so feasible. Now
we know `x = e (mod 2 ** 1024)`, and `x`'s 880 lsbs are flag. I get flag:

```  
actf{it's log, it's log, it's big, it's heavy, it's wood, it's log, it's log,
it's better than bad, it's good}  
```

Problem output: [logloglog.txt](logloglog.txt)  
exploit driver code: [solve.sage](solve.sage)  

Original writeup (https://github.com/pcw109550/write-
up/tree/master/2022/angstromCTF/logloglog).