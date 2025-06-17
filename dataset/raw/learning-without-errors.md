### crypto/learning-without-errors

This challenge is based on a [passive attack which broke the CKKS cryptosystem
last year](https://eprint.iacr.org/2020/1533). The gist of it is that CKKS
Ring Learning With Errors cryptosystem encrypts the message as a pair `(c_0,
c_1) = (a, a * s + m + e)` where `s` is the secret, `m` is the message, `a` is
a random ring element, and `e` is a "small" secret error. If `e` and `s` are
unknown, then recovering `m` from this requires solving a hard lattice
problem. However, when decrypting, CKKS returns `m + e`, which just ... tells
you ... what the secret error is.

Basic algebra then gives `s = (c_1 - (m + e)) * c_0^{-1}`. Therefore, seeing a
pair of encrypted and decrypted values is enough for a passive adversary to
completely recover the secret key!

However, this does seemingly require `c_0` to be invertible in the ring, which
for our parameters is `Zmod(2^100)[x] / [x^1024]`. The power-of-two modulus
sometimes raises an issue.

```python  
q = 1 << 100  
N = 10  
Rbase.<x> = PolynomialRing(Zmod(q))  
R.<x> = Rbase.quotient(x^N + 1)  
```

But you can solve it in `ZMod(2)` instead of `Zmod(q)`, where it has a much
higher change of being invertible. Or you can solve it over the p-adics (this
was the intended solution, which is way more complicated that the other
approach).

The challenge had a low number of solves, probably because RLWE is not common
in CTFs.

Original writeup
(https://hackmd.io/fmdfFQ2iS6yoVpbR3KCiqQ?both#cryptolearning-without-errors).