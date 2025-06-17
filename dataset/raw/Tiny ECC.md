# Tiny ECC - cryptoCTF2021

- Category: Crypto  
- Points: 217  
- Solves: 16  
- Solved by: drw0if - Crypt3dData

## Description

Being Smart will mean completely different if you can use special numbers!

`nc 01.cr.yp.toc.tf 29010`

## Solution

The challenge comes with two files:  
- mini_ecdsa.py: a file with a lot of code useful to deal with elliptic curve cryptography  
- tiny_ecc.py: the actual challenge file

The service asks us for a prime `p` and the two coefficients of the elliptic
curve in Weierstrass form (`y^2 = x^3 + ax + b`).  
Then we can solve the actual challenge: solve the discrete logarithm problem
over two elliptic curve.

### Prime number  
The prime number we give to the prompt must satisfy some conditions:  
```python  
isPrime(p) and p.bit_length() == nbit and isPrime(2*p + 1)  
```  
so the prime must be prime (lol), it has to be a 128 bit prime and `2*p + 1`
have to be prime too.  
These two numbers are then used as modulo for the two elliptic curves.

### Parameters  
The parameters we give to the challenge have to satisfy only one condition:  
```python  
a * b != 0  
```

That means we can use virtually every value as long as it's not `explicitly`
0.

### Curve forging  
As we learnt we can forge almost che curve we want since we can choose both
the field and the parameters.

What if we forge `y^2 = x^3`?  
As it turns out if we reach a curve of that type the discrete logarithm become
an easy problem!

To forge that curve we have to pass `(a,b) == (0,0)` but we can't send 0... we
can send `(a,b)==(p,p)` because for the modulo reduction `p` is congruent to
`0` but for the second curve it doesn't apply as well.  
In the end we can send `(a,b) = (p*(2*p+1),p*(2*p+1))` so that the modulo
reduction applies equally to the first and the second curve and we reach two
curves of the type `y^2 = x^3`.

### Deal with singular curve  
We reached a `singular curve` because the discriminant of the curve is 0. To
solve the DLP we need to map the point of the curve to an additive group over
the same field of the curve.

The map associated to `y^2 = x^3` is `(x,y) -> x/y`.

Then the DLP problem can be solved with a simple modulo division (multiple for
the inverse): `Q = kP -> k = map(Q)/map(P)`

```  
CCTF{ECC_With_Special_Prime5}  
```

For additional details:  
[Singular from Nullcon writeup](https://gitlab.com/n0tsobad/ctf-
writeups/tree/master/2019-02-01-nullcon/Singular)

Original writeup
(https://github.com/r00tstici/writeups/tree/master/cryptoCTF_2021/tiny_ecc).