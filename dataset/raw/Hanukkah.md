# __X-MAS CTF 2018__  
## _Hanukkah_

## Information  
**Category:** | **Points:** | **Writeup Author**  
--- | --- | ---  
Crypto | 50 | MiKHalyCH

**Description:**

> Most of the old religions celebrate Christmas in one way or another!  
>  
> [hannukah.zip](src/hannukah.zip)  
>  
> Author: Gabies

## Solution  
[Encryption file](src/Hanukkah.py) contains two interesting functions.

```py  
def encrypt(m,pubkey):  
	c=m**2 % pubkey  
	return c  
```  
From `encrypt` we can understand that it uses
[Rabin](https://en.wikipedia.org/wiki/Rabin_cryptosystem) cryptosystem.

```py  
def genKey(k):  
	while True:  
		r=getrandbits(k)  
		while(r%2):  
			r=getrandbits(k)  
		p =  3 * r**2 +  2 * r + 7331  
		q = 17 * r**2 + 18 * r + 1339  
		n = p * q  
		if(isPrime(p) and isPrime(q)):  
			return (p,q) , n  
```  
`genkey` function shows that `p` and `q` are polynomials from same `r`.

So firstly we need to recover `r`.

We know that `N` is polynomial too:  
```py  
N = p*q =  
= (3*r**2 + 2*r + 7331)*(17*r**2 + 18*r + 1339) =  
= 51*r**4 + 88*r**3 + 128680*r**2 + 134636*r + 9816209  
```

`r` is 256 bits long, but `N` coefficients are small. It means that `r =
iroot(N - 9816209, 4)`. Now we can easy recover `p` and `q`.

Second step is decrypting Rabin. Just because `p = q = 3 (mode 4)` we can
easily compute `x_p` and `x_q`:  
```py  
x_p = sqrt(ct) % p = pow(ct, (p + 1) // 4, p)  
x_q = sqrt(ct) % q = pow(ct, (q + 1) // 4, q)  
```

Now we have 4 candidates for `m`. We can choose the right one because we know
that flag was padded with some `X` characters at end.

Full decryption algo contains in [solver.py](solver.py).

Original writeup (https://github.com/VoidHack/write-
ups/tree/master/X-MAS%20CTF%202018/crypto/Hanukkah).