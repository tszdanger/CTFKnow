# Heavy Computation

> A friend of mine handed me this script and challenged me to recover the
> flag. However, I started running it on my school cluster and everything is
> burning now... Help me please!

## Description

We are given a Python script

```python  
from Crypto.Util.number import bytes_to_long, long_to_bytes  
from Crypto.Cipher import AES  
from Crypto.Util.Padding import pad  
from secret import password, flag  
from hashlib import sha256

NB_ITERATIONS = 10871177237854734092489348927  
e = 65538  
N =
16725961734830292192130856503318846470372809633859943564170796604233648911148664645199314305393113642834320744397102098813353759076302959550707448148205851497665038807780166936471173111197092391395808381534728287101705

def derive_key(password):  
	start = bytes_to_long(password)

	#Making sure I am safe from offline bruteforce attack  
  
	for i in range(NB_ITERATIONS):  
		start = start ** e  
		start %= N  
  
	#We are never too cautious let's make it harder  
  
	key = 1  
	for i in range(NB_ITERATIONS):  
		key = key ** e  
		key %= N  
		key *= start  
		key %= N  
  
	return sha256(long_to_bytes(key)).digest()

assert(len(password) == 2)  
assert(password.decode().isprintable())

key = derive_key(password)  
IV = b"random_and_safe!"  
cipher = AES.new(key, AES.MODE_CBC,IV)  
enc = cipher.encrypt(pad(flag,16))

with open("flag.enc","wb") as output_file:  
	output_file.write(enc)  
```

And the `flag.enc` file produced by this script. Well actually by an
equivalent script. As the description says, deriving the key using this
function will be impossible as it is linear in `NB_ITERATIONS`, which is
greater than `10^28`...

We also see that the key derivation comes from only a 2 bytes password, so we
may brute force it offline if we can rewrite the KDF efficiently.

## Solution

Let's use some mathematical properties. We have two loops, so let's simplify
them one by one.

## First loop

```python  
start = bytes_to_long(password)  
for i in range(NB_ITERATIONS):  
   start = start ** e  
   start %= N  
```

This simplifies easily to `start = pow(password, e ** NB_ITERATIONS, N)`.
However, `e ** NB_ITERATIONS` is still too big an exponent. From number
theory, we know we can compute this efficiently by simplifying the exponent
mod `phi(N)` (where `phi` is Euler's totient function).

```python  
start = pow(password, pow(e, NB_ITERATIONS, phi), N)  
```

We then need to compute `phi`. The creator of the challenge fucked up, and
therefore factorizing `N` is very very hard... Until around the middle of the
competition, they published a message saying to consider the big factor of N
as a prime... So we found small factors of N: 5, 23, 61 and 701. We can
compute `phi` as the product of prime factors minus 1:

```python  
NB_ITERATIONS = 10871177237854734092489348927  
e = 65538  
N =
16725961734830292192130856503318846470372809633859943564170796604233648911148664645199314305393113642834320744397102098813353759076302959550707448148205851497665038807780166936471173111197092391395808381534728287101705

phi = 4 * 22 * 60 * 700 * (N // (5*23*61*701) - 1)  
```

And the above computation gives me first step.

## Second loop

```python  
key = 1  
for i in range(NB_ITERATIONS):  
   key = key ** e  
   key %= N  
   key *= start  
   key %= N  
```

Let's again use number theory to simplify the computation. We have:

```python  
key = pow(start, e ** (NB_ITERATIONS-1), N) * pow(start, e **
(NB_ITERATIONS-2), N) * ... * pow(start, e ** 0, N) % N  
```

As `x^a x^b = x^(a+b)`, we can factorize the computation

```python  
big_exponent = sum([e ** i for i in range(NB_ITERATIONS)])  
key = pow(start, big_exponent, N)  
```

`big_exponent` is the sum of a geometric progression, so we can simplify it
once more:

```python  
big_exponent = (e ** NB_ITERATIONS - 1) / (e - 1)  
```

Once again, we may want to compute it mod `phi`, so first we invert `e-1` mod
`phi` and then we compute `big_exponent`. For the inversion, I quickly coded
my version of extended Euclid algorithm, but I'm sure some library provides
`modinv`.

```python  
import sys  
sys.setrecursionlimit(6400)

def egcd(a,b):  
   # Returns (g,u,v) such that au+bv = g = gcd(a,b)  
   if b == 0:  
       return (a, 1, 0)  
   g,u,v = egcd(b, a%b)  
   return (g,v,u-(a//b)*v)

def modinv(a,n):  
   g,u,_ = egcd(a,n)  
   return u % n

expo2 = (expo - 1) % phi  
d = modinv(e-1, phi)  
expo2 = (expo2*d) % phi

key = pow(start, expo2, N)  
```

## Final attack

Once we have a fast key derivation, we can execute the brute force attack. The
full script is here:

```python  
from Crypto.Util.number import bytes_to_long, long_to_bytes, GCD, isPrime  
from Crypto.Cipher import AES  
from hashlib import sha256

import sys  
sys.setrecursionlimit(6400)

def egcd(a,b):  
   # Returns (g,u,v) such that au+bv = g = gcd(a,b)  
   if b == 0:  
       return (a, 1, 0)  
   g,u,v = egcd(b, a%b)  
   return (g,v,u-(a//b)*v)

def modinv(a,n):  
   g,u,_ = egcd(a,n)  
   return u % n

NB_ITERATIONS = 10871177237854734092489348927  
e = 65538  
N =
16725961734830292192130856503318846470372809633859943564170796604233648911148664645199314305393113642834320744397102098813353759076302959550707448148205851497665038807780166936471173111197092391395808381534728287101705

phi = 4 * 22 * 60 * 700 * (N // (5*23*61*701) - 1)

def derive_key(password):  
	start = bytes_to_long(password)  
  
	expo = pow(e, NB_ITERATIONS, phi)  
	start = pow(start, expo, N)

	expo2 = (expo - 1) % phi  
	d = modinv(e-1, phi)  
	expo2 = (expo2*d) % phi

	key = pow(start, expo2, N)  
  
	return sha256(long_to_bytes(key)).digest()

for i in range(256*256):  
	password = long_to_bytes(i)  
	try:  
		if not password.decode().isprintable():  
			continue  
	except:  
		continue

	key = derive_key(password)  
	IV = b"random_and_safe!"  
	cipher = AES.new(key, AES.MODE_CBC,IV)

	with open("flag.enc", "rb") as in_file:  
		dec = cipher.decrypt(in_file.read())  
		try:  
			print(dec.decode())  
		except:  
			continue  
	print(password)  
	print(key)  
```

The key is `~@`.

Flag: `shkCTF{M4ths_0v3r_p4t13Nce_b4453d1f9f5386a1846e57a3ec95678f}`

Original writeup (https://github.com/apoirrier/CTFs-
writeups/blob/master/SharkyCTF2020/Crypto/HeavyComputation.md).