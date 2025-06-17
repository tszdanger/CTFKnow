# Mysterious RSA  
> 350 points

## Description  
> We found [this mysterious
> website](https://metaproblems.com/8b2797bf7f420d5ad92e60ba064a55a1/index.php),
> and we think it's trying to say something, but we're  
> having trouble figuring it out. It appears to be broadcasting the same
> message over and over again like a sort of modern day number station. We're
> pretty sure  
> the message is encrypted with RSA. Could you take a crack at it?  
  
> **Hint : Same message is being broadcasted...**

## Solution  
The link takes us to a website which gives random `N`, `E` and `C` **[ where N
= modulus, E = public exponent, C = Ciphertext ]**.

They also hinted us that they are encrypting the `message` with different `N`
and `E`.

This leads to the famous [Håstad's broadcast
attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#H%C3%A5stad%27s_broadcast_attack)
where we need to  
collect `E` ciphertexts to perform this attack.

### Collection of Ciphers

Here's the [python script](collect.py) that I used to grab the ciphertexts
from that site.  
```py  
#!/usr/bin/env python3  
# https://metaproblems.com/8b2797bf7f420d5ad92e60ba064a55a1/index.php

import requests as r  
import re

file = open('data.txt', 'w')  
for i in range(1000):  
	res = r.get("https://metaproblems.com/8b2797bf7f420d5ad92e60ba064a55a1/index.php").text  
	stripped = re.sub('<[^<]+?>', '', res).split('\n\n')	# regex to get only N, E, C  
	print(f"Collected {i+1}")

	n = stripped[0]  
	e = stripped[1]  
	ct = stripped[2]

	# store the N, C pairs in diff files with filename E  
	with open(e[2:]+'.txt', 'a') as f:  
		f.writelines(n+'\n'+ct)

```  
### The Attack  
I found a script on Github and modified it for the Attack. Download the
[0x43.txt](https://github.com/t3rmin0x/CTF-
Writeups/blob/master/MetaCTF%20CyberGames%202020/crypto/Mysterious%20RSA/%200x43.txt)
file to test.

Script : [hastad-attack.py](hastad-attack.py)

```py  
"""  
author : MxRy - 2016 - Hastad's attack python2  
https://github.com/MxRy/rsa-attacks/blob/master/hastad-attack.py  
"""  
import math  
import functools  
import gmpy2

# Get the Flag (only for CTFs)  
def ReverseX(x, e) :  
	m = gmpy2.iroot(x, e)[0]  
	size = int(math.log(m, 10) + 1)  
	print("Flag : \n"+"".join([chr((m >> j) & 0xff) for j in reversed(range(0, size << 3, 8))]))  
	return 1	

# Step-by-step CRT implementation (cf. demo precedente)  
def CrtComputation(C_i, N_i) :  
	mu = list()  
	nu = list()  
	e = list()  
	(x_i, N) = (0, 1)  
	"""  
	Calcul mu_i = PI_(j=1,j!=i)^k(n_j)  
	"""  
	N = functools.reduce(lambda a, b: a*b, N_i)  
	for n_i in N_i :  
		mu.append(N//n_i)  
	"""  
	Calcul nu_i inverse modulo n_i des mu_i  
	useful link :  
https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm  
	"""  
	for mu_i, n_i in zip(mu, N_i) :  
		nu.append(gmpy2.invert(mu_i, n_i))  
	"""  
	Calcul e_i = nu_i * mu_i  
	"""  
	for mu_i, nu_i in zip(mu, nu) :  
		e.append(mu_i*nu_i)  
	"""  
	Calcul et retour de x  
	"""	  
	for e_i, a_i in zip(e, C_i) :	  
		x_i += e_i*a_i  
	x = x_i % N  
	return x 

def HastadAttack(C, N, e):  
	x = CrtComputation(C, N)  
	return ReverseX(x, e)

def main():  
	C = []  
	N = []  
	e = 0x43

	with open(" 0x43.txt", "r") as f:  
		lines = f.read().split('\n')  
		for i, line in enumerate(lines):  
			if i <= e*2-1:  
				if line[0] == 'N':  
					N.append(int(line[3:], 16))  
				else:  
					C.append(int(line[3:], 16))  
	HastadAttack(C, N, e)

if __name__ == "__main__":  
	main()		

```  
## Flag  
> **MetaCTF{WoW_y0U_Sur3_L!ke_youR_CRT_Att@ck5!}**  

Original writeup (https://github.com/t3rmin0x/CTF-
Writeups/tree/master/MetaCTF%20CyberGames%202020/crypto/Mysterious%20RSA#mysterious-
rsa).