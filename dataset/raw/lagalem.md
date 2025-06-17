Good crypto challenge for beginners (like us), unfortunately we solved it
after the end of the event. We're given a piece of Python code and the result
of the encryption of the flag:  
```  
from Crypto.Util.number import *  
from key import FLAG

size = 2048  
rand_state = getRandomInteger(size//2)

def keygen(size):  
 q = getPrime(size)  
 k = 2  
 while True:  
   p = q * k + 1  
   if isPrime(p):  
     break  
   k += 1  
 g = 2  
 while True:  
   if pow(g, q, p) == 1:  
     break  
   g += 1  
 A = getRandomInteger(size) % q  
 B = getRandomInteger(size) % q  
 x = getRandomInteger(size) % q  
 h = pow(g, x, p)  
 return (g, h, A, B, p, q), (x, )

def rand(A, B, M):  
 global rand_state  
 rand_state, ret = (A * rand_state + B) % M, rand_state  
 return ret

def encrypt(pubkey, m):  
 g, h, A, B, p, q = pubkey  
 assert 0 < m <= p  
 r = rand(A, B, q)  
 c1 = pow(g, r, p)  
 c2 = (m * pow(h, r, p)) % p  
 return (c1, c2)

# pubkey, privkey = keygen(size)

m = bytes_to_long(FLAG)  
c1, c2 = encrypt(pubkey, m)  
c1_, c2_ = encrypt(pubkey, m)

print pubkey  
print (c1, c2)  
print (c1_, c2_)  
```

Analyzing the code we have:  
* $q$, $p=qk+1$ random primes  
* $g$ such that $g^q \equiv 1 \pmod{p}$  
* $A,B,x \in \\{0,...,q-1\\}$ random values  
* $h=g^x \pmod{p}$  
* $r$ random  
* $r'=Ar+B$  
* $m$ that is the flag  
* $C_1=g^r \pmod{p}$, $C_2=mh^r \pmod{p}$, $C_1'=g^{r'} \pmod{p}$, $C_2'=mh^{r'}\pmod{p}$ that are the encryption results

We're given $g,h,A,B,p,q$ as a public key, so basically we have to find $x$ or
$r$. The problem with this encryption is that $r$ and $r'$ are correlated and
are used to encrypt the same message $m$, so let's try to work on $r$. Because
we are working modulo a prime $p$ we know that the modular inverse of $h^r$
exists, so $m = (h^r)^{-1}C_2$. Working on $C_2'$ we find
$$C_2'=mh^{r'}=mh^{Ar}h^B$$  
$$\Rightarrow C_2'(h^B)^{-1}=mh^{Ar}$$  
$$\Rightarrow C_2'(h^B)^{-1}C_2^{-1}=h^{(A-1)r}$$  
Now recalling Fermat's little theorem: if $p$ is a prime and $a \in
\mathbb{Z}_p$ we have $a^{p-1}\equiv 1 \pmod{p}$.  
Noticing that $gcd(A-1,p-1)=1$ we know that there exists the multiplicative
inverse of $A-1$ modulo $p-1$ $(A-1)^{-1}$, so
$(h^{(A-1)r})^{(A-1)^{-1}}=(h^r)^{(A-1)(A-1)^{-1}}=h^r \pmod{p}$

$$\Rightarrow m = ((C_2'(h^B)^{-1}C_2^{-1})^{(A-1)^{-1}})^{-1}C_2$$