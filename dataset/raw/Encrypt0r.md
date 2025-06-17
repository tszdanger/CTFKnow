# Encrypt0r

#### Description:  
```  
EU instance 161.97.176.150 4449

US instance 185.172.165.118 4449  
```  
#### Auther:  
Soul  
#### Points and solvers:  
At the end of the CTF, 36 teams solved this challenge and it was worth 492
points.

## Solution:  
In this challenge once you connected to the remote server a prompt appeared,
"this is the flag":

> 848630917051893087050233654298398605870572417880786546004017

Then you were able to encrypt whatever number you wanted and see the result.

Fisrt let's try to encrypt some stuff see if we understand what encryption is
that.  
`0` -> `0`,  
`1` -> `1`,  
`2` -> `405518048190558088634310202493589629933137815074909354184258`  
We know that raising to some power will keep 0 at 0 and keep 1 at 1, this
leads us to thinking we are dealing with
[RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) here.

For us to decrypt then we need to find, `n` than `e` and than `d`, after that
we will be able to decrypt.  
Normally in order to find `n` when you are have an encryption oracel you can
use a method explained
[here](https://crypto.stackexchange.com/questions/65965/determine-rsa-modulus-
from-encryption-oracle)  
and this was indid the intended solution. But when encrypting `-1` (this
option should have been patched) we get `n - 1` due to modular arithmetics. So
we have `n`, it is:

> 943005855809379805541572246085636463198876208104363395594608 + 1

And now in order to find `e` we can simply iterate over may powers untill we
will find a power that matches the fact that we know the encryption of `2`:

```python  
tmp = 1  
for guessed_e in range(2 ** 17):  
   if tmp == 405518048190558088634310202493589629933137815074909354184258:  
       print(guessed_e)  
       break  
   tmp *= 2  
   tmp = tmp % n  
```

We get `e = 65537`. Now lets factorize `n` using the following [Integer
factorization calculator website](https://www.alpertron.com.ar/ECM.HTM):  
```  
p = 882152190529044698706991746907  
q = 1068983182191997868299760689187  
```

Great! Now find `d` as usual using a `modinv` function, decrypt, and print the
result:

```python  
from Crypto.Util.number import long_to_bytes

def egcd(a, b):  
   if a == 0:  
       return (b, 0, 1)  
   else:  
       g, y, x = egcd(b % a, a)  
       return (g, x - (b // a) * y, y)

def modinv(a, m):  
   g, x, y = egcd(a, m)  
   if g != 1:  
       raise Exception('modular inverse does not exist')  
   else:  
       return x % m  

e = 65537  
d = modinv(e, (p-1)*(q-1))  
print(pow(pow(2, e, n), d, n))  
f = pow(enc_flag, d, n)  
print(long_to_bytes(f))  
```

## Flag:  
```  
flag{y0u_d0nt_n33d_4nyth1ng}  
```  

Original writeup (https://github.com/yonlif/0x41414141-CTF-
writeups/blob/main/Encrypt0r.md).