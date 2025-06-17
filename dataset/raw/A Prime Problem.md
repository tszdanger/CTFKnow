# A Prime Problem  
- Solves - 15  
- Points - 400  
#  
# Description  
Suppose I generate primes p and q for RSA in the following way:

Choose a random 2048 bit integer  
p is next prime after that integer  
Choose another random integer r where 0 < r ≤ 2^1023  
q is next prime after r + p  
n = p*q Can you factor n and recover the flag?

Hint: CVE-2022-26320  
# Attachments  
[Файл public.pem](./sources/public.pem)  
[Файл key_gen_flag.bin](./sources/key_gen_flag.bin)  
# Solution  
It's a great task.

For First we decode the public key to get `n` and `e`.

```python  
key = open('public.pem', "r").read()  
rsakey = RSA.importKey(key)  
print(rsakey.n, rsakey.e)  
```  
Then, after getting the information from the hint, we understand that we need
to use the Fermat factorization method. Let's write the code and find `p` and
`q`:

```python  
def isqrt(n):  
   x = n  
   y = (x + n // x) // 2  
   while (y < x):  
       x = y  
       y = (x + n // x) // 2  
   return x

def fermat(n):  
   t0 = isqrt(n) + 1  
   counter = 0  
   t = t0 + counter  
   temp = isqrt((t * t) - n)  
   while ((temp * temp) != ((t * t) - n)):  
       counter += 1  
       t = t0 + counter  
       temp = isqrt((t * t) - n)  
   s = temp  
   p = t + s  
   q = t - s  
   return p, q  
```

Then we calculate the closed exponent `d`.

```python  
phi = (p-1)*(q-1)  
d = pow(e, -1, phi)  
```

Now we have everything we need, so we just create a private key and decode the
file with the flag:

```python  
comps = tuple([rsakey.n, rsakey.e, d, p, q])  
private_key = RSA.construct(comps, consistency_check=False)  
c = PKCS1_OAEP.new(Rprivate_key)  
with open('key_gen_flag.bin', 'rb') as f:  
 print(c.decrypt(f.read()))  
```  
Note: The code might not work correctly if you have a different version of the
crypto module  

Original writeup (https://github.com/EgorVinid/CTF-
writeups/blob/main/TexSAW/Crypto/A_Prime_Problem.md).