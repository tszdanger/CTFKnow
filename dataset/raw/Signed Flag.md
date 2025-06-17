# Signed Flag

Here is the challenge code and Description

```  
I will give you the signed flag only if you first show me that you can break
its signature!

nc 185.235.41.166 5000  
```

```python  
from string import ascii_uppercase, ascii_lowercase, digits  
from random import randrange, choice  
from Crypto.PublicKey import DSA  
from hashlib import sha1  
from gmpy2 import xmpz, to_binary, invert, powmod, is_prime

def gen_rand_str(size=40, chars=ascii_uppercase + ascii_lowercase + digits):  
   return ''.join(choice(chars) for _ in range(size))

def gen_g(p, q):  
   while True:  
       h = randrange(2, p - 1)  
       exp = xmpz((p - 1) // q)  
       g = powmod(h, exp, p)  
       if g > 1:  
           break  
   return g

def keys(g, p, q):  
   d = randrange(2, q)  
   e = powmod(g, d, p)  
   return e, d

def sign(msg, k, p, q, g, d):  
   while True:  
       r = powmod(g, k, p) % q  
       h = int(sha1(msg).hexdigest(), 16)  
       try:  
           s = (invert(k, q) * (h + d * r)) % q  
           return r, s  
       except ZeroDivisionError:  
           pass

if name == "main":  
   print("\n")  
   print(".___________..___  ___.               ______ .___________._______
___     ___    ___      ")  
   print("|           ||   \/   | |  |  |  |  /      ||           ||   ____|     | \   / _ \  |   \  /_ | ")  
   print('`---|  |----`|  \  /  | |  |  |  | |  ,----"`---|  |----`|  |           ) | | | | |    ) |  | | ')  
   print("    |  |     |  |\/|  | |  |  |  | |  |         |  |     |   |         / /  | | | |   / /   | | ")  
   print("    |  |     |  |  |  | |  `--'  | |  `----.    |  |     |  |         / /_  | |_| |  / /_   | | ")  
   print("    |  |     |  |  |  |  \______/   \______|    |  |     |  |        |____|  \___/  |____|  |_| ")

   steps = 10  
   for i in range(steps):  
       key = DSA.generate(2048)  
       p, q = key.p, key.q  
       print("\n\nq =", q)  
       g = gen_g(p, q)  
       e, d = keys(g, p, q)  
       k = randrange(2, q)  
       print(f"k : {k}")  
       print(f"d : {d}")  
       msg1 = gen_rand_str()  
       msg2 = gen_rand_str()  
       msg1 = str.encode(msg1, "ascii")  
       msg2 = str.encode(msg2, "ascii")  
       r1, s1 = sign(msg1, k, p, q, g, d)  
       r2, s2 = sign(msg2, k, p, q, g, d)  
       print("\nsign('" + msg1.decode() + "') =", s1)  
       print("\nsign('" + msg2.decode() + "') =", s2)  
       if i == (steps - 1):  
           with open('flag', 'rb') as f:  
               flag = f.read()  
               secret = flag  
       else:  
           secret = gen_rand_str()  
           secret = str.encode(secret, "ascii")  
           print(f"secret : {secret}")  
       r3, s3 = sign(secret, k, p, q, g, d)  
       print("\nsign(secret) =", s3, r3)  
       h = input("\nGive me SHA1(secret) : ")  
       if h == str(int(sha1(secret).hexdigest(), 16)):  
           print("\nThat's right, the secret is", secret.decode())  
       else:  
           print("\nSorry, I cannot give you the secret. Bye!")  
           break  
```

# Solution  
It's all about digital signature DSA Algorithm\  
We have 10 steps and each step produce new domain parameters and keys\  
Each step produce 2 random messages and a random secret and shares the
messages and their `s` signatures ans also `s,r` signature of the secret and
asks for the secret

because single `k` is used for message signing we can use `shared k` attack to
recover `k` and then the `known k` attack to recover the private key after
that we can compute the value of secret

## grab the needed values (q, m1, m2, s1, s2, s, r)  
```python  
from Crypto.Util.number import *  
from hashlib import sha1  
import re  
import socket  
from time import sleep

host = "185.235.41.166"  
port = 5000

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
sock.connect((host, port))

while True:  
   sleep(15)

   data = sock.recv(2048).decode()  
   print(data)

   q = int(re.search(r'q = (.*)\n', data).group(1))

   messages = re.findall(r"sign\('(.*)'\)", data)  
   m1 = messages[0]  
   m2 = messages[1]

   signatures = re.findall(r"'\) = (.*)\n", data)  
   s1 = int(signatures[0])  
   s2 = int(signatures[1])

   s = int(re.findall(r"sign\(secret\) = (.*) (.*)", data)[0][0])  
   r = int(re.findall(r"sign\(secret\) = (.*) (.*)", data)[0][1])  
```

## attack

According to this [link](https://ctf-wiki.mahaloz.re/crypto/signature/dsa/)  
1. First we recover `k` from two signatures  
2. Then we recover `x` which is private key  
3. Finally we recover `m` which is that hash value of the `secret` which the server expect from us

```python  
hm1 = int(sha1(m1.encode('utf-8')).hexdigest(), 16)  
hm2 = int(sha1(m2.encode('utf-8')).hexdigest(), 16)

ds = s2 - s1  
dm = hm2 - hm1

k = (inverse(ds, q) * dm) % q

x = ((s1*k - hm1) * inverse(r, q)) % q  
m = (s*k - x*r) % q  
```

And here is the overall automated code  
```python  
from Crypto.Util.number import *  
from hashlib import sha1  
import re  
import socket  
from time import sleep

host = "185.235.41.166"  
port = 5000

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
sock.connect((host, port))

while True:  
   sleep(15)

   data = sock.recv(2048).decode()  
   print(data)

   q = int(re.search(r'q = (.*)\n', data).group(1))

   messages = re.findall(r"sign\('(.*)'\)", data)  
   m1 = messages[0]  
   m2 = messages[1]

   signatures = re.findall(r"'\) = (.*)\n", data)  
   s1 = int(signatures[0])  
   s2 = int(signatures[1])

   s = int(re.findall(r"sign\(secret\) = (.*) (.*)", data)[0][0])  
   r = int(re.findall(r"sign\(secret\) = (.*) (.*)", data)[0][1])

   hm1 = int(sha1(m1.encode('utf-8')).hexdigest(), 16)  
   hm2 = int(sha1(m2.encode('utf-8')).hexdigest(), 16)

   ds = s2 - s1  
   dm = hm2 - hm1

   k = (inverse(ds, q) * dm) % q

   x = ((s1*k - hm1) * inverse(r, q)) % q

   m = (s*k - x*r) % q  
   print(m)

   sock.sendall(str(m).encode() + b"\n")  
   sleep(5)  
   info = sock.recv(2048).decode()  
   print(info)  
```

The flag:  
```  
Flag :
TMUCTF{7h15_w45_my_m1574k3__1_f0r607_7h47_1_5h0uld_n3v3r_516n_mul71pl3_m3554635_w17h_4_dupl1c473_k3y!!!}  
```

[solution code](https://github.com/KooroshRZ/CTF-
Writeups/blob/main/TMU2021/Crypto/SignedFlag/solve.py)

> KouroshRZ for **AbyssalCruelty**

Original writeup (https://kooroshrz.github.io/CTF-
Writeups/TMU2021/Crypto/SignedFlag/).