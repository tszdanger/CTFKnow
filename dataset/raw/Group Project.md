# UIUCTF 2023

## Group Project

> In any good project, you split the work into smaller tasks...  
>  
>  Author: Anakin  
>  
> [`chal.py`](https://github.com/D13David/ctf-
> writeups/blob/main/uiuctf23/crypto/group_project/chal.py)

Tags: _crypto_

## Solution  
For this challenge we have the encryption script that is running on the
server.

```python  
def main():  
   print("[$] Did no one ever tell you to mind your own business??")

   g, p = 2, getPrime(1024)  
   a = randint(2, p - 1)  
   A = pow(g, a, p)  
   print("[$] Public:")  
   print(f"[$]     {g = }")  
   print(f"[$]     {p = }")  
   print(f"[$]     {A = }")

   try:  
       k = int(input("[$] Choose k = "))  
   except:  
       print("[$] I said a number...")

   if k == 1 or k == p - 1 or k == (p - 1) // 2:  
       print("[$] I'm not that dumb...")

   Ak = pow(A, k, p)  
   b = randint(2, p - 1)  
   B = pow(g, b, p)  
   Bk = pow(B, k, p)  
   S = pow(Bk, a, p)

   key = hashlib.md5(long_to_bytes(S)).digest()  
   cipher = AES.new(key, AES.MODE_ECB)  
   c = int.from_bytes(cipher.encrypt(pad(flag, 16)), "big")

   print("[$] Ciphertext using shared 'secret' ;)")  
   print(f"[$]     {c = }")  
```

The flag is encrypted with AES-ECB, so to encrypt the flag we need to retrieve
the `key`. The key is the md5-hash of `S` and `S` is calculated like this:

```python  
Ak = pow(A, k, p)  
b = randint(2, p - 1)  
B = pow(g, b, p)  
Bk = pow(B, k, p)  
S = pow(Bk, a, p)  
```

The value of `k` can be specified. The critical observation here is that, if
`k` is set to 0 then `Bk = B^0 % p = 1` and `S = Bk^n % p = 1^n % p = 1`. So
we can calculate the md5-hash of the value 1 and have the key for decryption.

```python  
from Crypto.Cipher import AES  
import hashlib  
from Crypto.Util.Padding import pad  
from Crypto.Util.number import long_to_bytes

S = 1  
c =
31383420538805400549021388790532797474095834602121474716358265812491198185235485912863164473747446452579209175051706

key = hashlib.md5(long_to_bytes(S)).digest()  
cipher = AES.new(key, AES.MODE_ECB)  
c = cipher.decrypt(c.to_bytes(c.bit_length(), "big"))  
print(c)  
```

Flag `uiuctf{brut3f0rc3_a1n't_s0_b4d_aft3r_all!!11!!}`

Original writeup (https://github.com/D13David/ctf-
writeups/blob/main/uiuctf23/crypto/group_project/README.md).