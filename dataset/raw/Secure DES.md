# Secure DES (crypto, 464p)

In the task we get the
[code](https://raw.githubusercontent.com/TFNS/writeups/master/2020-04-12-ByteBanditsCTF/secure_des/securedes.py)
running on the server.

## Analysis

It might seem a bit complicated at first, but in reality the idea is rather
simple:

1. There is some secret array `key`  
2. We have some prime number `m`, selected in a very particular way to allow for easy `modular sqrt` calculation `mod m`  
3. There is randomly shuffled array `L` with values `range(0, 1024, 8)`  
4. There is array L2 which contains RSA-like encrypted values `key[i*8:(i+1)*8] + long_to_bytes(L[i])`, with `e=65536` (even number!) and `n=m` (so a prime modulus!)  
5. Encryption in the application performs 128 chained encryptions via DES using `key[L[i]:L[i]+8]` as keys.

What we know is `m` and `L2` and we need to decrypt the flag.

## Solution

First thing to notice is that since they're doing RSA with prime modulus, we
can easily decrypt it, because in such case `phi(m) = m-1`, and therfore `d =
modinv(65536, m-1)`.

However, the exponent is even, and `gcd(e, m-1) == 2`, so we can't just
perform a simple RSA decryption, because we will be left with `x^2 mod m`
instead of `x`.  
We need to perform `modular sqrt` after that, to get two possible values of
`x`, similarly as in Rabin Cryptosystem.

```python  
from crypto_commons.rsa.rsa_commons import modinv, modular_sqrt

def decrypt(value, m):  
   d = modinv(65536, m-1)  
   res = modular_sqrt(pow(value, d, m), m)  
   return res, m - res  
```

Now we somehow need to split decrypted L2 values into `key` part and `L1`
part.  
We can do that by matching the suffixes.

We can easily generate all values in `L1` array by:

```python  
   suffixes = map(lambda x: long_to_bytes(x), [x for x in range(8, 1024, 8)])  
   suffixes.insert(0, '\0')  
```

We don't know the correct order after the `shuffle` on the server, but we can
try to match the suffixs of decrypted L2 values (starting from the longest)
with what we just generated, and hope it's unique:

```python  
   suffixes = map(lambda x: long_to_bytes(x), [x for x in range(8, 1024, 8)])  
   suffixes.insert(0, '\0')  
   suffixes = suffixes[::-1]  
   key_parts = []  
   L = []  
   for k in L2:  
       decrypted1, decrypted2 = [long_to_bytes(x) for x in decrypt(k, d, m)]  
       for suffix in suffixes:  
           decrypted = decrypted1 if len(decrypted1) < 12 else decrypted2 # the real payload should be a bit logner than 8 bytes  
           if decrypted.endswith(suffix):  
               key_part = decrypted[:-len(suffix)]  
               key_part = '\00' * (8 - len(key_part)) + key_part  
               key_parts.append(key_part)  
               L.append(bytes_to_long(suffix))  
               break  
   assert len(key_parts) == 128  
   assert len(set(L)) == 128  
   assert all(map(lambda x: len(x) == 8, key_parts))  
```

This works just fine, we do get all `key` entries 8 bytes long and we managed
to recover all 128 parts of `L1` and `key`

Now we just need to decrypt the data:

```python  
def decrypt_des(ct, keys_parts, L):  
   plaintext = ct  
   for i in range(127, -1, -1):  
       cipher = DES.new(keys_parts[L[i] / 8], DES.MODE_ECB)  
       plaintext = cipher.decrypt(plaintext)  
   return plaintext  
```

We apply this to the encrypted flag we know:

```python  
   flag =
'gevktwWdgwre7OR4ICIOX8+j+UkprTDjk6vFE0cpn5ik/i7RaiYrjw=='.decode("base64")  
   print(decrypt_des(flag, key_parts, L))  
```

And we get `flag{y0u_f0und_th3_rar35t_ch33s3}`

[complete solver
here](https://raw.githubusercontent.com/TFNS/writeups/master/2020-04-12-ByteBanditsCTF/secure_des/solver.py)

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-04-12-ByteBanditsCTF/secure_des/README.md).