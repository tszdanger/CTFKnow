# gipfel

**Category**: crypto, baby \  
**Difficulty**: easy \  
**Points**: 85 points (109 solves) \  
**Author**: yyyyyyy

Hey, I heard you’re good with computers! So… Thing is, I forgot my password.
Can you help??

Download: [gipfel.tar.xz](gipfel.tar.xz)

## Overview

> This is the first challenge in a two-challenge series. The second challenge  
> is kipferl, which I didn't solve.

Here's the relevant code:

```py  
q =
0x3a05ce0b044dade60c9a52fb6a3035fc9117b307ca21ae1b6577fef7acd651c1f1c9c06a644fd82955694af6cd4e88f540010f2e8fdf037c769135dbe29bf16a154b62e614bb441f318a82ccd1e493ffa565e5ffd5a708251a50d145f3159a5

def enc(a):  
   f = {str: str.encode, int: int.__str__}.get(type(a))  
   return enc(f(a)) if f else a

def H(*args):  
   data = b'\0'.join(map(enc, args))  
   return SHA256.new(data).digest()

def F(h, x):  
   return pow(h, x, q)

password = random.randrange(10**6)

def go():  
   g = int(H(password).hex(), 16)

   privA = 40*random.randrange(2**999)  
   pubA = F(g, privA)  
   print(f'{pubA = :#x}')

   pubB = int(input(),0)  
   if not 1 < pubB < q:  
       exit('nope')

   shared = F(pubB, privA)

   verA = F(g, shared**3)  
   print(f'{verA = :#x}')

   verB = int(input(),0)  
   if verB == F(g, shared**5):  
       key = H(password, shared)  
       flag = open('flag.txt').read().strip()  
       aes = AES.new(key, AES.MODE_CTR, nonce=b'')  
       print(f'flag:', aes.encrypt(flag.encode()).hex())  
   else:  
       print(f'nope! {shared:#x}')

go()  
go()  
go()  
```

To summarize:  
- We're working in the multiplicative group of integers modulo the prime `q`  
- `password` and `g` is fixed for each connection, and is bruteforceable  
- The server generates a random `privA`, which I'll denote as `a`  
- We get `g ** a`  
- We supply `B`, and the server calculates `shared = B ** a`  
- The server calculates `verA = g ** (shared ** 3)`, which is printed to us  
- We need to supply `g ** (shared ** 5)`

## Solution

- Choose `B === q - 1 === -1  (mod q)`.  
- Then `shared === B ** a === 1  (mod q)` since `a` is even.  
- Then `verA === g ** (shared ** 3) === g  (mod q)`  
- And `g ** (shared ** 5) === g  (mod q)`

```  
$ nc 65.108.176.66 1088  
pubA =
0x1c6b7de759f81bb4899e90410a151d92e280b96669dd07771d88278c8bcf81539b0ea90c71aa95712e914ada28c7ed30b4273055eed0c775f160b874116ff77e14337530ba25cd92eefb56856569bebbc368ae864ddb8dc2375d95bb4fdd9e0  
0x3a05ce0b044dade60c9a52fb6a3035fc9117b307ca21ae1b6577fef7acd651c1f1c9c06a644fd82955694af6cd4e88f540010f2e8fdf037c769135dbe29bf16a154b62e614bb441f318a82ccd1e493ffa565e5ffd5a708251a50d145f3159a4  
verA = 0x4460f991cd7644a6e70268c0e786807de5d07a7e99d799fc1777a22faf3e265b  
0x4460f991cd7644a6e70268c0e786807de5d07a7e99d799fc1777a22faf3e265b  
flag:
8cc14560e62654903a42eb6b9d95d24ea7bb2a63a394cabfedbd61e2450b9555164fcf30c1f0f8ba  
```

Now we can bruteforce `g` to recover `flag`:

```py  
from Crypto.Hash import SHA256  
from Crypto.Cipher import AES  
from tqdm import tqdm

def enc(a):  
   # If you give this something that isn't a str or int, it returns the same  
   # thing back  
   f = {str: str.encode, int: int.__str__}.get(type(a))  
   return enc(f(a)) if f else a

def H(*args):  
   data = b"\0".join(map(enc, args))  
   return SHA256.new(data).digest()

flag = bytes.fromhex(  
"8cc14560e62654903a42eb6b9d95d24ea7bb2a63a394cabfedbd61e2450b9555164fcf30c1f0f8ba"  
)

for password in tqdm(range(10 ** 6)):  
   g = int(H(password).hex(), 16)

   key = H(password, 1)  
   aes = AES.new(key, AES.MODE_CTR, nonce=b"")  
   pt = aes.decrypt(flag)  
   if pt.startswith(b"hxp{"):  
       tqdm.write(pt + b"\n")  
       break  
```

```  
$ python3 decrypt.py  
hxp{ju5T_k1ddIn9_w3_aLl_kn0w_iT's_12345}  
22%|███████████████████████████████▎                                                                                                            | 223448/1000000 [00:10<00:36, 21306.03it/s]  
```  

Original writeup (https://github.com/cscosu/ctf-
writeups/tree/master/2021/hxp_ctf/gipfel).