# Bit Flip 1

**Category**: Cryptography \  
**Points**: 155 points \  
**Difficulty**: Easy (84 solves)

## Challenge

Flip bits and decrypt communication between Bob and Alice.

`nc bitflip1.hackable.software 1337`

Given [task.tgz](task.tgz)

## Solution

**Summary**: A simplified version of a timing-based side-channel attack on a  
prime number generator.

To understand the crypto used in this problem, I first read  
[this tutorial](https://martin.kleppmann.com/papers/curve25519.pdf)  
up to section 2.4.

This program uses Diffie-Hellman on the multiplicative group where:  
- `g = 5`  
- `k` (`alice.my_secret`) is random but determined by our input seed  
- `j` (`bob.my_secret`) is random  
- `g^j` (`bob.my_number`) is given to us by the server (removed in Bit Flip 2)

Therefore our goals are:  
- Find `g^{jk}` (`alice.shared`), the shared symmetric key used to encrypt the flag  
- We know `g^j` so we can compute `(g^j)^k` if we know `k`  
- `k` is determined by `alice_seed` (random) XOR'd with our input  
- If we find `alice_seed`, then we can find `k`

On each iteration of the program, we are told how many iterations were
required  
to generate `p`. This is almost like  
[this approach](https://crypto.stackexchange.com/a/1971)  
but not quite—the seed for the `Rng` is incremented, not `p` itself.

Here is an overview of how `p` is determined:  
```  
alice_seed = 16 bytes = 128 bits  
flip_str = 32 bytes = 256 bits  
seed = flip_str ^ alice_seed

prime (generate until found a prime)  
   = sha256(seed)     + sha256(seed + 1)  
   = sha256(seed + 2) + sha256(seed + 3)  
   = sha256(seed + 4) + sha256(seed + 5)  
   = sha256(seed + 6) + sha256(seed + 7)  
   = ...  
   = sha256(seed + x) + sha256(seed + x + 1)  
```

We are told the number of iterations to find `p`. We can use this information  
to determine every bit of `alice_seed` except the LSB bit. For example, let's  
say we want to find the 5th bit (where the LSB is the 0th bit). Assume that we  
know bits 0 through 4.

We want to make our seed look like this, where `x` indicates the bit we want
to  
find:  
```  
... x1110  
```

Since we know the first four bits stored in `guess`, we can accomplish this by  
sending `guess ^ 0b1110`, assuming `guess` matches `alice_seed`. We then
record  
the reported number of iterations in `x_n_iters`.

Next we want to make our seed look like this:  
```  
... x0000 ^ 10000  
```

If `x == 0`, then our seed will be `10000`, which is two larger than the seed
we just sent. \  
If `x == 1`, then our seed will be `00000`, which is much lower than the seed
we just sent.

We can send `guess | 0b10000` to make our seed look like how we want. We then  
record the reported number of iterations in `y_n_iters`.

Next we check if `x_n_iters == y_n_iters + 1` (see the pseudocode above  
explaining how `p` is generated to understand why this is so). If this is
true,  
then we know `x` is 0. Otherwise, `x` is 1.

We can do this for bits 1 through 127. The LSB is unknown, so we have two  
guesses for `alice_seed`.

Now that we have `alice_seed`, the rest is fairly straightforward. Using the  
code provided with the challenge, we just create `alice` using our guessed
seed  
to determine `k`. Then we calculate `(g^j)^k` to determine the shared
symmetric  
key and use that to decrypt the flag!

Script:  
```python  
from Crypto.Util.number import long_to_bytes, bytes_to_long  
import pwn  
import base64  
import re  
import flag_decrypt  
import subprocess

def get_bit(n, pos):  
   return (n >> pos) & 1

def set_bit(n, pos):  
   return n | (1 << pos)

# Note: This is not provided in the real challenge, but may be useful for  
# debugging  
seed_regex = re.compile(r'seed: (.*)\n', re.MULTILINE)

gen_regex = re.compile(r'Generated after (\d*) iterations', re.MULTILINE)  
bob_regex = re.compile(r'bob number (\d*)\n', re.MULTILINE)  
iv_regex = re.compile(r'bob .*\n(.*)\n', re.MULTILINE)  
enc_flag_regex = re.compile(r'bob .*\n.*\n(.*)\n', re.MULTILINE)

anno = False  
remote = True

def send(flip):  
   payload = base64.b64encode(long_to_bytes(flip))  
   sh.sendline(payload)  
   output = sh.recvuntilS('bit-flip str:')  
   n_iters = int(gen_regex.search(output).group(1))  
   if anno:  
       seed = seed_regex.search(output).group(1)  
       seed = bytes.fromhex(seed)  
       seed = bytes_to_long(seed)  
   else:  
       seed = None  
   return (n_iters, seed)

def send_get_all(flip):  
   payload = base64.b64encode(long_to_bytes(flip))  
   sh.sendline(payload)  
   output = sh.recvuntilS('bit-flip str:')

   n_iters = int(gen_regex.search(output).group(1))

   if anno:  
       seed = seed_regex.search(output).group(1)  
       seed = bytes.fromhex(seed)  
       seed = bytes_to_long(seed)  
   else:  
       seed = None

   bob_number = int(bob_regex.search(output).group(1))

   iv = iv_regex.search(output).group(1)  
   iv = base64.b64decode(iv)

   enc_flag = enc_flag_regex.search(output).group(1)  
   enc_flag = base64.b64decode(enc_flag)

   return {  
       'n_iters': n_iters,  
       'seed': seed,  
       'bob_number': bob_number,  
       'iv': iv,  
       'enc_flag': enc_flag  
   }

if remote:  
   sh = pwn.remote('bitflip1.hackable.software', 1337)  
else:  
   if anno:  
       sh = pwn.process('./task_anno.py')  
   else:  
       sh = pwn.process('./task.py')

if remote:  
   hashcash_regex = r'.* Proof of Work: (.*)\n'  
   output = sh.recvline(hashcash_regex).decode()  
   hashcash_cmd = re.search(hashcash_regex, output).group(1)

   print('Running hashcash cmd:', hashcash_cmd)  
   hashcash_token = subprocess.check_output(hashcash_cmd,
shell=True).decode().strip()  
   print('Got hashcash token:', hashcash_token)  
   sh.sendline(hashcash_token)

if anno:  
   output = sh.recvuntilS('bit-flip str:')  
   alice_seed = re.search(r'alice_seed: (.*)\n', output).group(1)  
   alice_seed = bytes.fromhex(alice_seed)  
   alice_seed = bytes_to_long(alice_seed)  
else:  
   print('Starting bit flipping')  
   output = sh.recvuntilS('bit-flip str:')

orig_n_iters = send(0)[0]  
print('Original number of iters:', orig_n_iters)

guess = 0  
for i in range(1, 128):  
   # 3 2 1 0  
   # x 1 1 0  
   des = set_bit(0, i) - 2  
   flip = guess ^ des  
   (x_n_iters, x_seed) = send(flip)

   # 3 2 1 0  
   # x 0 0 0  
   flip = guess | set_bit(0, i)  
   (y_n_iters, y_seed) = send(flip)

   if x_n_iters == y_n_iters + 1:  
       # It's zero  
       pass  
   else:  
       guess = set_bit(guess, i)

   print('.', end='', flush=True)

print()

guesses = [guess, guess + 1]  
for guess in guesses:  
   response = send_get_all(0)  
   print(flag_decrypt.get_flag(response, guess))  
```

flag_decrypt.py:  
```python  
#!/usr/bin/python3

# This is all copy-and-paste from task.py

from Crypto.Util.number import bytes_to_long, long_to_bytes  
from Crypto.Cipher import AES  
import hashlib  
import os  
import base64  
from gmpy2 import is_prime  
import pwn  
import re

class Rng:  
 def __init__(self, seed):  
   self.seed = seed  
   self.generated = b""  
   self.num = 0

 def more_bytes(self):  
   self.generated += hashlib.sha256(self.seed).digest()  
   self.seed = long_to_bytes(bytes_to_long(self.seed) + 1, 32)  
   self.num += 256

 def getbits(self, num=64):  
   while (self.num < num):  
     self.more_bytes()  
   x = bytes_to_long(self.generated)  
   self.num -= num  
   self.generated = b""  
   if self.num > 0:  
     self.generated = long_to_bytes(x >> num, self.num // 8)  
   return x & ((1 << num) - 1)

class DiffieHellman:  
 def gen_prime(self):  
   prime = self.rng.getbits(512)  
   iter = 0  
   while not is_prime(prime):  
     iter += 1  
     prime = self.rng.getbits(512)  
   print("Generated after", iter, "iterations")  
   return prime

 def __init__(self, seed, prime=None):  
   self.rng = Rng(seed)  
   if prime is None:  
     prime = self.gen_prime()

   self.prime = prime  
   self.my_secret = self.rng.getbits()  
   self.my_number = pow(5, self.my_secret, prime)  
   self.shared = 1337

 def set_other(self, x):  
   self.shared ^= pow(x, self.my_secret, self.prime)

def pad32(x):  
 return (b"\x00"*32+x)[-32:]

def xor32(a, b):  
 return bytes(x^y for x, y in zip(pad32(a), pad32(b)))

def bit_flip(x, s=''):  
 print("bit-flip str:")  
 flip_str = base64.b64decode(s.strip())  
 return xor32(flip_str, x)

# Real code starts here

def get_alice(guess):  
 alice_seed = long_to_bytes(guess)  
 alice = DiffieHellman(bit_flip(alice_seed))  
 return alice

def get_flag(response, guess):  
 alice = get_alice(guess)  
 shared = pow(response['bob_number'], alice.my_secret, alice.prime)  
 cipher = AES.new(long_to_bytes(shared, 16)[:16], AES.MODE_CBC,
IV=response['iv'])  
 flag = cipher.decrypt(response['enc_flag'])  
 return flag  
```

Output:  
```  
$ python3 solve.py  
[+] Opening connection to bitflip1.hackable.software on port 1337: Done  
Running hashcash cmd: hashcash -mb28 lmtdpenp  
Got hashcash token: 1:28:201122:lmtdpenp::1nR0qTyIQ4K19//9:00000000E5rwo  
Starting bit flipping  
Original number of iters: 456  
...............................................................................................................................  
bit-flip str:  
Generated after 456 iterations  
b'DrgnS{T1min9_4ttack_f0r_k3y_generation}\n        '  
bit-flip str:  
Generated after 674 iterations  
b'\xd7J\x1a\xe9K\xde\xbd\xacw,h\xcc4\x91\x87\xb1\xa6cb\x94Z\x99\xd2I\xa3\xdc8Ev\x9e{\xa02$\x03N.\xcbE\x85\xa3Y\xb1\xde\xf8\xbc\xf0y'  
```  

Original writeup
(https://github.com/qxxxb/ctf/tree/master/2020/dragon_ctf/bit_flip/1).