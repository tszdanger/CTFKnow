# Poison Prime

> Thanks to Robin Jadoul for helping me make this challenge!

It's Diffie-Hellman, but the parameters are weird.

```  
nc 35.224.135.84 4000  
```

Attachments: `server.py`

## Overview

Alice and Bob use Diffie-Hellman key exchange to encrypt some plaintext, but
we  
get to pick the prime `p`. The goal is to decrypt the plaintext within 30  
seconds to get the flag.

```python  
class DiffieHellman:  
   def __init__(self, p: int):  
       self.p = p  
       self.g = 8  
       self.private_key = crr.getrandbits(128)

   def public_key(self) -> int:  
       return pow(self.g, self.private_key, self.p)

   def shared_key(self, other_public_key: int) -> int:  
       return pow(other_public_key, self.private_key, self.p)

def get_prime() -> int:  
   p = int(input("Please help them choose p: "))  
   q = int(  
       input(  
           "To prove your p isn't backdoored, "  
           + "give me a large prime factor of (p - 1): "  
       )  
   )

   if (  
       cun.size(q) > 128  
       and p > q  
       and (p - 1) % q == 0  
       and cun.isPrime(q)  
       and cun.isPrime(p)  
   ):  
       return p  
   else:  
       raise ValueError("Invalid prime")

def main():  
   print("Note: Your session ends in 30 seconds")

   message = "My favorite food is " + os.urandom(32).hex()  
   print("Alice wants to send Bob a secret message")

   p = get_prime()  
   alice = DiffieHellman(p)  
   bob = DiffieHellman(p)

   shared_key = bob.shared_key(alice.public_key())  
   assert shared_key == alice.shared_key(bob.public_key())

   aes_key = hashlib.sha1(cun.long_to_bytes(shared_key)).digest()[:16]  
   cipher = AES.new(aes_key, AES.MODE_ECB)  
   ciphertext = cipher.encrypt(cup.pad(message.encode(), 16))

   print("Here's their encrypted message: " + ciphertext.hex())

   guess = input("Decrypt it and I'll give you the flag: ")  
   if guess == message:  
       print("Congrats! Here's the flag: " + os.environ["FLAG"])  
   else:  
       print("That's wrong dingus")  
```

## Solution

Vulnerabilities:  
- We pick `p`  
- `g` is 8

We are also required to provide a large prime factor (128 bits) `q` for `p -
1`  
so:  
- Using Pohlig-Hellman to compute the discrete log isn't possible to do in 30  
 seconds (and actually the public key isn't even given)  
- However, a small subgroup confinement attack might work

Luckily `g = 8` is a power of 2, so the trick is to use a Mersenne prime  
`p == 2^k - 1`. Here's the reasoning as explained by Robin Jadoul:

> The order of 2 (`mod 2^k - 1`) would be k, since `2^k mod (2^k - 1)` is  
> obviously 1. So the order of `8` is at most `k` since `8 = 2^3`, which is in  
> the subgroup of 2.

We can find a list of Mersenne primes here: https://www.mersenne.org/primes/

Next we have to pick one where `p - 1` has a prime factor of at least 128
bits.  
Luckily, we can find that `2^2203 - 1` has one on  
[factordb](http://factordb.com/index.php?query=2%5E2203+-+2).

Now we have a `p` (and a `q` to show it's not backdoored) where `g` is
confined  
to a small subgroup. Solve script in `solve.py`:

```  
$ python3 solve.py  
[+] Opening connection to 35.224.135.84 on port 4000: Done  
[*] Switching to interactive mode  
Congrats! Here's the flag: CCC{sm0l_subgr0up_w1th_a_m3rs3nn3_pr1m3}  
[*] Got EOF while reading in interactive  
```  

Original writeup
(https://github.com/qxxxb/ctf_challenges/blob/master/2021/ccc/crypto/poison_prime/solve).