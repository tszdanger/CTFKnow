A simple implementation of the Winternitz signature scheme.  

`nc mc.ax 31001`  

[server.py](https://github.com/Nightxade/ctf-
writeups/blob/master/assets/CTFs/Dice-CTF-Quals-2024/server.py)  

---

We're provided a single file, `server.py`:  

```py  
#!/usr/local/bin/python

import os  
from hashlib import sha256

class Wots:  
	def __init__(self, sk, vk):  
self.sk = sk  
		self.vk = vk

	@classmethod  
	def keygen(cls):  
		sk = [os.urandom(32) for _ in range(32)]  
		vk = [cls.hash(x, 256) for x in sk]  
		return cls(sk, vk)

	@classmethod  
	def hash(cls, x, n):  
		for _ in range(n):  
			x = sha256(x).digest()  
		return x

	def sign(self, msg):  
		m = self.hash(msg, 1)  
		sig = b''.join([self.hash(x, 256 - n) for x, n in zip(self.sk, m)])  
		return sig

	def verify(self, msg, sig):  
		chunks = [sig[i:i+32] for i in range(0, len(sig), 32)]  
		m = self.hash(msg, 1)  
		vk = [self.hash(x, n) for x, n in zip(chunks, m)]  
		return self.vk == vk

if __name__ == '__main__':  
	with open('flag.txt') as f:  
		flag = f.read().strip()

	wots = Wots.keygen()

	msg1 = bytes.fromhex(input('give me a message (hex): '))  
	sig1 = wots.sign(msg1)  
	assert wots.verify(msg1, sig1)  
	print('here is the signature (hex):', sig1.hex())

	msg2 = bytes.fromhex(input('give me a new message (hex): '))  
	if msg1 == msg2:  
		print('cheater!')  
		exit()

	sig2 = bytes.fromhex(input('give me the signature (hex): '))  
	if wots.verify(msg2, sig2):  
		print(flag)  
	else:  
		print('nope')

```

Given that this problem is about the Winternitz signature scheme, I decided to
look it up. The diagram on [this
site](https://sphere10.com/articles/cryptography/pqc/wots) explained pretty
much everything about the algorithm succinctly.  

Notably, the Winternitz signature scheme is a one-time signature scheme.
Meaning, using it again could pose problems. However, looking at the provided
source code, it seemed that the service always generated a completely random
key upon connection, and we are only given 1 encryption before we are tasked
to find our own.  

In fact, the implementation in the source file seemed to be a standard
Winternitz signature scheme. I was left a bit confused for a while as I tried
to look for potential vulnerabilities in the source file or search for them
online. Unfortunately, the source code provided nothing apparently obvious to
exploit, and all the research papers online seemed to say that Winternitz was
very secure.  

After a while of searching, I ended up stumbling upon [this
paper](https://eprint.iacr.org/2023/1572.pdf). On page 5, it explains the
following:  

If the WOTS scheme were used just with the $$l_1$$ hash chains representing  
the message digest $$m$$, an adversary could trivially sign any message, where  
the digest $$r$$ consists only of chunks $$r_i$$, where $$r_i ≥ m_i$$, $$∀i ∈
[0, l_1 − 1]$$. This is  
because the adversary gains information about intermediate hash chain nodes  
from the original signature. Information that was prior to the signing
operation,  
private. The adversary can simply advance all signature nodes by $$r_i − mi$$
to  
forge a signature.  

Basically, this exploit relies on the process of the WOTS scheme, a.k.a. the
Winternitz One-Time Signature. Learn how it works before moving on in this
writeup! Then the writeup will make a lot more sense.  

Let $$n$$ represent each byte of the sha256 hash of a message. WOTS hashes
each of the 32 private keys $$256-n$$ times to obtain the signature, and
verifies the signature by hashing each of its 32-byte blocks $$n$$ times.
Therfore, given message $$m_1$$ and $$m_2$$, we can essentially forge the
signature if $$256-n_1 < 256-n_2$$ for every single 32-byte block. Note that
here, $$n_1$$ represents the byte 1,2,3...32 of $$m_1$$'s sha256 hash, and
similarly $$n_2$$ does the same with $$m_2$$. The comparison occurs between
the corresponding bytes, i.e. byte 1 of $$m_1$$ and byte 1 of $$m_2$$, etc.

This is because, if the aforementioned condition is true, we can simply hash
each 32-byte block of the signature that the signature oracle/service provides
to us the necessary number of times until it is essentially as if we took each
private key block and hashed it $$256-n_2$$, for each $$n_2$$ of the sha256
hash of $$m_2$$.  

Here's an example. Let's say the first byte of the sha256 hash of $$m_1$$ is
137, and the first byte of $$m_2$$'s is 80. The first 32-byte block of the
signature of $$m_1$$ is obtained by repeatedly hashing the first 32-byte
private key  $$256-137=119$$ times. Meanwhile, in order to obtain the first
32-byte block of $$m_2$$'s signature, we'd have to repeatedly hash the first
32-byte private key $$256-80=176$$ times.  

Notice how we can essentially just hash the first 32-byte block of $$m_1$$'s
signature $$176-119=57$$ more times to obtain the first 32-byte block of
$$m_2$$'s signature? That's the key idea. And if $$256-n_1 < 256-n_2$$ for
each byte of the sha256 hashes of $$m_1$$ and $$m_2$$, that means we can do
this for every single 32-byte block of the signature!  

So all we need to do now is find a pair of messages such that their sha256
hashes satisfy this condition, where $$m_1$$ is greater than $$m_2$$ for every
corresponding byte. We can actually very simply brute force this. Essentially,
I tried to greedily select a message where the minimum byte of the sha256 hash
was the maximum possible, and another message where the maximum byte of the
sha256 hash was the minimum possible. At each step, if either message changed,
I would check if it satisfied the aforementioned condition for all 32-byte
blocks, i.e. the sha256 hash with the greater bytes was greater than the
sha256 hash with smaller bytes for every single corresponding byte pair. It's
not a perfect greedy algorithm -- I'd love to know if there is actually a
better algorithm to do this -- but it worked out in the end! Here was my
implementation of it:  

```py  
from hashlib import sha256

largest_min_value_of_maxlist = 0  
smallest_max_value_of_minlist = 256  
minlist = []  
maxlist = []  
min_msg = ''  
max_msg = ''  
for i in range(10000000):  
   h = sha256(str(i).encode()).digest()  
   mx = max(list(h))  
   mn = min(list(h))  
   smallest_max_value_of_minlist = min(smallest_max_value_of_minlist, mx)  
   if smallest_max_value_of_minlist == mx:  
       # print("Min:", minsum, list(h), end='\n\n')  
       minlist = list(h)  
       min_msg = str(i).encode()  
  
       if maxlist == []: continue  
       s = ''  
       for i in range(32):  
           s += ('1' if minlist[i] < maxlist[i] else '0')  
       print(s)  
       if s == '1'*32: break

   largest_min_value_of_maxlist = max(largest_min_value_of_maxlist, mn)  
   if largest_min_value_of_maxlist == mn:  
       # print("Max:", maxsum, list(h), end='\n\n')  
       maxlist = list(h)  
       max_msg = str(i).encode()

       s = ''  
       for i in range(32):  
           s += '1' if minlist[i] < maxlist[i] else '0'  
       print(s)  
       if s == '1'*32: break

for i in range(32):  
   print(1 if minlist[i] < maxlist[i] else 0, end='')

print()  
print(min_msg, minlist)  
print(max_msg, maxlist)  
print(smallest_max_value_of_minlist, largest_min_value_of_maxlist)  
```

This ended up returning the following messages and corresponding hash bytes:  

```py  
msg1 = b'1973198'  
msg2 = b'752802'  
msg1_hash = [144, 246, 206, 112, 109, 246, 159, 156, 133, 235, 192, 200, 226,
105, 136, 87, 207, 242, 207, 117, 130, 177, 187, 166, 152, 86, 219, 116, 247,
147, 129, 94]  
msg2_hash = [72, 126, 124, 84, 46, 60, 148, 99, 45, 75, 40, 120, 38, 95, 7,
82, 57, 29, 32, 90, 91, 73, 27, 117, 92, 32, 134, 90, 77, 77, 92, 80]  
```

Notice how every byte in the msg1_hash is greater than its corresponding byte
in the msg2_hash? That's exactly what we need. Now, we can very easily create
a short script to interact with the remote service to execute the exploit!  

```py  
from hashlib import sha256  
from pwn import *  
import binascii

msg1 = binascii.hexlify(b'1973198')  
msg2 = binascii.hexlify(b'752802')  
msg1_hash = [144, 246, 206, 112, 109, 246, 159, 156, 133, 235, 192, 200, 226,
105, 136, 87, 207, 242, 207, 117, 130, 177, 187, 166, 152, 86, 219, 116, 247,
147, 129, 94]  
msg2_hash = [72, 126, 124, 84, 46, 60, 148, 99, 45, 75, 40, 120, 38, 95, 7,
82, 57, 29, 32, 90, 91, 73, 27, 117, 92, 32, 134, 90, 77, 77, 92, 80]

diffs = [msg1_hash[i] - msg2_hash[i] for i in range(32)]  
print(diffs)

def hash(x, n):  
   for _ in range(n):  
       x = sha256(x).digest()  
   return x

p = remote('mc.ax', 31001)  
p.sendlineafter(b': ', msg1)  
p.recvuntil(b': ')  
sig1 = p.recvline().decode('ascii')[:-1]  
sig1 = binascii.unhexlify(sig1)

chunks = [sig1[i:i+32] for i in range(0, len(sig1), 32)]

vk = [hash(x, n) for x, n in zip(chunks, diffs)]  
for i in range(len(vk)):  
   vk[i] = binascii.hexlify(vk[i]).decode('ascii')  
sig2 = "".join(vk)

p.sendlineafter(b': ', msg2)  
p.sendlineafter(b': ', sig2.encode())  
print(p.recvline().decode("ascii"))  
```

And with that, we run the script and get the flag!  

   dice{according_to_geeksforgeeks}

Thoughts: Quite a nice crypto challenge with a cleverly hidden vulnerability
in the problem. Perhaps I even could've figure it out myself after some time.
I still think it was a great solve on my part regardless!  

Original writeup (https://nightxade.github.io/ctf-writeups/writeups/2024/Dice-
CTF-Quals-2024/crypto/winter.html).