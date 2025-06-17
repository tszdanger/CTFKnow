# Crypto: Chunk Norris

## Task Description

Chunk Norris is black belt in fast random number generation.

## First Look

We are given the following Python file, as well as its output

```  
#!/usr/bin/python3 -u

import random  
from Crypto.Util.number import *  
import gmpy2

a = 0xe64a5f84e2762be5  
chunk_size = 64

def gen_prime(bits):  
 s = random.getrandbits(chunk_size)

 while True:  
   s |= 0xc000000000000001  
   p = 0  
   for _ in range(bits // chunk_size):  
     p = (p << chunk_size) + s  
     s = a * s % 2**chunk_size  
   if gmpy2.is_prime(p):  
     return p

n = gen_prime(1024) * gen_prime(1024)  
e = 65537  
flag = open("flag.txt", "rb").read()  
print('n =', hex(n))  
print('e =', hex(e))  
print('c =', hex(pow(bytes_to_long(flag), e, n)))  
```

It is clear from the last 3 lines that this is an RSA encryption scheme we
need to break, and in order to do that, we need the prime factors `p` and `q`
such that `n = pq`. This is only possible because of the weak prime generation
code used in the `gen_prime` function

## Program Analysis

We see that the `gen_prime` function initializes the variable `s` at a random
value, and then modifies it in the creation of a number, as well as performing
a bitwise `OR` operation. We treat this as effectively randomizing `s` before
each attempt to create a prime. From here on, when we refer to `s`, we mean
the actual value of `s` that was set at the start of the iteration of the loop
when the prime number was generated that is returned.

We also observe that the form of the prime generated is as follows, where each
term is calculated modulo `2^64`:

```  
p = s << 960 + (s * a) << 896 + (s * a^2) << 832 + ... + (s * a^14) << 64 + (s
* a^15)  
```  
The first observation that we make from this, is that the value of `p` is very
close to `s * 2^960`, and in fact, given a certain `p`, we can caculate `s = p
// 2^960`. This also means that we are able to use `n = pq` to get an
approximation for `s1 * s2`, the product of the two `s` values used for the
primes, as `n // 2^1920`. In fact, looking at `s1 * s2` as a 128-bit number,
the most significant 64 bits will be at most `1` away from the real value. In
order to obtain `s1 * s2`, however, we still need the lower 64 bits.

The second observation we make is that when multiplying two primes of this
form, the least significant 64 bits of the product will be equal to `(s1 *
a^15) * (s2 * a^15)` modulo `2^64`. This allows us to calculate the least
significant 64 bits of `s1 * s2` as being equal to `(n // 2^64) *
inverse(a^30, 2^64)`.

## Solution

Combining the above two parts, we get 3 (Or maybe 2? I am not very good at
math) possibilities for `s1 * s2`. We can factor these on a site such as
[factordb](https://factordb.com) to obtain the prime factors, and simply
iterate over all factor pairs for `s1` and `s2`, and check if the primes
generated with these two satisfy `pq = n`. Once we found these two primes,
reversing the RSA encyption is trivial with `d = inverse(e, (p-1)*(q-1))` and
`pt = pow(ct, d, n)`. Our solution script is as follows:

```  
from Crypto.Util.number import *  
from z3 import *  
from isqrt import *  
import random  
from functools import reduce

n =
0xab802dca026b18251449baece42ba2162bf1f8f5dda60da5f8baef3e5dd49d155c1701a21c2bd5dfee142fd3a240f429878c8d4402f5c4c7f4bc630c74a4d263db3674669a18c9a7f5018c2f32cb4732acf448c95de86fcd6f312287cebff378125f12458932722ca2f1a891f319ec672da65ea03d0e74e7b601a04435598e2994423362ec605ef5968456970cb367f6b6e55f9d713d82f89aca0b633e7643ddb0ec263dc29f0946cfc28ccbf8e65c2da1b67b18a3fbc8cee3305a25841dfa31990f9aab219c85a2149e51dff2ab7e0989a50d988ca9ccdce34892eb27686fa985f96061620e6902e42bdd00d2768b14a9eb39b3feee51e80273d3d4255f6b19  
e = 0x10001  
ct =
0x6a12d56e26e460f456102c83c68b5cf355b2e57d5b176b32658d07619ce8e542d927bbea12fb8f90d7a1922fe68077af0f3794bfd26e7d560031c7c9238198685ad9ef1ac1966da39936b33c7bb00bdb13bec27b23f87028e99fdea0fbee4df721fd487d491e9d3087e986a79106f9d6f5431522270200c5d545d19df446dee6baa3051be6332ad7e4e6f44260b1594ec8a588c0450bcc8f23abb0121bcabf7551fd0ec11cd61c55ea89ae5d9bcc91f46b39d84f808562a42bb87a8854373b234e71fe6688021672c271c22aad0887304f7dd2b5f77136271a571591c48f438e6f1c08ed65d0088da562e0d8ae2dadd1234e72a40141429f5746d2d41452d916

a = 0xe64a5f84e2762be5

def get_prime(s):  
	p = 0  
	for _ in range(1024 // 64):  
		p = (p << 64) + s  
		s = a * s % 2**64  
	return p

s1s2l = ((n%(2**64))*inverse(a**30, 2**64))%2**64  
s1s2m = n//(2**(960*2))

print(((s1s2m) // 2**64 - 1) *2**64 + s1s2l)  
print(((s1s2m) // 2**64 + 0) *2**64 + s1s2l)  
print(((s1s2m) // 2**64 + 1) *2**64 + s1s2l)

# Use factordb.com to find prime factorization

def find_primes():  
   arr = [3, 5, 41, 43, 509, 787, 31601, 258737, 28110221, 93627982031]  
   #arr = [11, 61, 443, 21751, 1933727, 53523187, 340661278587863]  
   #arr = [79, 30577, 12153143, 7765238529536474698954633]

   for i in range(2**len(arr)):  
       mask = [(i>>j) & 1 for j in range(len(arr))]  
       s1 = reduce(lambda x,y: x*y, [arr[j] for j in range(len(arr)) if mask[j]], 1)  
       s2 = reduce(lambda x,y: x*y, [arr[j] for j in range(len(arr)) if not mask[j]], 1)  
       if (p := get_prime(s1))*(q := get_prime(s2)) == n:  
           return (p, q)  
   return (0, 0)

p, q = find_primes()

d = inverse(e, (p-1)*(q-1))  
pt = pow(ct, d, n)  
print(long_to_bytes(pt))  
```

And neatly outputs the flag on the first try,
`CTF{__donald_knuths_lcg_would_be_better_well_i_dont_think_s0__}`  

Original writeup
(https://gist.github.com/RobotSquid/c02441ebc7621b42fac77f893143a563).