# Pow-Pow

**Points:** 299 (13 solves)

**Challenge Author:** defund

**Description:**

> It's a free flag, all you have to do is wait! Verifiably.  
>  
> `nc mc.ax 31337`

## Challenge

```python  
#!/usr/local/bin/python

from hashlib import shake_128

# from Crypto.Util.number import getPrime  
# p = getPrime(1024)  
# q = getPrime(1024)  
# n = p*q  
n =
20074101780713298951367849314432888633773623313581383958340657712957528608477224442447399304097982275265964617977606201420081032385652568115725040380313222774171370125703969133604447919703501504195888334206768326954381888791131225892711285554500110819805341162853758749175453772245517325336595415720377917329666450107985559621304660076416581922028713790707525012913070125689846995284918584915707916379799155552809425539923382805068274756229445925422423454529793137902298882217687068140134176878260114155151600296131482555007946797335161587991634886136340126626884686247248183040026945030563390945544619566286476584591  
T = 2**64

def is_valid(x):  
   return type(x) == int and 0 < x < n

def encode(x):  
   return x.to_bytes(256, 'big')

def H(g, h):  
   return int.from_bytes(shake_128(encode(g) + encode(h)).digest(16), 'big')

def prove(g):  
   h = g  
   for _ in range(T):  
       h = pow(h, 2, n)  
   m = H(g, h)  
   r = 1  
   pi = 1  
   for _ in range(T):  
       b, r = divmod(2*r, m)  
       pi = pow(pi, 2, n) * pow(g, b, n) % n  
   return h, pi

def verify(g, h, pi):  
   assert is_valid(g)  
   assert is_valid(h)  
   assert is_valid(pi)  
   assert g != 1 and g != n - 1  
   m = H(g, h)  
   r = pow(2, T, m)  
   assert h == pow(pi, m, n) * pow(g, r, n) % n

if __name__ == '__main__':  
   g = int(input('g: '))  
   h = int(input('h: '))  
   pi = int(input('pi: '))  
   verify(g, h, pi)  
   with open('flag.txt') as f:  
       print(f.read().strip())  
```

## Solution

The challenge presents us with a verifiable delay function (VDF), which (if
correctly implemented) requires us to compute

$$  
h \equiv g^{2^T} \pmod n.  
$$

This requires us to perform $T = 2^{64}$ squares of $g \pmod n$, which is
totally infeasible for a weekend CTF! If we could factor $n$, we could first
compute $a \equiv 2^T \pmod{\phi(n)}$, but as the challenge is set up, it's
obvious we can't factor the 2048 bit modulus.

Another option would be to pick a generator $g$ of low order, for the RSA
group $\mathcal{G} = (\mathbb{Z}/n\mathbb{Z})^*$, two easy options are $g=1$
or $g=-1$. However, looking at `verify(g,h,pi)`, we see that these elements
are explicitly excluded from being considered

```python  
def is_valid(x):  
   return type(x) == int and 0 < x < n

def verify(g, h, pi):  
   assert is_valid(g)  
   assert is_valid(h)  
   assert is_valid(pi)  
   assert g != 1 and g != n - 1  
   m = H(g, h)  
   r = pow(2, T, m)  
   assert h == pow(pi, m, n) * pow(g, r, n) % n  
```

First `is_valid(x)` ensures that $g,h,\pi \in \mathcal{G}$ and then the
additional check `assert g != 1 and g != n - 1` ensures that $g$ has unknown
order.

So if we can't run `prove(g)` in a reasonable amount of time, and we can't
cheat the VDF by factoring, or selecting an element of known order, then there
must be something within `verify` we can cheat.

First, let's look at what appears in `verify(g,h,pi)` and what we have control
over.

We choose as input any $g,h,\pi \in \mathcal{G}$ and from $g,h$ `shake128` is
used as a pseudorandom function to generate $m$. Finally, from $m$ we find $r
\equiv 2^T \pmod m$.

To pass the test in verify, naively we need to send integers from the output
of `h, pi = prove(g)` such that the following congruence holds:

$$  
h \equiv g^r \cdot \pi^m \pmod n.  
$$

Although this congruence assumes the input $(g,h,\pi)$ have the relationship
established by `prove(g)`, what if we instead view this as a general
congruence? Let's try by assuming all variables can be expressed as a power of
a generator $b$ and attempt to forget about `prove(g)` altogether! For our
implementation, we make the choice $b = 2$, but this is arbitary.

$$  
g \equiv b^M \pmod n, \quad h \equiv b^A \pmod n, \quad \pi \equiv b^B \pmod
n.  
$$

From this point of view, we need to try and find integers $(M,A,B)$ such that

$$  
b^A \equiv b^{rM} \cdot b^{mB} \pmod n \Leftarrow A = rM + mB  
$$

The integers $(m,r)$ are generated from

```python  
def H(g, h):  
   return int.from_bytes(shake_128(encode(g) + encode(h)).digest(16), 'big')

# We can pick these  
M, A, B = ?, ?, ?  
g = pow(2,M,n)  
h = pow(2,A,n)  
pi = pow(2,B,n)

# Effectively random  
m = H(g, h)  
r = pow(2, T, m)  
```

and we can effectively treat these integers as totally random. More
importantly, the values are unknown until we make a choice for both $g,h$ (and
therefore $M,A$).

Our first simplification will be $A = 0 \Rightarrow h = 1$, which simplifies
our equation and is a valid input for $h$. Now we need to pick $(M,B)$ such
that

$$  
0 = rM + mB,  
$$

where we remember that the values of $(r,m)$ are only known after selecting
$M$, but $B$ can be set afterwards. It then makes sense to rearrange the above
equation into the form:

$$  
B = -\frac{rM}{m}  
$$

To find an integer solution $B$, we then need to find some $rM$ which is
divisible by a random integer $m$.

The VDF function which appears in the challenge is based off work by
[Wesolowski](https://eprint.iacr.org/2018/623), reviewed in a paper by [Boneh,
Bünz and Fisch](https://eprint.iacr.org/2018/712.pdf). There is a key
difference though between the paper and the challenge. In Wesolowski's work,
$m$ is prime, and finding a $M$ divisible by some large, random prime is
computationally hard. The challenge becomes solvable because $m$ is totally
random and so can be composite.

To find an integer $M \equiv 0 \pmod m$, the best chance we have is to use
some very smooth integer, such as $M = n!$, or $M = \prod_i^n p_i$ as the
product of the first $n$ primes. In the challenge author's [write-
up](https://priv.pub/posts/dicectf-2022), they pick

$$  
M = 256! \prod_i^n p_i,  
$$

where they consider all primes $p_i < 10^{20}$. Including $256!$ allows for
repeated small factors in $m$. In our solution, we find it is enough to simply
take the product of all primes below $10^6$.

To then solve the congruence, we first generate a very smooth integer $M$ and
set $g \equiv b^M \pmod n$. From this, we compute $m = H(g,1)$. If $M \equiv 0
\pmod m$ we break the loop, compute $r$ from $m$, then $B(M,r,m)$. Finally
setting $\pi \equiv b^B \pmod n$ for our solution $(g,h,\pi)$. If the
congruence doesn't hold, we square $g \equiv g^2 \pmod n$ and double $M = 2M$
for bookkeeping, and try again.

Sending our specially crafted $(g,h,\pi) = (g,1,\pi)$ to the server, we get
the flag.

## Implementation

**Note:** We use `gmpy2` to speed up all the modular maths we need to do, but
you can do this using python's `int` type and solve in a reasonable amount of
time.

```python  
from gmpy2 import mpz, is_prime  
from hashlib import shake_128

##################  
# Challenge Data #  
##################

n =
mpz(20074101780713298951367849314432888633773623313581383958340657712957528608477224442447399304097982275265964617977606201420081032385652568115725040380313222774171370125703969133604447919703501504195888334206768326954381888791131225892711285554500110819805341162853758749175453772245517325336595415720377917329666450107985559621304660076416581922028713790707525012913070125689846995284918584915707916379799155552809425539923382805068274756229445925422423454529793137902298882217687068140134176878260114155151600296131482555007946797335161587991634886136340126626884686247248183040026945030563390945544619566286476584591)  
T = mpz(2**64)

def is_valid(x):  
   return type(x) == int and 0 < x < n

def encode(x):  
   if type(x) == int:  
       return x.to_bytes(256, 'big')  
   else:  
       return int(x).to_bytes(256, 'big')

def H(g, h):  
   return int.from_bytes(shake_128(encode(g) + encode(h)).digest(16), 'big')

def verify(g, h, pi):  
   assert is_valid(g)  
   assert is_valid(h)  
   assert is_valid(pi)  
   assert g != 1 and g != n - 1  
   m = H(g, h)  
   r = pow(2, T, m)  
   # change assert to return bool for testing  
   return h == pow(pi, m, n) * pow(g, r, n) % n

##################  
#    Solution    #  
##################

def gen_smooth(upper_bound):  
   M = mpz(1)  
   for i in range(1, upper_bound):  
       if is_prime(i):  
           M *= i  
   return M

def gen_solution(M):  
   # We pick a generator b = 2  
   g = pow(2, M, n)  
   h = 1  
   while True:  
       m = mpz(H(g, h))  
       if M % m == 0:  
           r = pow(2, T, m)  
           B = -r*M // m  
           pi = pow(2, B, n)  
           return int(g), int(h), int(pi)   
       M = M << 1  
       g = pow(g,2,n)

print(f"Generating smooth value M")  
M = gen_smooth(10**6)

print(f"Searching for valid m")  
g, h, pi = gen_solution(M)

assert verify(g, h, pi)  
print(f"g  = {hex(g)}")  
print(f"h  = {hex(h)}")  
print(f"pi = {hex(pi)}")  
```

## Flag

`dice{the_m1n1gun_4nd_f1shb0nes_the_r0ck3t_launch3r}`

Original writeup (https://org.anize.rs/dicectf-2022/crypto/powpow).