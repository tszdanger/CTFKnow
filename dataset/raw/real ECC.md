## Real ECC

> This recent change allows us to finally reduce the key sizeAuthor: @enedil

### Challenge

```python  
from operator import xor  
from public import p, g  
from secret import flag, a_s, b_s

def add(F, p1, p2):  
   try:  
       return {p1: p2, p2: p1}[-1]  
   except:  
       pass  
   x1, y1 = p1  
   x2, y2 = p2  
   x3 = FF(x1*x2 - x1*y2 - x2*y1 + 2*y1*y2) / FF(x1 + x2 - y1 - y2 - 1)  
   y3 = FF(y1*y2) / FF(x1 + x2 - y1 - y2 - 1)  
   return (x3, y3)

def mul(F, x, k):  
   acc = -1  
   while k:  
       if k & 1:  
           acc = add(F, x, acc)  
       # acc = add(F, acc, acc) Typo in challenge  
       acc = add(F, x, x)  
       k //= 2  
   return acc

def pad(data, length):  
   # Assume input is less than 256 bytes.  
   return data + bytes([length - len(data)] * (length - len(data)))

def encrypt(data, stream):  
   return xor(int(data), int(stream))

def encrypt_bytes(data, key):  
   data = pad(data, int(key).bit_length() // 8)  
   return encrypt(int.from_bytes(data, 'big'), key)

FF = Zmod(p)  
A = mul(FF, g, a_s)  
B = mul(FF, g, b_s)  
print(f'g = {g}', f'p = {p}', f'A = {A}', f'b = {B}', sep='\n')  
a_ms = mul(FF, B, a_s)  
b_ms = mul(FF, A, b_s)  
assert a_ms == b_ms  
shared = a_ms[0] * a_ms[1]

print(f'len = {len(flag)}, enc = {encrypt_bytes(flag, shared)}')

# g =
(375383228397780342292610905741415543021123193893202993933376546008355999579881,
125127742799260114097536968580471847673707731297734331311125515336118666526627)  
# p =
1017349223066738178194531452435878724694134639196427641168991759143390320356263  
# A =
(603956890649406768784284509883012839855804103607835093214222589654065615494206,
749634286053611578152285189158606552324508418540678613236591040516722145253708)  
# b =
(890062254689797703350145707732638943570461065304155615771307683230377614308406,
467371775612631851798003093722695784734930391102311439111204608050476921601852)  
# len = 42, enc =
54357159864722158692491564537102129439237984275607683326888133775459718903987000238912076679209103764  
```

### Solution

#### Defining the problem

This is a really interesting challenge. We're given an instance of a DH key
exchange using the group formed by a point addition law for some unknown
curve. The goal for the challenge is to break the discrete log in this group
to recover the shared secret.

Unlike traditonal ECDLP challenges, rather than being given the curve, we're
only given the operations of point addition and we're shown that this
operation is commutative:

```python  
a_ms = mul(FF, B, a_s)  
b_ms = mul(FF, A, b_s)  
assert a_ms == b_ms  
```

If we had the curve parameters, we could look at the curve order and see
whether we could attack it to solve the discrete log. I spent a bit of time
trying to deduce the form of the polynomial which gives rise to this point
addition law, but I was unable to.

Looking at the characteristic of the curve, we see that it's smooth

```python  
sage: p =
1017349223066738178194531452435878724694134639196427641168991759143390320356263  
sage: factor(p-1)  
2 * 4229971 * 4604689 * 6790219 * 9085073 * 9562139 * 9774509 * 11406217 *
20683151 * 24963011 * 26496859 * 29026219  
```

So then the question is, can we define a map from group of points on the curve
to the group $\mathbb{F}_p$? When an elliptic curve is singular, this is
indeed the case and is an interesting problem (we have a version of this on
CryptoHack). I've also seen this for rational curves of genus 0, such as the
circle.

Generally, the method is defining an isomorpishm from the group $C
(\mathbb{F}\_{p})$ for some curve $C$ to the finite group $\mathbb{F}\_{p^k}$
for some integer $n$. Normally I have seen this done from the curve
polynomial, but we can do just as well from the point addition law itself.

What we want to show, is that for the point addition

$$  
P = (x_0,y_0), \quad Q = (x^\prime, y^\prime) \qquad \qquad  Q = k \cdot P  
$$

we can find a function $f(x,y)$ such that

$$  
g = f(x_0,y_0), \quad h = f(x^\prime, y^\prime), \qquad h = g^k, \qquad
f(x,y) \in \mathbb{F}_p  
$$

we can then find the secret integer $k$ by solving the discrete log in
$\mathbb{F}_p$. This will be very quick using Pohlig-Hellman as $p$ is smooth
and easy as sage implements this for us!

#### Finding the mapping

From the challenge, lets write down exactly what the point addition law is.
Note that all operations are done mod $p$, which we will not include
explicitly. Adding the two points $P = (x_1, y_1)$ and $Q = (x_2, y_2)$ we get
a third point

$$  
P + Q = (x_3, y_3) = \left( \frac{x_1 x_2 + x_1 y_2 - x_2 y_1 + 2y_1 y_2}{x_1
+ x_2 - y_1 - y_2 - 1}, \frac{y_1 y_2}{x_1 + x_2 - y_1 - y_2 - 1} \right)  
$$

When $P = Q$, we can simplify the above and show that **point doubling** is
given by

$$  
2P = (x^\prime, y^\prime) = \left( \frac{x^2 - 2xy + 2y^2}{2(x - y) - 1},
\frac{y^2}{2(x - y) - 1} \right)  
$$

Written in this form, we want to try and find a function $f(x,y)$ such that
$f^2(x,y) = f(x^\prime,y^\prime)$. Looking at the numerator, we see the
tempting simplification

$$  
x^2 - 2xy + 2y^2 - y^2 = (x - y)^2 \quad \Rightarrow \quad x^\prime - y^\prime
= \frac{(x - y)^2}{2(x - y) - 1}  
$$

but how do we deal with the denominatior? I first decided to look at $3P$

$$  
x^\prime - y^\prime = \frac{(x - y)^3}{1 - 3(x - y) + 3(x - y)^2} \\  
$$

and $4P$

$$  
x^\prime - y^\prime = \frac{(x - y)^4}{(2(x - y) - 1) (2(x - y)^2 - 2(x - y) +
1)}  
$$

to check things were following my assumed pattern. Let us now change variables
to $t = x - y$, which gives us

$$  
\begin{align}  
t_{2P} &= \frac{t^2}{2t - 1} \\  
t_{3P} &= \frac{t^3}{3t^2 - 3t + 1} \\  
t_{4P} &= \frac{t^4}{(2t - 1) (2t^2 - 2t + 1)} = \frac{t^4}{4t^3 - 6t^2 + 4t -
1}  
\end{align}  
$$

Written like this, we can see that the denominator is of the form

$$  
t^k - (t-1)^k  
$$

and we can write

$$  
t^\prime = \frac{t^k}{t^k - (t-1)^k}  
$$

The last step is to write this in the form such that $h = g^k$, which means we
need to rearrange a little

$$  
\frac{1}{t^\prime} = \frac{t^k - (t-1)^k}{t^k} = 1 -
\left(\frac{t-1}{t}\right)^k  
$$

which allows us to write down

$$  
g = 1 - \frac{1}{t} \qquad h = 1 - \frac{1}{t^\prime} = \left(1 -
\frac{1}{t}\right)^k, \qquad h = g^k  
$$

We now have everything we need to solve, the generator, and Alice and Bob's
public keys can be represented as

$$  
g = 1 - \frac{1}{x_0 - y_0}, \quad h_{A} = 1 - \frac{1}{x_A - y_A}, \quad
h_{B} = 1 - \frac{1}{x_B - y_B}, \qquad g, h_a, h_B \in \mathbb{F}_p  
$$

All that's left is to code it up and grab the shared secret. From that we
simply extract the flag from a `xor` with the `enc` from the challenge data.

### Implementation

```python  
from Crypto.Util.number import long_to_bytes

def add(F, p1, p2):  
   try:  
       return {p1: p2, p2: p1}[-1]  
   except:  
       pass  
   x1, y1 = p1  
   x2, y2 = p2  
   x3 = FF(x1*x2 - x1*y2 - x2*y1 + 2*y1*y2) / FF(x1 + x2 - y1 - y2 - 1)  
   y3 = FF(y1*y2) / FF(x1 + x2 - y1 - y2 - 1)  
   return (x3, y3)

def mul(F, x, k):  
   acc = -1  
   while k:  
       if k & 1:  
           acc = add(F, x, acc)  
       x = add(F, x, x)  
       k //= 2  
   return acc

# Begin Challenge Data  
enc =
54357159864722158692491564537102129439237984275607683326888133775459718903987000238912076679209103764  
p =
1017349223066738178194531452435878724694134639196427641168991759143390320356263  
G =
(375383228397780342292610905741415543021123193893202993933376546008355999579881,
125127742799260114097536968580471847673707731297734331311125515336118666526627)  
A =
(603956890649406768784284509883012839855804103607835093214222589654065615494206,
749634286053611578152285189158606552324508418540678613236591040516722145253708)  
B =
(890062254689797703350145707732638943570461065304155615771307683230377614308406,
467371775612631851798003093722695784734930391102311439111204608050476921601852)  
# End Challenge Data

FF = GF(p)  
t = G[0] - G[1]  
t_a = A[0] - A[1]  
t_b = B[0] - B[1]

g = 1 - FF(1 / t)  
h_a = 1 - FF(1 / t_a)  
h_b = 1 - FF(1 / t_b)

a_s = h_a.log(g)  
b_s = h_b.log(g)

assert A == mul(FF, G, a_s)  
assert B == mul(FF, G, b_s)  
assert mul(FF, A, b_s) == mul(FF, B, a_s)

secret = mul(FF, A, b_s)  
s = secret[0] * secret[1]

print(long_to_bytes(Integer(enc)^^Integer(s)))  
```

### Flag

`chCTF{this_wasnt_elliptic_curve_after_all}`

Original writeup (https://jack4818.github.io/Chujowyc/).