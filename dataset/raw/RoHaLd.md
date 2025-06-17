## RoHaLd  
### Challenge

> There is always a [starting
> point](https://cr.yp.toc.tf/tasks/Rohald_86da9506b23e29e88d8c8f44965e9c2949a3dc41.txz),
> isn't it?

`RoHaLd_ECC.py`

```python  
#!/usr/bin/env sage

from Crypto.Util.number import *  
from secret import flag, Curve

def ison(C, P):  
   c, d, p = C  
   u, v = P  
   return (u**2 + v**2 - c**2 * (1 + d * u**2*v**2)) % p == 0

def teal(C, P, Q):  
   c, d, p = C  
   u1, v1 = P  
   u2, v2 = Q  
   assert ison(C, P) and ison(C, Q)  
   u3 = (u1 * v2 + v1 * u2) * inverse(c * (1 + d * u1 * u2 * v1 * v2), p) % p  
   v3 = (v1 * v2 - u1 * u2) * inverse(c * (1 - d * u1 * u2 * v1 * v2), p) % p  
   return (int(u3), int(v3))

def peam(C, P, m):  
   assert ison(C, P)  
   c, d, p = C  
   B = bin(m)[2:]  
   l = len(B)  
   u, v = P  
   PP = (-u, v)  
   O = teal(C, P, PP)  
   Q = O  
   if m == 0:  
       return O  
   elif m == 1:  
       return P  
   else:  
       for _ in range(l-1):  
           P = teal(C, P, P)  
       m = m - 2**(l-1)  
       Q, P = P, (u, v)  
       return teal(C, Q, peam(C, P, m))

c, d, p = Curve

flag = flag.lstrip(b'CCTF{').rstrip(b'}')  
l = len(flag)  
lflag, rflag = flag[:l // 2], flag[l // 2:]

s, t = bytes_to_long(lflag), bytes_to_long(rflag)  
assert s < p and t < p

P = (398011447251267732058427934569710020713094,
548950454294712661054528329798266699762662)  
Q = (139255151342889674616838168412769112246165,
649791718379009629228240558980851356197207)

print(f'ison(C, P) = {ison(Curve, P)}')  
print(f'ison(C, Q) = {ison(Curve, Q)}')

print(f'P = {P}')  
print(f'Q = {Q}')

print(f's * P = {peam(Curve, P, s)}')  
print(f't * Q = {peam(Curve, Q, t)}')  
```

`output.txt`

```python  
ison(C, P) = True  
ison(C, Q) = True  
P = (398011447251267732058427934569710020713094,
548950454294712661054528329798266699762662)  
Q = (139255151342889674616838168412769112246165,
649791718379009629228240558980851356197207)  
s * P = (730393937659426993430595540476247076383331,
461597565155009635099537158476419433012710)  
t * Q = (500532897653416664117493978883484252869079,
620853965501593867437705135137758828401933)  
```

The challenge is to solve the discrete log problem twice, given two pairs of
points on the curve. However, before we can do this, we need to recover the
curve parameters $(c,d,p)$. The writeup is broken into two pieces: first the
recovery of the paramters, then the mapping of the Edwards curve to
Weierstrass form to easily solve the dlog using Sage.

### Solution

#### Recovering Curve Parameters

Our goal in this section is to recover $(c,d,p)$ so we can reconstruct the
curve and solve the discrete log. We will obtain $p$ first, which will allow
us to take inversions mod $p$, needed to recover $c, d$.

We have the curve equation:

$$  
E_{c,d} : x^2 + y^2  = c^2 (1 + d x^2 y^2) \pmod p  
$$

and so we know for any point $(x_0,y_0)$  we have

$$  
x_0^2 + y_0^2  - c^2 (1 + d x_0^2 y_0^2) = k_0 p \equiv 0\pmod p  
$$

for some integer $k_0$.

Taking two points on the curve, we can isolate $cd^2$  using:

$$  
X_1 = x_1^2 + y_1^2  - c^2 (1 + d x_1^2 y_1^2) = k_1 p \\  
X_2 = x_2^2 + y_2^2  - c^2 (1 + d x_2^2 y_2^2) = k_2 p  
$$

The goal is to use two points to write something which is a multiple of $p$,
and to do this twice. We can then recover $p$ from the gcd of the pair of
points.

Taking the difference $X_1 - X_2$ elliminates the constant $c^2$ term:

$$  
X_1 - X_2 = (x_1^2 - x_2^2 + y_1^2 - y_2^2) - c^2d (x_1^2 y_1^2 - x_2^2 y_2^2)
\equiv 0 \pmod p  
$$

Collecting the multiples of $p$ we can isolate $c^2 d$ , where we use the
notation:

$$  
A_{ij} = x_i^2 - x_j^2 + y_i^2 - y_j^2, \qquad B_{ij} = x_i^2 y_i^2 - x_j^2
y_j^2  
$$

to write down:

$$  
\frac{A_{12}}{B_{12}} \equiv c^2 d \pmod p  
$$

Doing this with the other pair of points gives another expression for $c^2 d$
and the difference of these two expressions will be a multiple of $p$

$$  
\frac{A_{12}}{B_{12}}  -  \frac{A_{34}}{B_{34}}  = k \cdot p  
$$

There's one more problem: we can't divide without knowing $p$, so first let's
remove the denominator:

$$  
A_{12} B_{34} - A_{34} B_{12} = B_{12}B_{34}kp = \tilde{k} p  
$$

Finally, we can obtain $p$ from taking another combination of points and
taking the $\gcd$

$$  
\begin{aligned}  
Y_{1234} &= A_{12} B_{34} - A_{34} B_{12} = B_{12}B_{34} \\  
Y_{1324} &= A_{13} B_{24} - A_{24} B_{13} = B_{13}B_{24} \\  
p &\simeq \gcd(Y_{1234}, Y_{1324})  
\end{aligned}  
$$

Note, we may not get exactly $p$ , but some multiple of $p$, however, it's
easy to factor this and find $p$  precisely.

Returning to the above expression with the knowledge of $p$, we can compute
$c^2d$

$$  
c^2 d = \frac{x_1^2 - x_2^2 + y_1^2 - y_2^2 }{x_1^2 y_1^2 - x_2^2 y_2^2} \pmod
p  
$$

and with this known, we can so back to any point on a curve and write

$$  
c^2 = x_0^2 + y_0^2 - c^2 d x_0^2 y_0^2 \pmod p  
$$

and $c$ is then found with a square root and $d$ can be found from $c^2 d$.
With all curve parameters known, we can continue to solve the discrete log.

```python  
from math import gcd

def ison(C, P):  
   """  
   Verification points are on the curve  
   """  
   c, d, p = C  
   u, v = P  
   return (u**2 + v**2 - cc * (1 + d * u**2*v**2)) % p == 0

def a_and_b(u1,u2,v1,v2):  
   """  
   Helper function used to simplify calculations  
   """  
   a12 = u1**2 - u2**2 + v1**2 - v2**2  
   b12 = u1**2 * v1**2 - u2**2 * v2**2  
   return a12, b12

def find_modulus(u1,u2,u3,u4,v1,v2,v3,v4):  
   """  
   Compute the modulus from four points  
   """  
   a12, b12 = a_and_b(u1,u2,v1,v2)  
   a13, b13 = a_and_b(u1,u3,v1,v3)  
   a23, b23 = a_and_b(u2,u3,v2,v3)  
   a24, b24 = a_and_b(u2,u4,v2,v4)

   p_almost = gcd(a12*b13 - a13*b12, a23*b24 - a24*b23)

   for i in range(2,1000):  
       if p_almost % i == 0:  
           p_almost = p_almost // i

   return p_almost

def c_sq_d(u1,u2,v1,v2,p):  
   """  
   Helper function to computer c^2 d  
   """  
   a1,b1 = a_and_b(u1,u2,v1,v2)  
   return a1 * pow(b1,-1,p) % p

def c(u1,u2,v1,v2,p):  
   """  
   Compute c^2, d from two points and known modulus  
   """  
   ccd = c_sq_d(u1,u2,v1,v2,p)  
   cc = (u1**2 + v1**2 - ccd*u1**2*v1**2) % p  
   d = ccd * pow(cc, -1, p) % p  
   return cc, d

P = (398011447251267732058427934569710020713094,
548950454294712661054528329798266699762662)  
Q = (139255151342889674616838168412769112246165,
649791718379009629228240558980851356197207)  
sP = (730393937659426993430595540476247076383331,
461597565155009635099537158476419433012710)  
tQ = (500532897653416664117493978883484252869079,
620853965501593867437705135137758828401933)

u1, v1 = P  
u2, v2 = Q  
u3, v3 = sP  
u4, v4 = tQ

p = find_modulus(u1,u2,u3,u4,v1,v2,v3,v4)  
cc, d = c(u1,u2,v1,v2,p)

C = cc, d, p  
assert ison(C, P)  
assert ison(C, Q)  
assert ison(C, sP)  
assert ison(C, tQ)

print(f'Found curve parameters')  
print(f'p = {p}')  
print(f'c^2 = {cc}')  
print(f'd = {d}')

# Found curve  
# p = 903968861315877429495243431349919213155709  
# cc = 495368774702871559312404847312353912297284  
# d = 540431316779988345188678880301417602675534  
```

#### Converting to Weierstrass Form

With the curve known, all we have to do is solve the discrete log problem on
the Edwards curve. This could be done by using Pohlih-Hellman and BSGS using
the functions defined in the file, but instead we map the Edwards curve into
Weierstrass form and use sage in built dlog to solve. Potentially there is a
smarter way to do this conversion, here I used known mappings to go from
Edwards to Montgomery form, then Montgomery form to Weierstrass form. Please
let me know if there's a smarter way to do this!

We begin with the Edwards curve:

$$  
E_{c,d} : x^2 + y^2  = c^2 (1 + d x^2 y^2) \pmod p  
$$

This is in the less usual form, with the factor $c$, so before continuing, we
scale $(x,y,d)$ to remove $c$:

$$  
x \to \frac{x}{c}, \; \; y \to \frac{y}{c}, \;\; d \to c^4 d  
$$

To obtain the more familiar Edwards curve:

$$  
E_{c} : x^2 + y^2  = (1 + d x^2 y^2) \pmod p  
$$

Note: I am refering to $(x,y,d)$ using the same labels, I hope this doesnt
confuse people.

In this more familiar form, I referred to
https://safecurves.cr.yp.to/equation.html to map the curve to the Montgomery
curve

$$  
E_{A,B}: B v^2 =  u^3 + Au^2 + u \pmod p  
$$

With the factor $B$ here, I dont know how to create this curve using Sage,
maybe this is possible? This mapping is done by the coordinate transformation

$$  
u = \frac{1 + y}{1 - y}, \qquad v = \frac{2(1 + y)}{ x(1 - y)} = \frac{2u}{x}  
$$

and the curve parameters are related by

$$  
A = \frac{4}{1 - d } - 2 \qquad B = \frac{1}{1 - d }  
$$

Finally, we can convert this curve to short Weierstrass form (equations are
taken from https://en.wikipedia.org/wiki/Montgomery_curve)

$$  
E_{a,b}: Y^2 = X^3 + aX^2 + b \pmod p  
$$

My making the coordinate transformations

$$  
X = \frac{u}{B} + \frac{A}{3B}, \qquad Y = \frac{v}{B}  
$$

and the curve parameters are related by

$$  
a = \frac{3 - A^2}{3B^2} \qquad  b = \frac{2A^3 - 9A}{27B^3}  
$$

In this form, we can plug the points into the curve using Sage and solve the
discrete log. Implementation is given below

#### Grabbing the flag

```python  
from Crypto.Util.number import *

# Recovered from previous section  
p = 903968861315877429495243431349919213155709  
F = GF(p)  
cc = 495368774702871559312404847312353912297284  
c = F(cc).sqrt()  
d = 540431316779988345188678880301417602675534

# Point data from challenge  
P = (398011447251267732058427934569710020713094,
548950454294712661054528329798266699762662)  
Q = (139255151342889674616838168412769112246165,
649791718379009629228240558980851356197207)  
sP = (730393937659426993430595540476247076383331,
461597565155009635099537158476419433012710)  
tQ = (500532897653416664117493978883484252869079,
620853965501593867437705135137758828401933)

x1, y1 = P  
x2, y2 = Q  
x3, y3 = sP  
x4, y4 = tQ

R.<x,y> = PolynomialRing(F)  
g = (x^2 + y^2 - cc * (1 + d * x^2*y^2))

# Check the mapping worked!  
assert g(x=x1, y=y1) == 0  
assert g(x=x2, y=y2) == 0  
assert g(x=x3, y=y3) == 0  
assert g(x=x4, y=y4) == 0

# Scale: x,y,d to remove c:  
# x^2 + y^2 = c^2 * (1 + d * x^2*y^2)  
# to:  
# x^2 + y^2 = (1 + d * x^2*y^2)

d = F(d) * F(cc)^2  
x1, y1 = F(x1) / F(c),  F(y1) / F(c)  
x2, y2 = F(x2) / F(c),  F(y2) / F(c)  
x3, y3 = F(x3) / F(c),  F(y3) / F(c)  
x4, y4 = F(x4) / F(c),  F(y4) / F(c)

h = (x^2 + y^2 - (1 + d * x^2*y^2))

# Check the mapping worked!  
assert h(x=x1, y=y1) == 0  
assert h(x=x2, y=y2) == 0  
assert h(x=x3, y=y3) == 0  
assert h(x=x4, y=y4) == 0

# Convert from Edwards to Mont.  
# https://safecurves.cr.yp.to/equation.html  
def ed_to_mont(x,y):  
   u = F(1 + y) / F(1 - y)  
   v = 2*F(1 + y) / F(x*(1 - y))  
   return u,v

u1, v1 = ed_to_mont(x1, y1)  
u2, v2 = ed_to_mont(x2, y2)  
u3, v3 = ed_to_mont(x3, y3)  
u4, v4 = ed_to_mont(x4, y4)

e_curve = 1 - F(d)  
A = (4/e_curve - 2)  
B = (1/e_curve)

# Mont. curve: Bv^2 = u^3 + Au^2 + u  
R.<u,v> = PolynomialRing(ZZ)  
f = B*v^2 - u^3 - A* u^2 - u

# Check the mapping worked!  
assert f(u=u1, v=v1) == 0  
assert f(u=u2, v=v2) == 0  
assert f(u=u3, v=v3) == 0  
assert f(u=u4, v=v4) == 0

# Convert from Mont. to Weierstrass  
# https://en.wikipedia.org/wiki/Montgomery_curve  
a = F(3 - A^2) / F(3*B^2)  
b = (2*A^3 - 9*A) / F(27*B^3)  
E = EllipticCurve(F, [a,b])

# https://en.wikipedia.org/wiki/Montgomery_curve  
def mont_to_wei(u,v):  
   t = (F(u) / F(B)) + (F(A) / F(3*B))  
   s = (F(v) / F(B))  
   return t,s

X1, Y1 = mont_to_wei(u1, v1)  
X2, Y2 = mont_to_wei(u2, v2)  
X3, Y3 = mont_to_wei(u3, v3)  
X4, Y4 = mont_to_wei(u4, v4)

P = E(X1, Y1)  
Q = E(X2, Y2)  
sP = E(X3, Y3)  
tQ = E(X4, Y4)

# Finally we can solve the dlog  
s = P.discrete_log(sP)  
t = Q.discrete_log(tQ)

# This should be the flag, but s is broken  
print(long_to_bytes(s))  
print(long_to_bytes(t))

# b'\x05\x9e\x92\xbfO\xdf1\x16\xb0>s\x93\xc6\xc7\xe7\xa3\x80\xf0'  
# b'Ds_3LlipT!c_CURv3'

# We have to do this, as we picked the wrong square-root.  
print(long_to_bytes(s % Q.order()))  
print(long_to_bytes(t))

# b'nOt_50_3a5Y_Edw4r'  
# b'Ds_3LlipT!c_CURv3'  
```

##### Flag

`CCTF{nOt_50_3a5Y_Edw4rDs_3LlipT!c_CURv3}`

#### Wrong Root

When recovering the parameters we find:

```py  
# Recovered from previous section  
p = 903968861315877429495243431349919213155709  
F = GF(p)  
cc = 495368774702871559312404847312353912297284  
c = F(cc).sqrt()  
d = 540431316779988345188678880301417602675534  
```

however, there are two square roots to consider. By picking the wrong one, we
introduce a minus sign in the scaling of the curves from $E_{a,c}$ to $E_{a}$
which creates an issue with the point we consider in $E_{A,B}$. This can be
fixed by instead working with

```py  
# Recovered from previous section  
p = 903968861315877429495243431349919213155709  
F = GF(p)  
cc = 495368774702871559312404847312353912297284  
c = F((-1 * F(cc).sqrt()))  
d = 540431316779988345188678880301417602675534  
```

which would mean we did not need to take the reduction mod `Q.order()`

Original writeup (https://blog.cryptohack.org/cryptoctf2021-hard#rohald).