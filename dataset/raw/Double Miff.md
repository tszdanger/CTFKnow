## Double Miff  
### Challenge  
>A new approach, a new attack. Can you attack this curve?  
[double_miff.txz](https://cr.yp.toc.tf/tasks/double_miff_58336b2ad5ed82754ac8e9b3bdcc8f25623c909c.txz)

```python  
#!/usr/bin/env python3

from Crypto.Util.number import *  
from secret import a, b, p, P, Q  
from flag import flag

def onmiff(a, b, p, G):  
   x, y = G  
   return (a*x*(y**2 - 1) - b*y*(x**2 - 1)) % p == 0

def addmiff(X, Y):  
   x_1, y_1 = X  
   x_2, y_2 = Y  
   x_3 = (x_1 + x_2) * (1 + y_1*y_2) * inverse((1 + x_1*x_2) * (1 - y_1*y_2),
p) % p  
   y_3 = (y_1 + y_2) * (1 + x_1*x_2) * inverse((1 + y_1*y_2) * (1 - x_1*x_2),
p) % p  
   return (x_3, y_3)

l = len(flag) // 2  
m1, m2 = bytes_to_long(flag[:l]), bytes_to_long(flag[l:])

assert m1 < (p // 2) and m2 < (p // 2)  
assert onmiff(a, b, p, P) and onmiff(a, b, p, Q)  
assert P[0] == m1 and Q[0] == m2

print(f'P + Q = {addmiff(P, Q)}')  
print(f'Q + Q = {addmiff(Q, Q)}')  
print(f'P + P = {addmiff(P, P)}')  
```

```python  
P + Q = (540660810777215925744546848899656347269220877882,
102385886258464739091823423239617164469644309399)  
Q + Q = (814107817937473043563607662608397956822280643025,
961531436304505096581595159128436662629537620355)  
P + P = (5565164868721370436896101492497307801898270333,
496921328106062528508026412328171886461223562143)  
```

### Solution  
We have a curve equation $ax(y^2 - 1) \equiv by(x^2 - 1) \mod p$ with unknown
$a$, $b$, $p$; $P$ and $Q$ are some points on it, and we have $P + Q$, $Q + Q$
and $P + P$.

We need to recover $x$-coordinates of $P$ and $Q$, since they contain parts of
the flag.  
Addition here is commutative and associative, so we have

$$  
(P + P) + (Q + Q) = P + P + Q + Q = P + Q + P + Q = (P + Q) + (P + Q).  
$$

We have 2 ways of representing $x$- and $y$-coordinates of $P + P + Q + Q$.
Set $P + Q = (x_1, y_1)$, $Q + Q = (x_2, y_2)$, $P + P = (x_3, y_3)$, $P + P +
Q + Q = (x_0, y_0)$. Then from addition formulas for $x$ we have

$$  
x_0 \equiv \frac{(x_2+x_3)(1+y_2y_3)}{(1+x_2x_3)(1-y_2y_3)} \mod p \\  
x_0 \equiv \frac{2x_1(1+y_1^2)}{(1+x_1^2)(1-y_1^2)} \mod p  
$$,

from where we get this:

$$  
p|((1+x_1^2)(1-y_1^2)(x_2+x_3)(1+y_2y_3) - 2x_1(1+y_1^2)(1+x_2x_3)(1-y_2y_3))  
$$

Analogously from addition formulas for y we get

$$  
p|((1+y_1^2)(1-x_1^2)(y_2+y_3)(1+x_2x_3)-2y_1(1+x_1^2)(1+y_2y_3)(1-x_2x_3))  
$$

We can compute gcd of 2 numbers above to get a small multiple of $p$ ($8p$ in
this case), and from there we get $p =
1141623079614587900848768080393294899678477852887$.

Recall that for any point on the curve we have $ax(y^2-1) \equiv by(x^2-1)
\mod p$, from where we can compute $k \equiv \frac{a}{b} \equiv \frac{y(x^2 -
1)}{x(y^2-1)} \mod p$ by using any known point.

Note that we also have $\frac{y}{y^2-1} \equiv k\frac{x}{x^2-1} \mod p$.

Set $P = (x_4, y_4)$, and from addition formulas we get:

$$  
x_3 \equiv \frac{2x_4(1+y_4^2)}{(1+x_4^2)(1-y_4^2)} \mod p \\  
y_3 \equiv \frac{2y_4(1+x_4^2)}{(1+y_4^2)(1-x_4^2)} \mod p  
$$

from where we get

$$  
x_3y_3 \equiv \frac{4x_4y_4}{(x_4^2-1)(y_4^2-1)} \equiv 4k(\frac{x_4}{x_4^2 -
1})^2 \mod p  
$$

and then $(\frac{x_4^2-1}{x_4})^2 \equiv \frac{4k}{x_3y_3} \mod p$ and have
$\frac{x_4^2-1}{x_4} \equiv \pm l \mod p$, where $l \equiv
(\frac{4k}{x_3y_3})^{\frac{p+1}{4}} \mod p$, since $p \equiv 3 \mod 4$.

From here we get $x_4^2 \mp lx_4 - 1 \equiv 0 \mod p$. Discriminant in both
cases is equal to $D \equiv l^2 + 4 \mod p$, and we get roots of both
equations with $\frac{\pm l \pm \sqrt{D}}{2} \mod p$. Check each one of them,
the one that results into printable text gives us the first half of the flag.
Analogously we can recover $x$-coordinate of $Q$ and get second half of the
flag. By concatenating them, we will have the full flag. Judging by the flag,
though, this may be an unintended solution.

### Implementation  
```python  
#!/usr/bin/env python3  
from Crypto.Util.number import isPrime, long_to_bytes  
from math import gcd

x1, y1 = (540660810777215925744546848899656347269220877882,
102385886258464739091823423239617164469644309399)  
x2, y2 = (814107817937473043563607662608397956822280643025,
961531436304505096581595159128436662629537620355)  
x3, y3 = (5565164868721370436896101492497307801898270333,
496921328106062528508026412328171886461223562143)  
num1 = (1 + x1 ** 2) * (1 - y1 ** 2) * (x2 + x3) * (1 + y2 * y3) - 2 * x1 * (1
+ y1 ** 2) * (1 + x2 * x3) * (1 - y2 * y3)  
num2 = (1 + y1 ** 2) * (1 - x1 ** 2) * (y2 + y3) * (1 + x2 * x3) - 2 * y1 * (1
+ x1 ** 2) * (1 + y2 * y3) * (1 - x2 * x3)  
pmult = gcd(num1, num2)  
for i in range(2, 10):  
   while pmult % i == 0:  
       pmult //= i  
   if isPrime(pmult):  
       p = pmult  
       break

def recover_half(x, y):  
   k = y * (x ** 2 - 1) * pow(x * (y ** 2 - 1), -1, p) % p  
   l = pow(4 * k * pow(x * y, -1, p), (p + 1) // 4, p)  
   D = (l ** 2 + 4) % p  
   sqrtD = pow(D, (p + 1) // 4, p)  
   for i in range(-1, 2, 2):  
       for j in range(-1, 2, 2):  
           num = (i * l + j * sqrtD) * pow(2, -1, p) % p  
           text = long_to_bytes(num)  
           if b'CCTF{' in text or b'}' in text:  
               return text

first_half = recover_half(x3, y3)  
second_half = recover_half(x2, y2)  
flag = (first_half + second_half).decode()  
print(flag)  
```

##### Flag  
`CCTF{D39enEr47E_ECC_4TtaCk!_iN_Huffs?}`

Original writeup (https://blog.cryptohack.org/cryptoctf2021-hard#double-miff).