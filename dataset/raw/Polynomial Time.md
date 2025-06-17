Challenge Source:

```python  
import time  
import numpy as np  
import random

def interpolate(l):  
   for _ in range(624):  
       x = random.getrandbits(32*2**4)  
       print(x)  
   mo = random.getrandbits(32*2**4)  
   FR.<x> = PolynomialRing( IntegerModRing(mo) )  
   f = prod([(random.getrandbits(32*2**4)*x-1) for _ in range(1,l)])  
   return f, mo

#hmm, maybe a bit slow  
def evaluate(poly, points, mo):  
   evaluations = []  
  
   for point in points:  
       evaluations.append(poly(point))  
  
   return evaluations

if __name__ == "__main__":  
   with open("flag.txt","r") as f:  
       flag = f.read()  
  
   size = 1048576  
   poly, mo = interpolate(size)  
   R = Integers(mo)  
   points = [R(random.getrandbits(32*2**4)) for _ in range(size)]  
   ans = bytearray.fromhex(hex(prod(evaluate(poly,points,mo)))[2:-10])  
  
  
   ciphertext = bytearray(b"")  
   for i, c in enumerate(flag):  
       ciphertext.append(ord(c)^^ans[i])  
  
   print(ciphertext)  
```

The encryption is a one time pad.

We need to evaluate

$$ans =\prod \limits _{i=1}^{size}f(x_i) \mod m$$ for a given $$f(x) = \prod
\limits _{i=1}^{size}(a_ix - 1) \mod m$$

$m, a_i, x_i$ are generated from python's
[random.getrandbits()](https://docs.python.org/2/library/random.html#random.getrandbits)
function, which uses a [Mersenne
Twister](https://en.wikipedia.org/wiki/Mersenne_Twister) that is not
cryptographically secure. This is because observing a sufficient number of
outputs (624) allows one to predict all future outputs. Indeed, we do get 624
outputs in the problem and thus can obtain $m, a_i, x_i$.

Using the [mersenne-twister-predictor](https://mersenne-twister-
predictor.readthedocs.io/en/latest/) library in python, I was able to obtain
the values.

```python  
import random  
from mt19937predictor import MT19937Predictor

predictor = MT19937Predictor()

s = """  
number1  
number2  
... (copy from outputpt.txt)  
"""

arr = [int(x) for x in s.split("\n")[1:-1]]  
for _ in range(624):  
   predictor.setrandbits(arr[_], 512)

size = 2**20  # 1048576  
with open("mersenneoutputs.txt", "w") as f:  
   for i in range(2*size+1):  
       f.write(str(predictor.getrandbits(512)) + "\n")  
```

After we obtain $m, a_i, x_i$, we can get $f(x)$

```python  
with open("mersenneoutputs.txt", "r") as f:  
  
   arr = [int(x) for x in f.readlines()]  
   size = 2^20  
   mo = arr[0]

   FR.<x> = PolynomialRing( IntegerModRing(mo) , implementation = "NTL")

   f = prod([(arr[_]*x-1) for _ in range(1,size)])

   R = Integers(mo)  
   points = [R(arr[size+_]) for _ in range(size)]  
```

Now we need to evaluate $f(x_i)$ for each $x_i$. Since $f(x)$ is of order
$size$, it will take $O(size)$ time. We have $size$ points to evaluate, so in
total this will take $O(size^2)$ time. For $size = 2^{20}$, this is too slow.

After looking for a bit, I found this post about [multi-point evaluation of a
polynomial mod p](https://cs.stackexchange.com/questions/60239/multi-point-
evaluations-of-a-polynomial-mod-p), which is what I needed. The
[lecture](https://docplayer.net/25594945-Lecture-4-polynomial-algorithms.html)
was also useful.

This is how I understood it.

We know that

$f(t) = f(x) \mod (x-t)$

Proof:

$f(x) = A(x)(x-t) + R$ for some polynomial $A(x)$

subbing $x = t$ gives $f(t) = R$

Thus we need to calculate $f(x) \mod (x-x_i)$  for all $x_i$

SageMath's [NTL implementation](https://libntl.org/doc/ZZ_pX.cpp.html) uses
FFT for polynomial multiplication and division, which takes $O(N \log N)$ time
where $N$ is the order of the polynomial.

However we still cannot just do this for all $x_i$ as it will be $O(size) *
O(size \log size) = O(size^2 \log size)$ which is too slow.

My idea was to generate a binary tree, where each node stores a polynomial.

The i-th leaf of the tree stores $(x-x_i)$. For the parent of nodes storing
polynomials $P_1(x)$ and $ P_2(x)$, it will store $P_1(x)P_2(x)$.

Now, with this tree, we will calculate $f_{new}(x) := f(x) \mod P(x)$ for the
node storing $P(x)$.

Then, for its child storing $P_c(x)$, we will calculate $f_{newnew}(x) :=
f_{new}(x) \mod P_c(x)$, and so on until we reach the leaves.

We will get $f_{newnew....new} = f(x) \mod (x-x_i) = f(x_i)$ for all $x_i$ ,
which we take the product to get our answer.

For a rough estimate of the time complexity using Master Theorem, $T(n) =
2T(n/2) + O(n \log n)$ gives $T(n) = O(n \log^2 n)$, which is fast enough.

All these operations are done in the polynomial ring in the original source.  
```python  
tree = [0 for i in range(size*2)]  
ft = [0 for i in range(size*2)]

# For our binary trees, node i has children (2*i) and (2*i + 1). The parent of
node i is node (i//2)  
for i in range(size):  
   tree[i+size] = (x-points[i]) # set leaves

for i in range(size-1,0,-1):  
   tree[i] = tree[i*2]*tree[i*2+1]  # multiply polynomials of children

ft[1] = f                        # original f  
for i in range(2,size*2):  
   ft[i] = ft[i//2]%tree[i]     # f_child = f_parent mod P

ans = prod(ft[size:size*2])      # product of f(x_i)  
print(ans)  
```

This took around 5 minutes to run and we can get the answer, which we then use
as the one time pad to get the plaintext.

```python  
ciphertext =
b'/\xbe\x9f\x83\x8a\x9eY\xb43\x9f\xfa\xc2\x98\xe9@K\xd7r\xd7j\xde\xd5\xef,\xda\x11\x1as\x83k\x10\xb8\xaaP\x7f
\xb6|\xe02\x0fr\x0b\xf8\x9c\xfep2' # last line of outputpt.txt  
otp = bytearray.fromhex(hex(int(ans))[2:-10])  
  
plaintext = bytearray(b"")  
for i, c in enumerate(ciphertext):  
   plaintext.append(c^^otp[i])

print(plaintext)  
```  
Flag: `kqctf{p0lyn0m14l5_c4n_b3_v3ry_f457_0r_v3ry_5l0w}`

Full code:

```python  
import numpy as np  
import random

def interpolate(l):  
   for _ in range(624):  
       x = random.getrandbits(32*2**4)  
  
   return f, mo

with open("mersenneoutputs.txt", "r") as f:  
  
  
   arr = [int(x) for x in f.readlines()]  
   size = 2^20  
   mo = arr[0]

   FR.<x> = PolynomialRing( IntegerModRing(mo) , implementation = "NTL")

   f = prod([(arr[_]*x-1) for _ in range(1,size)])

   R = Integers(mo)  
   points = [R(arr[size+_]) for _ in range(size)]

   tree = [0 for i in range(size*2)]  
   ft = [0 for i in range(size*2)]  
  
   for i in range(size):  
       tree[i+size] = (x-points[i])  
  
   for i in range(size-1,0,-1):  
       tree[i] = tree[i*2]*tree[i*2+1]  
  
   ft[1] = f  
   for i in range(2,size*2):  
       ft[i] = ft[i//2]%tree[i]  
  
   ans = prod(ft[size:size*2])  
   print(ans)

   ciphertext =
b'/\xbe\x9f\x83\x8a\x9eY\xb43\x9f\xfa\xc2\x98\xe9@K\xd7r\xd7j\xde\xd5\xef,\xda\x11\x1as\x83k\x10\xb8\xaaP\x7f
\xb6|\xe02\x0fr\x0b\xf8\x9c\xfep2' # last line of outputpt.txt  
   otp = bytearray.fromhex(hex(int(ans))[2:-10])  
  
   plaintext = bytearray(b"")  
   for i, c in enumerate(ciphertext):  
       plaintext.append(c^^otp[i])  
  
   print(plaintext)  
  
```