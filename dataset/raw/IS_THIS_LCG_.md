# IS_THIS_LCG? Writeup

### RCTF 2022 - crypto 645 - 12 solves

> As we known, LCG is **NOT** cryptographically secure.  
So we designed these variants. Prove us wrong!
[下载附件](_media_file_task_64ca7085-e3fc-469e-bd81-9fa3452918c6.zip)

Solved with @encrypted-def, a.k.a BaaaaaaaarkingDog.

#### Overview

Lets inspect [task/task.py](task/task.py).

```python  
p1 = gen_p1()  
p2 = gen_p2()  
p3 = gen_p3()  
q = getStrongPrime(1024)  
N = int(p1 * p2 * p3 * q)  
flag = bytes_to_long(urandom(N.bit_length() // 8 - len(flag) - 1) + flag)  
c = pow(flag, 0x10001, N)  
print('N = {}'.format(hex(N)))  
print('c = {}'.format(hex(c)))  
```

We must crack textbook multiprime RSA having `N = p1 * p2 * p3 * q`. `p1`,
`p2`, `p3` are sourced by some weird [linear congruential
generator(LCG)](https://en.wikipedia.org/wiki/Linear_congruential_generator)-ish
generators. We must recover `p1`, `p2`, `p3` using [output](output) given.

#### Stage 1: `p1` from [`partial_challenge.py`](task/partial_challenge.py)

```python  
def gen_p1():  
   m = 2 ** 1024  
   a = bytes_to_long(b'Welcome to RCTF 2022')  
   b = bytes_to_long(b'IS_THIS_LCG?')  
   x = getRandomInteger(1024)  
   for i in range(8):  
       x = (a * x + b) % m  
       print('x{} = {}'.format(i, hex(x >> 850)))  
   x = (a * x + b) % m  
   return next_prime(x)  
```

Truncated LCG's internal state can be recoverable using
[CVP](https://link.springer.com/referenceworkentry/10.1007/0-387-23483-7_66).
The attack is well known. Refer
[here](https://gist.github.com/maple3142/642ef0b59bf05882bccd5302e1310de1) and
[here](https://github.com/pcw109550/my-ctf-
challenges/tree/master/codegate2020/Qual/MUNCH) for more details. Attack
implemented in `solve1()` method.

#### Stage 2: `p2` from [`curve_challenge.py`](task/curve_challenge.py)

```python  
def gen_p2():  
   p = getStrongPrime(1024)  
   A = getRandomRange(p//2, p)  
   B = getRandomRange(p//2, p)  
   assert (4*A**3+27*B**2) % p != 0  
   E = EllipticCurve(GF(p), [A, B])  
   a = 1  
   b = E.random_element()  
   x = E.random_element()  
   for i in range(7):  
       x = a*x + b  
       print('x{} = {}'.format(i, hex(x[0])))  
   return p  
```

This type of RNG is called `EC-LCG`. We have 7 x-coordinates of elliptic curve
points. This part was the hardest part of this challenge. Guess the paper
time! According to the paper: [PREDICTING THE ELLIPTIC CURVE CONGRUENTIAL
GENERATOR](http://compalg.inf.elte.hu/~merai/pub/merai_predictingEC-LCG.pdf),

> The following theorem shows that if at least seven initial values are
> revealed, then it can be computed a curve E.

Exactly matches our situation. Implement the paper!

```python  
T = matrix(  
   ZZ,  
   [  
       [  
           2 * X[i] ^ 2 + 2 * X[i] * (X[i - 1] + X[i + 1]),  
           2 * X[i] - (X[i - 1] + X[i + 1]),  
           2 * X[i],  
           2,  
           (X[i - 1] + X[i + 1]) * X[i] ^ 2,  
       ]  
       for i in range(1, 6)  
   ],  
)  
```

The determinant of the upper matrix `T` is a multiple of `p2`. So we recover
`p2 = gcd(T.determinant(), N)`.

#### Stage 3: `p3` from [`matrix_challenge.py`](task/matrix_challenge.py)

```python  
def gen_p3():  
   n, m = 8, next_prime(2^16)  
   A, B, X = [random_matrix(Zmod(m), n, n) for _ in range(3)]  
   for i in range(1337**1337):  
       if i < 10:  
           print('X{} = {}'.format(i, hex(mt2dec(X, n, m))))  
       X = A*X + B  
   return next_prime(mt2dec(X, n, m))  
```

We recover `A` and `B` by using simple matrix calculation.

```python  
X0 = dec2mt(X0, n, m)  
X1 = dec2mt(X1, n, m)  
X2 = dec2mt(X2, n, m)  
delta1 = X1 - X0  
delta2 = X2 - X1  
A = delta2 * delta1 ^ (-1)  
B = X1 - A * X0  
```

We optimize advancement of LCG state by `1337 ** 1337` times by using the
multiplicative order of `A`. We just need to advance LCG by `pow(1337, 1337,
Aorder)`, using the definition of order. We finally evaluate `p3`:

```python  
Aorder = A.multiplicative_order()  
power = Integer(pow(1337, 1337, Aorder))  
ApowN = A ^ power  
I = matrix.identity(Zmod(m), n)  
Fin = ApowN * X0 + (ApowN - I) * (A - I) ^ (-1) * B  
p3 = next_prime(mt2dec(Fin, n, m))  
```

### Textbook RSA for flag

Textbook RSA time.

```python  
q = N // (p1 * p2 * p3)  
phiN = (p1 - 1) * (p2 - 1) * (p3 - 1) * (q - 1)  
e = 0x10001  
d = pow(e, -1, phiN)  
m = pow(c, d, N)

flag = long_to_bytes(int(m))  
```

We get flag:

```  
RCTF{Wo0oOoo0Oo0W_LCG_masT3r}  
```

Full exploit code: [solve.sage](solve.sage) requiring
[inequality_cvp.sage](inequality_cvp.sage): from  
[rkm0959/Inequality_Solving_with_CVP](https://github.com/rkm0959/Inequality_Solving_with_CVP).

Problem source: [task](task), [output](output)

Original writeup (https://github.com/pcw109550/write-
up/tree/master/2022/RCTF/IS_THIS_LCG).