## Polish  
### Challenge

> Maybe this time we should focus on important parts of
> [RSA](https://cr.yp.toc.tf/tasks/polish_attack_de0955bc42af9591300a30c39dc74aaceea2451d.txz)!

```python  
m = bytes_to_long(flag)

e = 65537

n = p * q  
 =
40246250034008312612597372763167482121403594640959033279625274444300931999548988739160328671767018778652394885185401059130887869211330599272113849088780129624581674441314938139267245340401649784020787977993123159165051168187958742107

d =
0b1[REDACTED]00001101110000010101000000101110000111101011011101111111000011110101111000100001011100001111011000010101010010111100000011000101000001110001111100001011001100010001100000011100001101101100011101000001010001100000101000001

c = pow(x**2 + m + y, e, n)  
 =
28505561807082805875299833176536442119874596699006698476186799206821274572541984841039970225569714867243464764627070206533293573878039612127495688810559746369298640670292301881186317254368892594525084237214035763200412059090430060075

x**2 * (y -
146700196613209180651680280746469710064760660116352037627587109421827052580531)
+ y**2 * (x -
146700196613209180651680280746469710064760660116352037627587109421827052580531)
=
27617741006445293346871979669264566397938197906017433294384347969002810245774095080855953181508639433683134768646569379922750075630984038851158577517435997971553106764846655038664493024213691627948571214899362078353364358736447296943  
```

We have $n$ which we probably need to factor, along with $221$ LSBs of $d$. We
also have a diophantine to solve in order to get $x, y$. If we factorize $n$
and find $x, y$, we can compute the flag.

### Factorization of $n$

It's known that with lower $1/4$ bits of $d$, we can factorize $n$ in
polynomial time of $e$. To learn how, check out Theorem 9 on [Twenty Years of
Attacks on the RSA Cryptosystem](https://crypto.stanford.edu/~dabo/papers/RSA-
survey.pdf).

Basically, we can compute $\mathcal{O}(e \log_2 e)$ candidates for the lower
half bits of $p$ by solving some quadratic congruences, which we can apply
Coppersmith afterwards to factorize $n$.

### Solving the Diophantine

We start by writing the equation as

$$  
x^2(y-a) + y^2(x-a) = b  
$$

To solve this, we substitute

$$  
u = x+y, \quad v = xy  
$$

and rewrite our equation as

$$  
xy(x+y) - a(x^2+y^2) = b \\  
uv - a(u^2 - 2v) = b \\  
(u+2a) v = au^2 + b \\  
v = \frac{au^2 + b}{u + 2a}  
$$

Performing long division, we see that

$$  
v = au - 2a^2 + \frac{4a^3 + b}{u + 2a}  
$$

This shows that $u + 2a$ is a factor of $4a^3 + b$. Therefore, it makes sense
to try and factorize $4a^3 + b$ to compute the possible values for $u$.

Surprisingly, it turns out that

$$  
4a^3 + b = n  
$$

Now we see that factorization of $n$ solves the problem. Since $n = pq$ has
four divisors, we have a small number of candidates for $u+2a$. For each
candidate, we can compute $u$, then compute $v$. From $u, v$, we can solve a
quadratic to find $x, y$. Then, we can compute the flag.

### Back to Factorization of $n$

rbtree was writing the program to find the factorization of $n$. At first, we
$n = pq$ would split evenly, i.e. both $p, q$ would have around $387$ bits.

In this case, after we compute (a candidate of) $221$ LSBs of $p$, we have to
find the remaining $166$ MSBs of $p$. To utilize Coppersmith attack, we used
SageMath's small_roots with $\beta = 0.5$ and $\epsilon$ that

$$  
2^{166} \le \frac{1}{2} n^{\beta^2 - \epsilon}  
$$  
We decided to use $\epsilon = 0.034$ and run the algorithm.

However, while running this algorithm, I suggested that $n = pq$ will not
split evenly.

The logic is that one of the factors of $n$ would be $u + 2a$. If we guess
that $x$ and $y$ have similar size, we would have something like $x \sim y
\sim M$ where $M$ is the value such that

$$  
2 M^2(M-a) = b  
$$

Since $b \sim a^3$ we would also have $M \sim a$ which implies $u + 2a \sim a$
as well. Here, $A \sim B$ when $A, B$ have a similar size, i.e. $\max(A, B) /
\min(A, B)$ is a small value.

Since $a$ has around $256$ bits, what this means is that $u + 2a$ also has
around $256$ bits, i.e. one of $p, q$ has around $256$ bits. Therefore, if our
guess is correct, then $n$, which is $773$ bits, is composed of something like
$258$ bit $p$ and $515$ bit $q$. This changes how we have to choose $\beta$
and $\epsilon$.

In the end, we have chosen $\beta = 0.33$ and $\epsilon = 0.05$ in the end and
ran the algorithm with 20 cores.

```python  
# Part 1 : Factorization of n, written by rbtree  
# Also, multiprocess the code below with multiple cores for shorter
computation time

e = 65537  
n =
40246250034008312612597372763167482121403594640959033279625274444300931999548988739160328671767018778652394885185401059130887869211330599272113849088780129624581674441314938139267245340401649784020787977993123159165051168187958742107

mod = 2^221  
d_low =
0b00001101110000010101000000101110000111101011011101111111000011110101111000100001011100001111011000010101010010111100000011000101000001110001111100001011001100010001100000011100001101101100011101000001010001100000101000001

def get_p(p_low):  
   F.<z> = PolynomialRing(Zmod(n))

   f = mod * z + p_low  
   f = f.monic()  
   res = f.small_roots(beta=0.33, epsilon=0.05)

   if len(res) > 0:  
       return 1  
   return None

R.<x> = PolynomialRing(ZZ)  
for k in range(1, e + 1):  
   cands = [1]  
   f = k * x^2 + (e*d_low - k*n - k - 1) * x + k * n  
   for i in range(1, 221):  
       new_cands = []  
       for v in cands:  
           if f(v) % 2^(i+1) == 0:  
               new_cands.append(v)  
           if f(v + 2^i) % 2^(i+1) == 0:  
               new_cands.append(v + 2^i)  
  
       cands = new_cands  
       if len(new_cands) == 0:  
           print("break", i)  
           break

   print(k)  
   print(cands)

   ret = None  
   for v1 in cands:  
       for v2 in cands:  
           if v1 * v2 % mod != n % mod:  
               continue  
           ret = get_p(v1)  
           break  
       if ret is not None:  
           break  
  
   print(ret)  
   if ret:  
       break  
```

```python  
# Part 2 : Calculating the Flag

def inthroot(a, n):  
   return a.nth_root(n, truncate_mode=True)[0]

n =
40246250034008312612597372763167482121403594640959033279625274444300931999548988739160328671767018778652394885185401059130887869211330599272113849088780129624581674441314938139267245340401649784020787977993123159165051168187958742107

a =
146700196613209180651680280746469710064760660116352037627587109421827052580531  
b =
27617741006445293346871979669264566397938197906017433294384347969002810245774095080855953181508639433683134768646569379922750075630984038851158577517435997971553106764846655038664493024213691627948571214899362078353364358736447296943

assert n == 4 * a * a * a + b

# from rbtree's code with partial exposure attack on d  
p =
893797203302975694226187727100454198719976283557332511256329145998133198406753  
q = n // p

u = p - 2 * a  
v = (a * u * u + b) // (u + 2 * a)  
dif = inthroot(Integer(u * u - 4 * v), 2)

x = (u + dif) // 2  
y = (u - dif) // 2

e = 65537

c =
28505561807082805875299833176536442119874596699006698476186799206821274572541984841039970225569714867243464764627070206533293573878039612127495688810559746369298640670292301881186317254368892594525084237214035763200412059090430060075

d = inverse(e, (p-1) * (q-1))

res = pow(c, d, n)

print(long_to_bytes(res - x * x - y))  
print(long_to_bytes(res - y * y - x))  
```

##### Flag

`CCTF{Par7ial_K3y_Exp0sure_At7ack_0n_L0w_3xP_RSA}`

Original writeup (https://blog.cryptohack.org/cryptoctf2021-hard#polish).