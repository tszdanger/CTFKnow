# Show me your private key Writeup

### Harekaze 2019 - crypto 200

Our goal is to find the generator `G` of curve. We can factor `n = p * q` by
knowing secret key `d`. Also we can evaluate `b` since point `(Cx, Cy)` is
also on the given curve. By knowing all the parameters needed for constructing
elliptic curve `EC` in sage, we get the following code.

``` python  
b = (pow(Cy, 2, n) - pow(Cx, 3, n)) % n  
EC = EllipticCurve(Zmod(n), [0, b])  
```

To obtain `G`, we must first know the order `#EC` of `EC`, and get the modular
inverse of `e` over `#EC` because of the following equations.

``` python  
C = EC(Cx, Cy)  
C = e * G  
einv = inverse(e, EC.order())  
G = e * einv * G  
 = einv * e * G  
 = einv * C  
```

However, sage couldn't evaluate `#EC` since `n` was composite(sage gave an
error when `EC.order()` was called). We may manually calculate the order `#EC`
since we know the factor of `n`. By using the
[fact](https://link.springer.com/content/pdf/10.1007%2FBFb0054116.pdf)(fact 4)
introduced in this paper, we successfully computed the order `#EC` by the
following code.

``` python  
assert n == p * q  
E1 = EllipticCurve(IntegerModRing(p), [0, b])  
E2 = EllipticCurve(IntegerModRing(q), [0, b])  
# order of EC: #EC  
E_order = E1.order() * E2.order()  
```

Now it is straightforward, evaluate generater `G` and get the flag.

``` python  
einv = inverse_mod(e, E_order)  
G = einv * C  
Gx, Gy = G.xy()  
flag = long_to_bytes(Gy) + long_to_bytes(Gx)  
```

We get the flag:

```  
HarekazeCTF{dynamit3_with_a_las3r_b3am}  
```

Full exploit code: [solve.sage](solve.sage)

Original problem: [problem.sage](problem.sage)

Output: [result.txt](result.txt)

Original writeup (https://github.com/pcw109550/write-
up/tree/master/2019/Harekaze/show_me_your_private_key).