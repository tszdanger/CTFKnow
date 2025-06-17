# SuperCurve Writeup

### CSAW Quals 2019 - crypto 300 - 171 solves

> We are a super legitimate crypto company asking you to complete an audit on
> our new elliptic curve, SuperCurve, in order to show those hecklers at
> WhiteHat how legit we are! `nc crypto.chal.csaw.io 1000`

#### Solving ECDLP

The challenge asked us to solve
EL[DLP](https://en.wikipedia.org/wiki/Discrete_logarithm). All the parameters
for initializing the problem was given. Base point `G`, Public key `P`, and
elliptic curve parameters `a`, `b`, `p`. The only changing value was `P`. `p =
14753` so the discrete logarithm problem can be easily solved using
bruteforce, or just ask sage to solve it by calling the `discrete_log` method.
Using the sage script, I successfully calculated the value of `secret_scalar`,
which is the solution of ECDLP.

```python  
a, b = 1, -1  
p = 14753  
E = EllipticCurve(Zmod(p), [a, b])  
G = E(1, 1)  
P = E(Px, Py)  
d = discrete_log(P, G, operation="+")  
assert P == d * G  
# d == secret_scalar  
```

Simply send it back to the server and get the flag:

```  
flag{use_good_params}  
```

exploit driver code: [solve.py](solve.py)

ecdlp solver: [ecdlp.sage](ecdlp.sage)

server: [server.py](server.py)

Supercurve module: [supercurve.py](supercurve.py)  

Original writeup (https://github.com/pcw109550/write-
up/tree/master/2019/CSAW/SuperCurve).