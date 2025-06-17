# Too secure (crypto, 237p, 26 solved)

## Description

In the task we get a
[pdf](https://raw.githubusercontent.com/TFNS/writeups/master/2020-07-25-CybricsCTF/too_secure/too_secure.pdf)
with task description.  
The description is not very accurate and it required a lot of hit-and-miss to
actually create a proper implementation...

The whole point of the task is to break a commitment scheme - user selects a
certain value and some random and calculates a special value called
`commitment`, and broadcasts this value.  
Randomization helps to hide the selection (others can't simply calculate
commitment over all possible selections).  
The point is that in future the user can reveal his selection and the random,
and everyone can confirm that this combination in fact matches the initial
commitment.

Our goal is to create a different pair `selection, random` which gives the
same `commitment` value.

Following the paper, and some guessing, the scheme is implemented as:

```python  
import hashlib  
from crypto_commons.generic import long_to_bytes, bytes_to_long

def bytes_to_long_le(S):  
   return sum([ord(S[i]) * 2 ** (8 * i) for i in range(len(S))])  
  
def calculate(g, p, m):  
   x = bytes_to_long_le(m)  
   G = pow(g, x, p)  
   Gprim = long_to_bytes(G)  
   Gprim = '\0' * (128 - len(Gprim)) + Gprim  
   a = hashlib.sha512(Gprim).digest()  
   a_prim = bytes_to_long(a)  
   a_dash = pow(a_prim, a_prim, p - 1)  
   h = pow(g, a_dash, p)  
   return G, h, a_dash  
  
p =
12039102490128509125925019010000012423515617235219127649182470182570195018265927223  
g =
10729072579307052184848302322451332192456229619044181105063011741516558110216720725  
r1 = 31245182471  
M1 = 'Hi! I am Vadim Davydov from ITMO University'  
G1, h1, a1 = calculate(g, p, M1)  
print(G1 * pow(h1, r1, p) % p)  
```

## Solution

In order to attack this scheme let's follow the computation backwards:

```  
(G * h^r mod p) mod p  
```

Since `G = (pow(g, x, p)` we have:

```  
(g^x mod p * h^r mod p) mod p  
```

Now because `h = pow(g, a_dash, p)` we have:

```  
(g^x mod p * (g^a_dash)^r mod p) mod p  
(g^x mod p * g^a_dash*r mod p) mod p  
g^(x+a_dash*r) mod p  
```

One thing we can notice here is that we can do `mod p-1` on the exponent by
power of Euler theorem -> `a^phi(p) mod p == 1`  
This is because we could mark `x+a_dash*r == y + k*(p-1)` and thus we would
have:

```  
g^(x+a_dash*r) mod p  
g^(y + k*(p-1)) mod p  
(g^y * g^k*(p-1)) mod p  
(g^y * (g^(p-1) mod p)^k) mod p  
(g^y * 1^k) mod p  
g^y mod p  
```

As follows, we could also do `mod t` where `t` is any of prime factors of
`p-1`.

Now what we want to do is to use different `x` and different `a_dash` but get
identical result, hence:

```  
x1+a_dash1*r1 = x2+a_dash2*r2  
x1-x2 + a_dash1*r1 = a_dash2*r2  
(x1-x2 + a_dash1*r1)/a_dash2 = r2  
```

Note that `x1`, `x2`, `a_dash1` and `a_dash2` are all contants given in the
task!

Now obviously it's unlikely that such integer value `r2` would exist, but as
we said above, we could make this whole equation `mod p-1` and it would still
hold just fine!  
This would imply that instead of division by `a_dash2` we would multiply by
`modinv(a_dash2, p-1)` and we would definitely get an integer.

The issue is that `gcd(a_dash2, p-1) != 1` so modinv does not exists.  
But as we noted above, we don't need `mod p-1`, we can use any prime factor of
`p-1` just as well.  
Conveniently there is a large prime factor `q` we can use!  
Since it's prime, we don't need to worry about `gcd` with `a_dash2`.  
(Keep in mind this large factor `q` is not at fault, it's necessary to avoid
the possibility of computig discrete logarithm!)

So we can simply do `r2 = (x1-x2 + a_dash1*r1) * modinv(a_dash2, q) % q` to
get one of potential `r2` values.

Note that since we're doing `mod q`, there are lots of other `r2` values in
form `r = r2 + k*q` as long as `r < p`

We do:

```python  
def main():  
   q =
1039300813886545966418005631983853921163721828798787466771912919828750891  
   p =
12039102490128509125925019010000012423515617235219127649182470182570195018265927223  
   g =
10729072579307052184848302322451332192456229619044181105063011741516558110216720725  
   r1 = 31245182471  
   M1 = 'Hi! I am Vadim Davydov from ITMO University'  
   M2 = 'Transfer the points for easy task to this team'  
   x1 = bytes_to_long_le(M1)  
   x2 = bytes_to_long_le(M2)

   G1, h1, a1 = calculate(g, p, M1)  
   G2, h2, a2 = calculate(g, p, M2)

   r2 = ((x1 - x2 + a1 * r1) * gmpy2.invert(a2, q) % q)  
   assert G1 * pow(h1, r1, p) % p == G2 * pow(h2, r2, p) % p  
   print(r2)

main()  
```

And recover the value
`299610740605778098196154877327490870095375317123548563579894088319476495`

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-07-25-CybricsCTF/too_secure/README.md).