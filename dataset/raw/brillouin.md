# brillouin

500 points, Crypto

## Description  
brillouin is an exciting new b l o c c c h a i n authentication provider. you
can tell how decentralized it is because the signatures are so small! nc
crypto.chal.csaw.io 1004

Author: (@japesinator, @trailofbits)

Files: [brillouin.py](brillouin.py)

## Solution

Basic inspection of the file reveals that BLS Signature Scheme is used to sign
and verify here. Googling here and there reveal  
that it makes use of a function `e` called bilinear pairing function. It works
on a pair of points on some elliptic curve and  
returns a point on some other curve. It has a property that -

```  
e(x + y, z) = e(x, z) * e(y, z)  
```

We don't need to know the actual structure of the function, just this property
is enough.

In BLS scheme, secret key `sk` is some integer and public key is the point `sk
* g` where `g` is the generator of the curve.

We sign a message `m` by first hashing this message to some point using a hash
function `H` and then multiplying it with our  
secret key `sk`:

`signature = sk * hash(m)`

We verify a message by comparing the values `e(g, signature)` and `e(pk,
hash(m))`, the signature is valid if both of them  
evaluate to the same point.

```  
if e(g, signature) == e(pk, hash(m)):  
   print("signature is valid")  
```

Why is this correct? Because for a valid signature:

`e(g, signature) = e(g, sk * hash(m)) = e(g, hash(m)) * e(g, hash(m)) * e(g,
hash(m)) ....` (`sk` times)  
` = e(g * sk, hash(m)) = e(pk, hash(m))`

In BLS signature scheme we also have a concept called aggregation which is
basically a linear operation over the public keys/  
signatures. Coefficients are determined by the `lagrange_basis` function
([defination](https://github.com/asonnino/bls/blob/master/bls/utils.py#L13)).
Aggregation is used in multiparty signature schemes,  
details of which I would be skipping, but you may read over [here]()

Now for the challenge, lets collect what all we have; We have three public
keys `pA`, `pB` and `pC`. We can get message "ham"  
signed by `pA`, `pB` is good for nothing and `pC` is the most useful - we can
get any of our message signed. End goal - we  
need to give them three public keys `p1`, `p2` and `p3` and two signatures
`s1` and `s2` such that aggregation of `s1` and `s2`  
is a valid signature of the public key obtained by aggregation of `p1`, `p2`
and `p3` for the message "this stuff".

There are some constraints too - `s1` and `s2` cannot be same
([here](brillouin.py#L65)), `p1` and `p2` must be one of the `pA`,  
`pB` and `pC`, though they can be same ([here](brillouin.py#L51)). _We have no
limitations for `p2`_. This is our catch. We use  
`lagrange_basis` function to calculate the coefficients, referring the code
from [here](https://github.com/asonnino/bls/blob/master/bls/scheme.py#L69)

```python  
from bls.scheme import setup

def lagrange_basis(t, o, i, x=0):  
	numerator, denominator = 1, 1  
	for j in range(1,t+1):  
		if j != i:  
			numerator = (numerator * (x - j)) % o  
			denominator = (denominator * (i - j)) % o   
	return (numerator * denominator.mod_inverse(o)) % o

params = setup()  
(G, o, g1, g2, e) = params  
# for 2 signatures  
l = [lagrange_basis(2, o, i, 0) for i in range(1,3)]  
print l  
# for 3 public keys  
l = [lagrange_basis(3, o, i, 0) for i in range(1,4)]  
```  
Output comes out to be -  
```  
[2,
16798108731015832284940804142231733909759579603404752749028378864165570215948]  
[3,
16798108731015832284940804142231733909759579603404752749028378864165570215946,
1]  
```

It is important to see that the difference between the two large numbers is 2.
Let us call them `L` and `L-2`.

So we now have to plug such values of `s1`, `s2`, `p1`, `p2` and `p3`such
that:

```  
e(g, 2*s1 + L*s2) == e(3*p1 + (L-2)*p2 + p3, hash("this stuff"))  
```  
Now suppose I sign the message "this stuff" with my key and pass that in `s2`
and get the sign of `pC` on the same message, I will get two signs of the
required message. Let's create a dummy public + secret key pair `sk0 = 3` and
`p0 = 3*g` and sign "this stuff" with it and get `s0`. Lets call the sign from
`pC` - `sC`. So,

```  
e(pC, hash("this stuff")) = e(g, sC)  
e(p0, hash("this stuff")) = e(g, s0)  
```

Now what we do is also called Rogue Public Key attack, but lets not use these
terms here. Rather a simple explaination - If I put `p1 = pC`, `p2 = pC` and
`p3 =  2*p0 - pC`:

```  
      e( 3*p1 + (L-2)*p2 + p3, hash("this stuff"))  
   =  e( (L+1)*pC + 2*p0 - pC, hash("this stuff"))  
   =  e( L*pC + 2*p0, hash("this stuff"))  
   =  e( pC, hash("this stuff") ) * e( pC, hash("this stuff") ) .... * e( p0,
hash("this stuff") ) * e( p0, hash("this stuff") )  
   =  e( g, sC ) * e( g, sC ) .... * e( g, s0 ) * e( g, s0 )  
   =  e( g, 2*s0 + L*sC )  
```  
  
Voila!

I can pass `s0` and `sC` as the signatures! And you get the flag on running
the script:

```  
flag{we_must_close_the_dh_gap}

```  

Original writeup (https://github.com/kanav99/csaw19-quals-
writeup/tree/master/brillouin-crypto-500).# CSAW CTF Qualification Round 2019 : Brillouin

**category** : crypto

**points** : 500

**solves** : 39

## write-up

This challenge use Boneh–Lynn–Shacham Scheme for signature verification

You can read [this article](https://medium.com/cryptoadvance/bls-signatures-
better-than-schnorr-5a7fe30ea716) first

In line 66, the server didn't check the third public key, so we can forge a
public key here

Read the source code of `bls.scheme.aggregate_vk`
[here](https://github.com/asonnino/bls/blob/master/bls/scheme.py#L54)

First `chester_sign` to sign a valid signature `s` of 'this stuff'

Send `s` and `2 * s` as signatures to server

Forge the third public key to cancel the second public key and make the
`aggregate_vk` calculate to `publics[2] + 2 * publics[2]`

Becuase the `Threshold` is True, it is actually calculate to `l2[0] *
publics[2] + l2[1] * 2 * publics[2]`

flag: `flag{we_must_close_the_dh_gap}`

# other write-ups and resources  

Original writeup (https://github.com/OAlienO/CTF/tree/master/2019/CSAW-
CTF/Brillouin).