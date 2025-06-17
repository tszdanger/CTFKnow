# DarkpearAI 500 points

_Writeup:_

This problem is based on [Diffie-Hellman](https://hackernoon.com/algorithms-
explained-diffie-hellman-1034210d5100). Our goal is to find the Secret Key.
The data provided to us are messages between two person (Alice & Bob for
instance) & two numbers.  
We can identify those numbers provided to us as `base` and prime `modulus`.

Now, we have 4 known variables.

```  
g = 3  
n = 371781196966866977144706219746579136461491261  
Person1: applepearblue  
Person2: darkhorseai  
```

We first need to convert those messages into decimal format as correct
conversion would matter while performing discrete logarithm. We carefully
convert and retrieve

```  
m1 = 97112112108101112101097114098108117101  
m2 = 100097114107104111114115101097105  
```

Diffie-Hellman equations are as follow (where a,b are the secret of Person1
and Person2 respectively):  
```  
m1 = pow(g,a)%n  
m2 = pow(g,b)%n  
```

For the secret-key our goal is to get  
```  
secretkey = pow(g,a*b)%n  
```  
which requires the information of a,b. Another discrete logarithm problem, but
our friend Sage's `discrete_log` would be enough for this (Internally, it
implements Pohlig-Hellman)  
So, we use the following to crack `a` and `b`

Then it's a simple equation to get the secretkey.

The full solver is implemented in [dh-
solve.sage](https://github.com/aadityapurani/My-CTF-
Solutions/blob/master/ritsec-2018/DarkpearAI/dh-solve.sage)

```  
./sage dh-solve.sage  
RITSEC{342060940412689854597111481732886330798298027}  
```  
##### Flag: RITSEC{342060940412689854597111481732886330798298027}  

Original writeup (https://github.com/aadityapurani/My-CTF-
Solutions/tree/master/ritsec-2018/DarkpearAI).