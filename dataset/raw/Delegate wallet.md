# Challenge Name: Delegate Wallet

I have been using this software for generating crypto wallets. I think if I
was able to predict the next private key, I could probably steal the funds of
other users.

EU instance: 161.97.176.150 4008

US instance: 185.172.165.118 4008

Author: Soul

## First Glance

We are given a remote service and a
[wallet.py](https://github.com/pragyanmehrotra/0x414141_2021/blob/master/Delegate%20Wallet/wallet.py).

```  
class prng_lcg:

   def __init__(self):  
       self.n = pow(2, 607) -1   
       self.c = random.randint(2, self.n)  
       self.m = random.randint(2, self.n)  
       self.state = random.randint(2, self.n)

   def next(self):  
       self.state = (self.state * self.m + self.c) % self.n  
       return self.state

```  
This is the most interesting piece of code in the file rest of the code is
just interacting with the client. So from here it's clear that our n = 2^607 -
1 which stays constant for each execution, but m and c are generated randomly.

We have a look at the remote service as seen in wallet.py we are given 2
options to generate a new wallet seed or to guess it.  
```  
1) Generate a new wallet seed  
2) Guess the next wallet seed  
>  
```

## Approach

From the above observations, our task boils down to simply finding m and c.
Since if we know m and c then we can generate a seed $s$ and we would know
that the next seed is given by the equation s<sub>new</sub> = m\*s + c %n

Now, we are given the liberty to generate as many seeds as we want. Which
creates the vulnerability with reused parameters in [LCG (Linear Congruential
Generator)](https://en.wikipedia.org/wiki/Linear_congruential_generator).

This can be seen as a simple mathematical problem as -

Let s0 <- random seed, Then,  

s1 = (m\*s0 + c) mod n  
  
s2 = (m\*s1 + c) mod n  
  
s3 = (m\*s2 + c) mod n  

Now,

=> s3 - s2 = (m\*s2 + c) - (m\*s1 + c) mod n  
  
=> s3 - s2 = m\*(s2 - s1) + c - c mod n  
  
=> s3 - s2 = m\*(s2 - s1) mod n  
  
=> (s3 - s2)\*(s2 - s1)^-1 = m\*(s2 - s1)\*(s2 - s1)^-1 mod n  
  
=> m = (s3 - s2)\*(s2 - s1)^-1 mod n  

and once we have m,

s2 = m\*s1 + c mod n  
  
=> c = s2 - m\*s1 mod n  

Simple code to solve the equations given s1, s2, s3

```python  
n = pow(2, 607) -1  
m = ((s3 - s2)*gmpy.invert(s2 - s1, n))%n  
print "m: ", m  
c = (s3 - m*s2)%n  
print "c: ", c  
print "s4: ", (s3*m + c)%n  
```

Actual solution:
[solve.py](https://github.com/pragyanmehrotra/0x414141_2021/blob/master/Delegate%20Wallet/solve.py)

`flag{NBD_7H3Y_U53D_0ffsh1ft4532}`

Original writeup
(https://github.com/pragyanmehrotra/0x414141_2021/blob/master/Delegate%20Wallet/writeup.md).