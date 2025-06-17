# Prefix sum (ByteCTF 2020)

Check the challenge
[here](http://bytectf.eastus.cloudapp.azure.com/challenges#Prefix%20Sums-15)

## Description

Here’s your problem. Can you solve it? And this is the MD5 hash of the flag so
you know you got it right:  
`6046f30cf9e942ed47c88621a69ed0b2`

File:
[prefix_sums.pdf](http://bytectf.eastus.cloudapp.azure.com/files/383cb02ca35e14dc7c25fd5be0bcfafa/prefix_sums.pdf)

## Real description

The pdf contains the real description of the problem. The short version is:

Given a random sequence, containing `p` 0s and `q` 1s, what is the probability
that on each prexif of such sequence the number of 1s is strictly greater than
the number of 0s. You may assume each sequence happens with equal probability.

The problem boils down to count the number of valid sequence and the total
number of sequence, and find the ratio between such values. The total number
of sequence is simply: [`choose(p + q,
p)`](https://en.wikipedia.org/wiki/Combination).

The final answer would be:

`#valid_sequences / choose(p + q, p)`

### Counting valid sequences

The first element of a valid sequence must be a `1`. After we add the first
element, we can "relax" our problem to be: How many sequences of `p` 0s and
`q-1` 1s are there such that each prefix contains **at least as many 1s as
0s**.

Notice that if the number of 1s and 0s are the same in the subproblem, it is
equivalent to calculate the number of balanced parenthesis strings with `2 *
k` characters (say each `1` is an open parenthesis `(` and each `0` is a
closing parentheis `)`). This is a "well known" combinatoric value: [Catalan
number](https://en.wikipedia.org/wiki/Catalan_number) which can be also found
in [OEIS](https://oeis.org/A000108).

We should compute a more generalized version of Catalan Numbers: The number of
balanced parenthesis string (prefixes) that contains `q - 1` opening
parentheis and `p` closing parenthesis.

The easy way to solve such problem is assume this values are famous enough to
be in OEIS, so just brute force few small values, search for such sequence in
OEIS and get a closed formulae.

```python  
from functools import lru_cache

@lru_cache(None)  
def brute_force(tot_1, tot_0, prefix_sum):  
   if tot_1 == 0 and tot_0 == 0:  
       return 1

   res = 0

   if tot_1 > 0:  
       res += brute_force(tot_1 - 1, tot_0, prefix_sum + 1)

   if tot_0 > 0 and prefix_sum > 1:  
       res += brute_force(tot_1, tot_0 - 1, prefix_sum - 1)

   return res

for tot_1 in range(10):  
   print(tot_1, end=" : ")  
   # The amount of 1s must be strictly greater  
   # than the amount of 0s  
   for tot_0 in range(tot_1):  
       res = brute_force(tot_1, tot_0, 0)  
       print(res, end=" ")  
   print()  
```

The output of the previous code is:

```  
0 :  
1 : 1  
2 : 1 1  
3 : 1 2 2  
4 : 1 3 5 5  
5 : 1 4 9 14 14  
6 : 1 5 14 28 42 42  
7 : 1 6 20 48 90 132 132  
8 : 1 7 27 75 165 297 429 429  
9 : 1 8 35 110 275 572 1001 1430 1430  
```

Just search for any significant row in OEIS:
https://oeis.org/search?q=1+5+14+28+42+42  
And we get our desired answer: [Catalan's triangle
T(n,k)](https://oeis.org/A009766)

It turns out there is a very simple formulae: `T(n, m) = choose(n + m, n) * (n
- m + 1) / (n + 1)`. So we can print the previous table with the following
code (notice there is an off-by-one-error in the arguments of the formula with
respect to our formula):

```python  
from math import factorial

def choose(n, k):  
   return factorial(n) // factorial(k) // factorial(n - k)

for tot_1 in range(10):  
   print(tot_1, end=" : ")  
   # The amount of 1s must be strictly greater  
   # than the amount of 0s  
   for tot_0 in range(tot_1):  
       res = choose(tot_1 + tot_0 - 1, tot_1 - 1) * (tot_1 - tot_0) // (tot_1)  
       print(res, end=" ")  
   print()  
```

So the number of valid sequence is:

```  
n = 3141592653589793238  
p = 101124131231734

tot_1 = n - p  
tot_0 = p

#valid_sequences  
 = choose(tot_1 + tot_0 - 1, tot_1 - 1) * (tot_1 - tot_0) / (tot_1)  
 = choose(n - 1, n - p - 1) * (n - 2 * p) / (n - p)  
 = choose(n - 1, p) * (n - 2 * p) / (n - p)  
```

This is a humongous number which I recommned you don't try to compute locally.
The good news is that we are asked to compute the ratio of two number in a
simplified way:

```  
numerator = choose(n - 1, p) * (n - 2 * p) / (n - p)  
denominator = choose(n, p)  
```

We can simplify the combinatorial numbers by applying the following "trick":
`choose(n - 1, p) = choose(n, p) * (n - p) / n`.  
Then the ratio is just:

```  
answer = (n - 2 * p) / n  
```

The only thing remaining is to actually compute the flag from this value:

```python  
import hashlib

n = 3141592653589793238  
p = 101124131231734

def gcd(a, b):  
   return a if b == 0 else gcd(b, a % b)

num = n - 2 * p  
den = n

g = gcd(num, den)

num //= g  
den //= g

encoded = str(num) + str(den)  
encoded = hex(int(encoded))  
flag = f"flag{{{encoded}}}"

print(flag)

assert hashlib.md5(flag.encode()).hexdigest() ==
'6046f30cf9e942ed47c88621a69ed0b2'  
```

We are given the md5 hash of the flag, so we can even check without submitting
if we have the correct flag.

The output of the code above:

```  
flag{0xbd10c864dce5299aadd5b7aac2124eb}  
```  

Original writeup
(https://gist.github.com/mfornet/5f560a95ee31cb18932feb358de7bfc4).