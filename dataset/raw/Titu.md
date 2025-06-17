## Titu  
### Challenge

>
> [Cryptography](https://cr.yp.toc.tf/tasks/Tuti_f9ebebb92f31b4eaefdb6491bdcd7a9c008ad2ec.txz)
> is coupled with all kinds of equations very much!

```python  
#!/usr/bin/env python3

from Crypto.Util.number import *  
from flag import flag

l = len(flag)  
m_1, m_2 = flag[: l // 2], flag[l // 2:]

x, y = bytes_to_long(m_1), bytes_to_long(m_2)

k = '''  
000bfdc32162934ad6a054b4b3db8578674e27a165113f8ed018cbe9112  
4fbd63144ab6923d107eee2bc0712fcbdb50d96fdf04dd1ba1b69cb1efe  
71af7ca08ddc7cc2d3dfb9080ae56861d952e8d5ec0ba0d3dfdf2d12764  
'''.replace('\n', '')

assert((x**2 + 1)*(y**2 + 1) - 2*(x - y)*(x*y - 1) == 4*(int(k, 16) + x*y))  
```

Given this source, the goal is to solve the equation to obtain both $x,y$.

### Solution

Factoring $k$ we find that it is a perfect square

```python  
sage: factor(k)  
2^2 * 3^2 * 11^4 * 19^2 * 47^2 * 71^2 * 3449^2 * 11953^2 * 5485619^2 *
2035395403834744453^2 * 17258104558019725087^2 *
1357459302115148222329561139218955500171643099^2  
```

Which tells us that moving some terms around, we can write the left hand side
as a perfect square too:

```python  
sage: f = (x**2 + 1)*(y**2 + 1) - 2*(x - y)*(x*y - 1) - 4*x*y  
sage: f  
x^2*y^2 - 2*x^2*y + 2*x*y^2 + x^2 - 4*x*y + y^2 + 2*x - 2*y + 1  
sage: factor(f)  
(y - 1)^2 * (x + 1)^2  
```

So we can solve this challenge by looking at the divisors of $\sqrt{4k}$ as we
have

$$  
(y - 1)^2  (x + 1)^2 = 4k = m  
$$

This is easy using Sage's `divisors(m)` function:

```python  
factors = [2, 2, 3, 11, 11, 19, 47, 71, 3449, 11953, 5485619,
2035395403834744453, 17258104558019725087,
1357459302115148222329561139218955500171643099]

m = prod(factors)  
  
for d in divs:  
   x = long_to_bytes(d - 1)  
   if b'CCTF{' in x:  
       print(x)    
       y = (n // d) + 1   
       print(long_to_bytes(y))

b'CCTF{S1mPL3_4Nd_N!cE_D'  
b'iophantine_EqUa7I0nS!}'  
```

##### Flag

`CCTF{S1mPL3_4Nd_N!cE_Diophantine_EqUa7I0nS!}`

Original writeup (https://blog.cryptohack.org/cryptoctf2021-easy#titu).