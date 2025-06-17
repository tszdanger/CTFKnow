# nDLP

## Description

How hard are discrete logarithms problems in Z_n? Try to solve the given
[DLP](https://asisctf.com/tasks/nDLP_e29f9df33a5782c92e485a1bf648ca950d323024.txz).

## Writeup

The file contains a discrete logarithm problem:

```python  
x = bytes_to_long(flag)  
g = 685780528648223163108441  
n =
12588567055208488159342105634949357220607702491616160304212767442540158416811459761519218454720193189  
y = pow(g, x, n)  
y =
9136134187598897896238293762558529068838567704462064643828064439262538588237880419716728404254970025  
```

We should find `x` and use `long_to_bytes` to convert it into a string.

We have:

<div align = "center">

![](./formula/mod.svg)

</div>

To find x, we should use Discrete Logarithm. By using factorization tools
(Like [Alperton](https://www.alpertron.com.ar/ECM.HTM)) we found that `n` is
not prime. Actually:

<div align = "center">

![](./formula/y.svg)

</div>

We need a prime modulus to solve DLP trivially, but our modulus is not prime
here. We could use two approaches here. The first approach is to calculate the
remainder of y when divided by each prime factor; Then, solve DLP for each of
the prime factors and use the Chinese remainder theorem to combine the results
and find the answer.

But our solution is much more straightforward :))

### Solution

Our solution is to use online tools :)) We used
[Alperton](https://www.alpertron.com.ar/DILOG.HTM) website to solve the DLP
problem. It solves it even for composite numbers. We just need to input `g` as
`Base`, `y` as `Power`, and `n` as `Modulus` in this site, and after some
time, it gives us the general result of this problem:

<div align = "center">

![](./formula/x.svg)

</div>

By evaluating the expression above for `k=0` and using this simple python
script, we can quickly get the flag:

```python  
from Crypto.Util.number import *

print(long_to_bytes(1936424274652643265366177146994482280350488968204318138649641400181832241265975677))

```

The flag is:

```  
ASIS{D!5Cre73_L09_iN_Zn_I5_3aSy?!}  
```

Original writeup (https://github.com/titansarus/ASIS-CTF-
Final-2021/tree/main/nDLP).