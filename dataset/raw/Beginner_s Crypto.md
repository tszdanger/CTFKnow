# TSG CTF 2020 Beginner's Crypto

## Problem

The problem is given in the form of the follewing file:

```python  
assert(len(open('flag.txt', 'rb').read()) <= 50)  
assert(str(int.from_bytes(open('flag.txt', 'rb').read(), byteorder='big') <<
10000).endswith('1002773875431658367671665822006771085816631054109509173556585546508965236428620487083647585179992085437922318783218149808537210712780660412301729655917441546549321914516504576'))  
```

The flag is converted to an integer value and shifted 10,000 bits to the left
to give the last 175 decimal digits of the value. In other words, the purpose
of this problem is to restore the flag value from:

$$  
c=\text{flag}\cdot2^{10000}\bmod10^{175}  
$$

## Solution

At first you may try taking the inverse of $2^{10000}$ over $F_{10^{175}}$,
but that should be impossible because they are not coprime.

The correct way is, first think of

$$  
c=\text{flag}\cdot2^{10000}\bmod5^{175}  
$$

and, using Euler’s theorem, calculate:

$$  
\begin{aligned}  
(2^{10000})^{-1}\bmod5^{175}&=(2^{10000})^{\varphi(5^{175})-1}\\&=(2^{10000})^{5^{175}-5^{174}-1}  
\end{aligned}  
$$

and get the flag by:

$$  
\text{flag}=c\cdot(2^{10000})^{-1}\bmod5^{175}  
$$

Since ${256}^{50}<5^{175}$, this is the only value that can satisfy the
equation.

### Solver Script

```python  
c =
1002773875431658367671665822006771085816631054109509173556585546508965236428620487083647585179992085437922318783218149808537210712780660412301729655917441546549321914516504576  
mod = 5 ** 175  
phi = 5 ** 175 - 5 ** 174  
inv = pow(pow(2, 10000, mod), phi - 1, mod)  
print(((c * inv) % mod).to_bytes(50, byteorder='big'))  
```

The answer is `TSGCTF{0K4y_Y0U_are_r3aDy_t0_Go_aNd_dO_M0r3_CryPt}`.

## Alternative Solution #1 (by [@naan112358](https://twitter.com/naan112358))

Let's start with

$$  
c=\text{flag}\cdot2^{10000}\bmod5^{175}  
$$

for the previous solution.

By considering:

$$  
2x=\begin{cases}2x\qquad\ \ (2x<M)\\2x-M\ (2x\geq M)\end{cases}\bmod M  
$$

we can assume that the above case produces even number and the below case
produces odd number. So,

```python  
def divide_by_two(x):  
   if x % 2 == 0:  
       return x // 2  
   else:  
       return (x + mod) // 2  
```

simulates division by 2 over the given modulo.

We can repeat this 10000 times and get the flag.

### Solver Script

```python  
mod = 5 ** 175  
c =
1002773875431658367671665822006771085816631054109509173556585546508965236428620487083647585179992085437922318783218149808537210712780660412301729655917441546549321914516504576
% mod

def divide_by_two(x):  
   if x % 2 == 0:  
       return x // 2  
   else:  
       return (x + mod) // 2

for i in range(10000):  
   c = divide_by_two(c)

print(c.to_bytes(50, byteorder='big'))  
```

## Alternative Solution #2 (by [@satos___jp](https://twitter.com/satos___jp))

Now we put:

$$  
C=\text{flag}\cdot2^{10000}  
$$

Note that there's no modulo here.

On the other hand we know $c$, which is the last 175 digits of $C$, so we can
put:

$$  
C=c_0\cdot{10}^{175}+c  
$$

Now we want to calculate $c_0$ which makes the last 10000 digits of the binary
form of $C$ all zero.

Then consider $C'$, which can be obtained by replacing $c_0$ to
$c'_0=c_0+2^x$. Now we get:

$$  
\begin{aligned}  
C'&=c'_{0}\cdot10^{175}+c\\&=\left(c_{0}+2^{x}\right)\cdot10^{175}+c\\&=c_{0}\cdot10^{175}+c+2^{x}\cdot10^{175}\\&=C+5^{175}\cdot2^{x+175}  
\end{aligned}  
$$

And the last $x+175$ digits of the binary form of $C$ is unchanged.

So, by determining $c_0$ from the least significant bits, we can obtain $C$
such that all the last 10000bit is zero.

Flag can be obtained by right-shifting $C$ 10000bits.

### Solver Script

```python  
c =
1002773875431658367671665822006771085816631054109509173556585546508965236428620487083647585179992085437922318783218149808537210712780660412301729655917441546549321914516504576  
c0 = 0  
bit = 1  
mask = 1 << 175  
while '1' in bin(c0 * 10 ** 175 + c)[-10000:]:  
 if (c0 * 10 ** 175 + c) & mask != 0:  
   c0 += bit  
 bit <<= 1  
 mask <<= 1  
C = c0 * 10 ** 175 + c  
flag = (C >> 10000).to_bytes(50, byteorder='big')  
print(flag)  
```

Original writeup (https://hackmd.io/@hakatashi/HJJoxeAyD).