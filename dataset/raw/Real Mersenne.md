# Real Mersenne

**Category**: crypto \  
**Solves**: 13 \  
**Points**: 949 \  
**Author**: deuterium

Do you believe in games of luck? I hope you make your guesses real or you'll
be  
floating around

```  
nc crypto.zh3r0.cf 4444  
```

Download - [real_mersenne.tar.gz](real_mersenne.tar.gz)

## Overview

All we have to do is guess the output of Python's `random.random()` function.  
The more accurate our guess is, the more points we get. We get the flag after  
`10 ** 6` points.

```python  
import random  
from secret import flag  
from fractions import Fraction

def score(a, b):  
   if abs(a - b) < 1 / 2 ** 10:  
       # capping score to 1024 so you dont get extra lucky  
       return Fraction(2 ** 10)  
   return Fraction(2 ** 53, int(2 ** 53 * a) - int(2 ** 53 * b))

total_score = 0  
for _ in range(2000):  
   try:  
       x = random.random()  
       y = float(input("enter your guess:\n"))  
       round_score = score(x, y)  
       total_score += float(round_score)  
       print("total score: {:0.2f}, round score: {}".format(total_score, round_score))  
       if total_score > 10 ** 6:  
           print(flag)  
           exit(0)  
   except:  
       print("Error, exiting")  
       exit(1)  
else:  
   print("Maybe better luck next time")  
```

## Solution

It's well-known that after 624 outputs from a Mersenne Twister, we can deduce  
its seed and predict any future outputs.

So our goal is:

1. Extract the actual bits that the MT outputs from the `round_score`, which is  
 a `Fraction`  
2. Solve for the seed  
3. Predict future outputs and get the flag

### Part 1: Extracting the bits

> Solved with @vishiswoz, who helped me sort out a bunch of mistakes in my
> code  
> (having teammates is great)

```c  
/*  
*...  
* In effect, `a` contains 27 random bits shifted left 26, and `b` fills in the  
* lower 26 bits of the 53-bit numerator.  
*/  
static PyObject *  
_random_Random_random_impl(RandomObject *self)  
/*[clinic end generated code: output=117ff99ee53d755c
input=afb2a59cbbb00349]*/  
{  
   uint32_t a=genrand_uint32(self)>>5, b=genrand_uint32(self)>>6;  
   return PyFloat_FromDouble((a*67108864.0+b)*(1.0/9007199254740992.0));  
}  
```

We can recover `a` and `b` just by shifting the bits:

```c  
#include <stdint.h>  
#include <assert.h>

int main()  
{  
 uint32_t a = 446374322 >> 5;  
 uint32_t b = 2269612274 >> 6;  
 double x = (a * 67108864.0 + b) * (1.0 / 9007199254740992.0);

 // We only know x. Goal is to recover a and b.  
 // Note: 9007199254740992 == 2 ** 53  
 // Note: 67108864 == 2 ** 26  
 uint64_t y = (uint64_t)(x * 9007199254740992.0);  
 assert(((uint64_t)a * 67108864 + b) == y);

 uint32_t a_recovered = y >> 26;  
 uint32_t b_recovered = y & 0x3ffffff; // y % (2 ** 26)  
 assert(a == a_recovered);  
 assert(b == b_recovered);

 return 0;  
}  
```

## Part 2: Solving for the seed

Now that we have the exact bits generated from the Mersenne Twister, we  
can give it to a Z3 solver to deduce the internal state.

I used this, which was well-written and easy to use:  
https://github.com/icemonster/symbolic_mersenne_cracker/

It was also designed to handle truncated outputs, which was exactly what we  
needed:  
```python  
ut = Untwister()

a, b = get_a_b_str(x)  
assert len(a) == 32  
assert len(b) == 32

# Just send stuff like "?11????0011?0110??01110????01???"  
# Where ? represents unknown bits  
ut.submit(a)  
ut.submit(b)  
```

## Part 3: Putting it together

After some testing, my script was able to solve the challenge locally in about  
10 seconds. Sometimes it would give `z3.z3types.Z3Exception: model is not  
available` for some reason, but I just re-ran it until it worked.

Unfortunately, running it remotely would take 20 minutes due to my slow
network  
connection. I could rent a VPS in India to send requests faster, but instead I  
just modified my script to send inputs and parse outputs in bulk.

Output (solve script in `solve.py`)  
```  
$ python3 solve.py REMOTE  
[x] Opening connection to crypto.zh3r0.cf on port 4444  
[x] Opening connection to crypto.zh3r0.cf on port 4444: Trying 34.93.202.214  
[+] Opening connection to crypto.zh3r0.cf on port 4444: Done  
100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████|
624/624 [00:03<00:00, 196.82it/s]  
Solving...  
...  
   b'enter your guess:\n'  
   b'total score: 992535.43, round score: 1024\n'  
   b'enter your guess:\n'  
   b'total score: 993559.43, round score: 1024\n'  
   b'enter your guess:\n'  
   b'total score: 994583.43, round score: 1024\n'  
   b'enter your guess:\n'  
   b'total score: 995607.43, round score: 1024\n'  
   b'enter your guess:\n'  
   b'total score: 996631.43, round score: 1024\n'  
   b'enter your guess:\n'  
   b'total score: 997655.43, round score: 1024\n'  
   b'enter your guess:\n'  
   b't'  
[DEBUG] Received 0xe5 bytes:  
   b'otal score: 998679.43, round score: 1024\n'  
   b'enter your guess:\n'  
   b'total score: 999703.43, round score: 1024\n'  
   b'enter your guess:\n'  
   b'total score: 1000727.43, round score: 1024\n'  
   b'zh3r0{r34l_m3n_d34l_w17h_m3r53nn3_w17h_r34l_v4lu3s}\n'  
   b'Error, exiting\n'  
```  

Original writeup
(https://github.com/qxxxb/ctf/tree/master/2021/zh3r0_ctf/real_mersenne).