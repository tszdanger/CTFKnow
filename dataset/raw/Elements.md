Elements  
============

TL;DR: WolframAlpha -> [CMA-ES](http://cma.gforge.inria.fr/) -> Bruteforce
lower bits

------------

The program receives an input as following:  
```  
flag{xxxxxxxxxxxx-xxxxxxxxxxxx-xxxxxxxxxxxx}  
```  
where each of the `xxxxxxxxxxxx` are hexadecimal numbers that are casted as
floating-point numbers. The input restrictions are as follows:

1. The first number is `391BC2164F0A`  
2. The three numbers must be side lengths of a triangle, with the last number being the longest side  
3. The inradius of the triangle must be `1.940035480806554e13` with error range of `1e-5`  
4. The circumradius of the triangle must be `4.777053952827391e13` with error range of `1e-5`

Our team first used WolframAlpha to find an approximate value for the
remaining two sides. This yielded us a solution with error about `1e10`, which
is quite a large error. One of our team member managed to optimize the
circumradius to an error range of `1e-3` through binary searching by hand, but
the inradius was still huge.

It occured to me that finding the appropriate side length can be considered as
an **optimization problem**, where the **function we wish to minimize is the
sum of absolute error of both the inradius and circumradius**. More
specifically, we have floating point error in calculation, so the function
must also be considered **noisy**.

As I had [good experiences](https://github.com/leesh3288/Tetris) with such
optimization problems with CMA-ES, I proceeded to try it out. The below code
uses a [python implementation of CMA-ES](https://github.com/CMA-ES/pycma).

```python  
import cma  
from math import sqrt

ks = 0x391BC2164F0A  
kr = 1.940035480806554e13  
kR = 4.777053952827391e13

def radiusFit(s):  
   v19 = ks*ks + s[0]*s[0] - s[1]*s[1]  
   S_in = 4*ks*ks*s[0]*s[0] - v19*v19  
   if S_in < 0:  
       return float('inf')  
   S = sqrt(S_in) / 4  
   cr = 2*S / (ks + s[0] + s[1])  
   cR = (ks*s[0]*s[1]) / (4*S)  
   distr = (kr - cr)  
   distR = (kR - cR)  
   print(distr, distR)  
   return abs(distr) + abs(distR)

es = cma.CMAEvolutionStrategy([70789268583970.951, 95523433899867.88], 0.2)  
es.optimize(radiusFit, min_iterations=500)  
print(es.result_pretty())  
```

The result immediately yielded a minimizing solution that was only offset from
the answer by `1`. I found the final answer by brute-forcing `[-0x100, 0x100]`
range of both unknown sides.

```python  
#!/usr/bin/python3.6

import subprocess  
from multiprocessing.dummy import Pool as ThreadPool

d = [0x391BC2164F0A, 0x4064e4798768, 0x56e0de138176]

DELTARANGE = 0x100

def run(d1):  
   print("solving d1 = {:x}".format(d1))  
   for d2 in range(-DELTARANGE, DELTARANGE + 1):  
       payload = "flag{" + "{:012x}-{:012x}-{:012x}".format(d[0], d[1] + d1, d[2] + d2) + "}\n"  
       try:  
           s = subprocess.check_output("./Elements", input=bytes(payload, 'ascii'))  
           if len(s) != 0:  
               print(payload)  
               return payload  
       except subprocess.CalledProcessError as e:  
           pass  
   return ""

pool = ThreadPool(8)  
results = pool.map(run, list(range(-DELTARANGE, DELTARANGE + 1)))  
pool.close()  
pool.join()  
print(''.join(results))  
```

**FLAG: `flag{391bc2164f0a-4064e4798769-56e0de138176}`**

Original writeup
(https://github.com/leesh3288/CTF/blob/master/2019/0CTF_Quals/Elements/elements_writeup.md).