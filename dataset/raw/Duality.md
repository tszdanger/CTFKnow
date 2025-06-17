# TeamItalyCTF 2023

## [crypto] Duality (2 solves)

## Overview

In this challenge we are given 300 tuples, consisting of values that belong to
two different distributions. Either the value is sampled uniformly at random
from the range $[0, 2^{436}]$, or it is of the form $a_{i}p+b_{i}$, with $p$
being a prime number. An RNG that is a combination of a LCG and a LFSR is used
to decide from which distribution each tuple comes from. Our goal is to
retrieve the RNG seed and use it to decrypt the flag.

## Solution

We can see this as an instance of a decisional version of the approximate gcd
problem. Heuristically, we notice that, to recover $p$ for parameters similar
to the challenge ones, one needs 4 samples of the correct form (i.e.
$a_{i}p+b_{i}$). Iterating over the possible combinations, we can
probabilistically recover $p$ and learn a shuffling of the output of the PRNG.

One can then notice that the LCG in the PRNG is heavily biased to 1, so the
PRNG almost fully behaves like an LFSR, with an error term with a really low
probability of showing up.

We get rid of the shuffling by summing the consecutive values of the recovered
boolean vectors via the AGCD, learning the sum of 12 consecutive clocks of the
PRNG for each sample that contains enough information to solve the AGCD
problem (e.g. with more than 4 elements being of the form $a_{i}p+b_{i}$).

We now have an instance of LPN, with relatively low error. We also have a
relatively low number of samples, which hints at the fact that the ISD
approach is faster than the BKW approach. We can hence use ISD to recover the
key, and then decrypt the flag.

## Exploit

```python  
from pwn import *  
from sage.all import *  
import itertools  
from Crypto.Util.number import *  
from Crypto.Cipher import AES  
import hashlib  
import random

f = open('output.txt', 'r')  
leaks = [eval(f.readline()) for i in range(300)]  
enc = f.readline().strip()

nsamples = 4  
nbitsq = 180  
nbitsr = 180

wt = [2^(nbitsq + 1)] + [2^(nbitsr + nbitsq) for j in range(nsamples-1)]  
wt = [max(wt)/x for x in wt]  
W = diagonal_matrix(wt)

class symLFSR:  
   def __init__(self, seed):  
       self.state = list(seed)  
       self.taps = [0, 16, 32, 64, 96, 127]

   def get(self):  
       next_bit = 0  
       for tap in self.taps:  
           next_bit += self.state[tap]  
       self.state = self.state[1:] + [next_bit]  
       return next_bit

def agcd(leak):  
  
   for x in itertools.combinations(range(len(leak)), nsamples):  
       f = 0  
       vals = [leak[i] for i in x]  
       M = diagonal_matrix([-vals[0] for j in range(nsamples)])  
       M[0, 0] = 1  
       for j in range(1, nsamples):  
           M[0, j] = vals[j]

       M *= W  
       M = M.dense_matrix().LLL()  
       M /= W  
       row0 = M[0]  
       row0 = row0 * sign(row0[0])  
       t1 = int(row0[0])  
       for j in range(1, 2^5):  
           qg = t1*j  
           rg = int(vals[0] % qg)  
           pg = (vals[0] - rg) // qg

           if isPrime(int(pg)) and int(pg).bit_length() == 256 and int(rg).bit_length() <= nbitsr and int(qg).bit_length() <= nbitsq:  
               f = 1  
               break  
       if f:  
           print(f'found the correct value of p')  
           p = pg  
           break

   if not f:  
       print('did not find the correct value of p')  
       return -1

   bs = []  
   for j in range(len(leak)):  
       ri, qi = leak[j] % p, leak[j] // p  
       if ri.bit_length() <= nbitsr and qi.bit_length() <= nbitsq:  
           bs.append(1)  
       else:  
           bs.append(0)

   return bs

def compute_SD(vectors, n, k, w, s):  
   #vectors is an array of n elements in GF(2)^(n-k), casted as python lists
of integers  
   #H is the (n-k, n) matrix obtained by considering vectors as the columns of
said matrix

   n_k = n-k  
   indices = [j for j in range(n)]  
   found = 0  
   gf2_id = identity_matrix(n_k).change_ring(GF(2))

   for trial in range(10000):  
       random.shuffle(indices)  
       rows = [vectors[indices[i]] for i in range(n)]  
       H = Matrix(GF(2), rows).T  
       tmp_l = H.matrix_from_columns([i for i in range(n-k)])

       if (det(tmp_l) != 0):  
           #found  
           found = 1  
           break

   if found == 0:  
       #somehow there are linear dependencies if this gets triggered, pls throw them away  
       raise Exception(f"Could not find {n_k} linearly independent vectors")  
  
   assert(tmp_l.rank() == tmp_l.nrows() == tmp_l.ncols())

   #compute the permutation matrix bringing H into systematic form  
   P = gf2_id / tmp_l  
   r_mat = P*H  
   rhs = P*s

   M_T = r_mat.matrix_from_columns([i + n - k for i in range(k)]).T  
   f = open("SD_find", "w")  
   f.write(f"# n\n{n}\n")  
   f.write(f"# k\n{k}\n")  
   f.write("# seed\n0\n")  
   f.write(f"# w\n{w}\n")  
   f.write("# H^transpose (each line corresponds to column of H, the identity
part is omitted)\n")  
   for row in M_T:  
       f.write("".join(list(map(str, row))) + "\n")

   f.write("# syndrome to compute\n")  
   f.write("".join(list(map(str,rhs))))  
   f.close()  
   p = process(["/home/genni/Sources/isd/build/isd","8", "SD", "SD_find"])  
   print(p.recvlines(2))

   for j in range(4):  
       try:  
           t = p.recvline(False).decode()  
           print(t)  
           out = list(map(int, t))  
           break  
       except Exception as e:  
           print(e)  
           continue  
   p.close()  
   assert(H * vector(GF(2), out) == s)  
  
   x = [0 for _ in range(n)]  
   for i, y in enumerate(out):  
       if y == 1:  
           x[indices[i]] = 1

   assert(Matrix(GF(2), vectors).T * vector(GF(2), x) == s)  
   return vector(GF(2), x)

bs = []  
for i, leak in enumerate(leaks):  
   print(f'\x1b[32mRound number {i}\x1b[0m')  
   out = agcd(leak)  
   if out == -1:  
       bs.append(-1)  
       continue  
   s = int(sum(out))  
   bs.append(s)

P = PolynomialRing(GF(2), [f'x_{i}' for i in range(128)])  
coefs = P.gens()

S = symLFSR(coefs)  
eqs = []  
rhs = []  
for s in bs:  
   tt = sum([S.get() for _ in range(12)])  
   if s == -1:  
       continue  
   eqs.append(tt)  
   rhs.append(s)

y = vector(rhs)  
A, _= Sequence(eqs).coefficient_matrix()  
A = A.dense_matrix()

B = A.left_kernel().basis_matrix().dense_matrix()  
rr = B * y  
vectors = [x for x in B.T]  
n = len(vectors)  
k = n - len(vectors[0])  
w = 36  
e = compute_SD(vectors, n, k, w, rr)  
print(sum(e.change_ring(ZZ)))  
x = A.solve_right(y + e)  
x = list(x.change_ring(ZZ))  
key = sum([x[127 - i]*2^i for i in range(128)])  
pt = AES.new(hashlib.sha256(long_to_bytes(key)).digest(),
AES.MODE_ECB).decrypt(bytes.fromhex(enc))  
print(pt)  
```

Original writeup
(https://github.com/TeamItaly/TeamItalyCTF-2023/blob/master/Duality/README.md).