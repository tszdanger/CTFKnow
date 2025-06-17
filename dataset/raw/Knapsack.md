https://meashiri.github.io/ctf-writeups/posts/202312-backdoorctf/#knapsack

TLDR: This a knapsack problem with 20 entries. The density was too high to use
LLL. So, I solved it using a "meet-in-the-middle" approach.

Original writeup (https://meashiri.github.io/ctf-
writeups/posts/202312-backdoorctf/#knapsack).This challenge generates a random list of integers $w_i$, one for each bit of
the flag $f_i$. To do so, first a random 8-bit prime number $r$ is generated.

The process is:  
* $w_0\in [1, 69]$  
* $w_i \in \Big (\sum_{j=0}^{i-1} w_j, r \cdot w_{i - 1}\Big ]$

Next, we let $q$ be the next prime after $r\cdot w_{n - 21}$.

Finally, set $b$ to be the array of $(r\cdot w_i)\bmod q$, $0\le i\le n - 1$
and $c$ to be the sum $\sum_{i=0}^{n-1} f_i\cdot b_i$. We are given $b$ and
$c$ and need to determine $f_i$.

To solve this, notice that the problem as given is the standard NP-hard
Knapsack problem. To solve this, note the following crucial property:

if the array of weights for knapsack satisfies the property that $w_i >
\sum_{j=0}^{i-1}w_j$, then Knapsack is solvable in linear time, by proceeding
greedily from the largest element and including it if it is smaller than the
target. Indeed, suppose not: we are trying to sum up to $V$ with our array
$W$. Suppose $w_{n-1} \le V$ and we do not include it. Then,
$\sum_{i=0}^{n-2}w_i < w_{n-1} \le V$, so we can never sum to the desired
value. So, we must include $w_{n-1}$. We can proceed down like this to find
that there is a unique decomposition.

The small issue here is that the last 21 elements of $b$ are not necessarily
increasing. To get around this, we try every possible subset of them and
proceed greedily on the rest. The flag has 207 bits, so this takes time
$\approx 2^{21}\cdot (207 - 21)$ which is pretty quick. Here's the code:

```  
from itertools import chain, combinations  
from tqdm import tqdm

def powerset(iterable):  
   "powerset([1,2,3]) --> () (1,) (2,) (3,) (1,2) (1,3) (2,3) (1,2,3)"  
   s = list(iterable)  
   return chain.from_iterable(combinations(s, r) for r in range(len(s)+1))

to_iter = range(len(b) - 21, len(b))  
ps = powerset(to_iter)

def greedy(ll, target):  
   out = set()  
   for i in range(len(ll) - 1, -1, -1):  
       elem = ll[i]  
       if elem <= target:  
           target -= elem  
           out.add(i)  
   return out, target

for comb in tqdm(ps):  
   target = c  
   out = set(comb)  
   for cc in out:  
       target -= b[cc]  
   if target < 0:  
       continue  
   nout, nt = greedy(b[:-21], target)  
   if nt != 0:  
       continue  
   ans = out.union(nout)  
   bm = int(''.join(['1' if i in ans else '0' for i in range(len(b))]), 2)  
   print(bm.to_bytes((len(b) + 7) // 8, 'big'))  
   break  
```

Running this gives `flag{b4d_r_4nd_q_1s_sc4ry}`.