## Robert  
### Challenge

> Oh, Robert, you can always handle everything!  
`nc 07.cr.yp.toc.tf 10101`

Upon connection, we see  
```  
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++  
+   hi all, all cryptographers know that fast calculation is not easy! +  
+   In each stage for given integer m, find number n such that:        +  
+   carmichael_lambda(n) = m, e.g. carmichael_lambda(2021) = 966       +  
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++  
| send an integer n such that carmichael_lambda(n) = 52:  
```  
where we can of course assume we will need to pass a certain number of rounds,
and the numbers will grow.

### Solution

Early on, we find [this math stackexchange
post](https://math.stackexchange.com/questions/41061/what-is-the-inverse-of-
the-carmichael-function), where we already make the comment

> looks hard

as, in general, this problem appears to be at least as hard as factoring $m$.  
We consider the possibility of factoring $m$ and applying a dynamic
programming based approach to group the prime factors of $m$ among the prime
factors of what would be $n$.  
In the end, this did not get implemented, as our intermediate attempts at
cheesy solutions converge towards a simpler approach that solves the
challenge.  
The first of these cheesy attempts comes from 3m4 -- while setting the basis
for further server communication scripts -- where we simply cross our fingers
and hope that $m + 1$ is prime, leading to $n = m + 1$ and $\lambda(n) = m$.  
While this clears up to 6 rounds on numerous occasions, it appears we'd need
to either hammer the server really hard, or find something better.  
Somewhere during this period of running our cheesy script full of hope, dd
suggests that we might be in a situations where $m$ is known to be derived
from a semiprime originally, i.e. $m = \lambda(pq)$.  
Alongside this idea, an attempted solution exploiting that property is
proposed, that unfortunately has several flaws and doesn't work against the
server.

Basing ourselves on this idea, we can however write the dumbest sage script
imaginable for this problem:  
- Let $D$ be the set of divisors of $m$  
- Enumerate all $(a, b) \in D^2$  
- If $a + 1$ is prime, $b + 1$ is prime, *and* $\mathsf{lcm}(a, b) = m$: reply with $n = (a + 1)(b + 1)$

Clearly, *if* our assumed property that $m = \lambda(pq)$ holds, and $m$ does
not grow too large to enumerate $D^2$, this should give us a correct solution.

Without all too much hope, we run the following sage script (with the `DEBUG`
command line argument for pwntools, so that we can observe the flag should it
get sent at the end):

```python  
import os  
os.environ["PWNLIB_NOTERM"] = "true"

from pwn import remote  
io = remote("07.cr.yp.toc.tf", 10101)

io.recvuntil(b"++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")  
io.recvuntil(b"++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

proof.arithmetic(False)  
def reverse_lambda(n):  
   for x in divisors(n):  
       for y in divisors(n):  
           if lcm(x, y) == n and is_prime(x + 1) and is_prime(y + 1):  
               return (x + 1) * (y + 1)  
  
try:  
   while True:  
       io.recvuntil(b"carmichael_lambda(n) = ")  
       integer = ZZ(io.recvuntil(b":")[:-1])  
       print(f"[*] Reversed: {integer} ->", end=" ", flush=True)  
       rev = reverse_lambda(integer)  
       print(f"{rev}")  
       io.sendline(str(rev).encode())  
except EOFError:  
   print("EOF")  
```

Against our initial expectations, we easily clear more than 10 rounds.  
Slowing down on an occasional $m$ that might have been hard to factor or have
a lot of different divisors, the script happily chugs along without the server
closing the connection on it, eventually getting the flag after 20 rounds.

##### Flag  
`CCTF{Carmichael_numbers_are_Fermat_pseudo_primes}`

Original writeup (https://blog.cryptohack.org/cryptoctf2021-hard#robert).