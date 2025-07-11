# SSSP - Cryptography - 400 points - 4 teams solved

> P = NP?  
>  
> nc 54.92.67.18 50216  
>  
>
> [sssp-58ab171bacc3c82fa6704228fb9f1d78.cpp](./sssp-58ab171bacc3c82fa6704228fb9f1d78.cpp)

This challenge is quite similar to a [Tokyo Westerns 2017 CTF
problem](https://github.com/ymgve/ctf-
writeups/tree/master/tokyowesterns2017/ppc-backpackers_problem). We are tasked
with solving 30 different [Subset
sum](https://en.wikipedia.org/wiki/Subset_sum_problem) problems, from 11 to
127 integers in size, and the problems are generated with the standard
[Mersenne Twister](https://en.wikipedia.org/wiki/Mersenne_Twister) variant
MT19937. There are a few key differences:

* Instead of the MT being initialized by a single 32bit seed, the whole 624-integer initial state is initialized from a secure RNG source  
* The number of bits in the integers of a problem set varies from 24 to 120 bits  
* The list of integers in a problem set isn't sorted, so we know the exact order of the partial PRNG info we receive  
  
Since there isn't a single seed this time, we decided to try a different
approach - predict the PRNG state increasingly from the integers of the
problem sets, hopefully recovering the full state before the size of the
problems become too large.

Instead of the normal 624 integer state, we model the Twister as an unbounded
length array, and each entry is an array containing all possible integers at
that point, or None if the number of possible integers is too large. For
example, if we know 24 of the 32 bits generated by the PRNG at one point, we
know that the state value at that point could only be one of 256 different
ones.

We then use the fact that `state[x]` is generated on the basis of
`state[x-624]`, `state[x-623]`, and `state[x-227]`. `state[x-624]` only
contributes a single bit, so worst case it has two possible values. For the
other integers, if we know the possible candidates for two out of three in
`(state[x-623], state[x-227], state[x])`, we can compute an array of possible
candidates for third one. If this narrows down the number of possible
candidates from what we had before, we repeat this process for other values of
`x` until we don't get any better constraints. We also add some sane limits
for the number of states generated and the depth of iteration to stop the
process from using too much time.

Until our predictor has "warmed up", we have to solve the Subset sum problems
normally. We use the same solver as last time, though we really should have
used LLL or something faster than Python. We did get a speed boost from using
[pypy](https://pypy.org/), though. After the first few problems, our predictor
starts generating results, and we can eliminate some of the values from the
problem set.

We encountered a "hump" with problem 14, where our predictor manages to reduce
the problem size from 63 numbers to 50, but this is still too much for our
solver algorithm to solve within the five second time limit. Instead of
searching for another more optimized algorithm, we decided to just chop off
the last 7 numbers, reducing the problem size to 43. This means that on
average, our solver will fail to find a solution 127 out of 128 times, but by
simply running the program enough times, we eventually will get a solution and
can continue. After problem 14 it gets easier, and at problem 20 the full PRNG
state is known, and we don't have to solve anything at all. We finally get the
flag, `hitcon{SSSP = Silly Shik's Superultrafrostified Present}`

Post contest, we realized that there is no randomness in which bits of the
PRNG state gets leaked, so in theory we could have done an in-depth analyzis
with for example [z3](https://github.com/Z3Prover/z3) offline, then used the
results to fill in the bits quickly. This might have reduced the problem sizes
even further, and we might have avoided the repeated executions of the script.  

Original writeup (https://github.com/ymgve/ctf-
writeups/tree/master/hitcon2017quals/crypto-sssp).