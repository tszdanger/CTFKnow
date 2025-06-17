# Projective Signature

## Challenge  
```  
I'm spending a lot of time on this board that computes ECDSA signatures on
secp256k1, with an unknown private key.

Using my favorite oscilloscope, I was able to capture what I think is the
computation of this signature.

The public key, written in base 10 is
```(94443785317487831642935972645202783659685599642218408192269455854005741686810,  
78142542704322095768523419012865788964201745299563420996262654666896320550926)```.

I was able to get a lot of signatures of the same message, and to record a
power trace each time. Using signature verification, I was able to also
retrieve the resulting curve point P each time.

The scalar multiplication algorithm is probably performed left to right, bit
by bit, as a sequence of double and add operations.

My reasonable assumption is that the developers used the usual formulas:
[point addition](https://www.hyperelliptic.org/EFD/g1p/auto-shortw-
jacobian.html#addition-add-2007-bl) and [point
doubling](https://www.hyperelliptic.org/EFD/g1p/auto-shortw-
jacobian.html#doubling-dbl-2007-bl)

After some time analyzing the traces, I have come to the conclusion that the
implementation is really well protected, as I couldn't find any meaningful
signal relative to these operations.

However, a small window of several thousands of points seems to be
exploitable. This leakage occurs right after the numerous similar patterns of
the scalar multiplication, and they should hence correspond to the conversion
of the point from a projective coordinates representation to an affine
coordinates representation.

Once again, I have a reasonable assumption that the algorithm used to perform
the inversion of the Z coordinate is the classic extended binary GCD, that is
described for example in Algorithm 1.
[here](https://eprint.iacr.org/2020/972.pdf).

I don't have any idea what to do of all this, but I really need this private
key!

I extracted from my traces the relevant window. You can download the resulting
campaign as an hdf5 file [here](https://cdn.donjon-ctf.io/all_signatures.h5).

Can you help me retrieve the private key?  
```

## Disclaimer  
Let's not pretend I knew what to do from the beginning :sweat_smile: I
docilely followed the methodology given in the following paper :  
https://tches.iacr.org/index.php/TCHES/article/view/8596/8163. Do not hesitate
to check the parts `2`, `3` and `6.3`, which correspond more or less to the
challenge!

## Traces analysis  
First, let's look at one of the given traces to try and link together the
concepts described in the paper, the given scenario and the data.

```python  
#!/usr/bin/python3  
import h5py  
import numpy as np  
from matplotlib import pyplot as plt  
f = h5py.File('all_signatures.h5', 'r')  
leakages = f['leakages']  
values = f['values']  
plt.plot(leakages[1337])  
plt.show()  
```  
![](./imgs/graph0.png "One trace from the dataset")

It seems that structured data is present in each trace, conveniently inserted
between 2 small ranges of 50 data points staying at a low level (circled in
red in the graph above).

### Aligning the traces  
Unfortunately, the interesting parts of each trace do not start at the same
offset, and are not the same length. But the small ranges previously mentioned
(around 50 points averaging the value 48 with a small standard deviation) can
be detected automatically. For that, we compute a "sliding" average on a
window of 50 points, and look for peaks.

```python  
conv = np.convolve(leak, np.ones((N,))/N, mode='valid')  
plt.plot(conv)  
plt.show()  
```  
![](./imgs/graph1.png "Sliding average")

We define some empirically defined thresholds that seem to hold for all traces
to precisely detect these patterns:  
```python  
conv = np.convolve(leak, np.ones((N,))/N, mode='valid')  
start = np.where(conv < 50)[0][0]  
leak = np.roll(leak, -start)  
while leak[N]<70.0:  
   leak = np.roll(leak, -1)  
leak = np.roll(leak, -50)  
plt.plot(leak)  
plt.show()  
```

![](./imgs/graph2.png "Aligned trace")

This way, the traces are aligned, we can start analyzing them properly.

### Normalizing levels  
Looking at the first points of an aligned trace, we can easily notice that the
power values are distributed between 4 levels :

![](./imgs/graph3.png "4 visible levels")

As before, we define 3 empirically-verified thresholds to separate the data
between 4 fixed levels, in order to easily look for patterns later.

```python  
v0,v1,v2,v3 = range(1,5)  
v0_indices = np.where(leak < 68)  
v0v1_indices = np.where(leak < 108)  
v0v1v2_indices = np.where(leak < 148)  
leak[:] = v3  
leak[v0v1v2_indices] = v2  
leak[v0v1_indices] = v1  
leak[v0_indices] = v0  
plt.plot(leak)  
plt.show()  
```

![](./imgs/graph4.png "Normalized trace")

This already looks better.

*N.B.: the soundness of this approach is debatable; it might not work with "real" traces. But with these simulated traces, it worked like a charm.*

### Defining patterns

Looking at the graph more closely, we can define 3 patterns :  
```python  
pattern_A = np.array([v2]*4 + [v0] + [v1]*2 + [v2]*4 + [v3]*10,
dtype=np.uint8)  
pattern_B = np.array([v2]*4 +        [v1]*2 + [v2]*4 + [v3]*10,
dtype=np.uint8)  
pattern_C = np.array(                [v1]*2 +          [v3]*10,
dtype=np.uint8)  
```

Every data point from the "interesting" part of each trace belongs to a
pattern, which seems to validate the approach.

![](./imgs/graph5.png "Colored patterns")

### Extracting values from traces

Given the information given in the challenge, the algorithm corresponding to
the traces is the "classic" Extended Binary GCD  
:

![](./imgs/alg0.png "Algorithm corresponding to the traces")

We can notice two important facts:  
* There are exactly 3 possible paths inside the loop :  
 * We have identified 3 patterns in our traces  
* The number of loop iteration is variable (depends on the inverted value `a`)  
 * Interesting parts of our trace vary in length

So each pattern corresponds to an execution path in the loop. Matching
patterns and paths is quite easy :  
* As `y < m`, the first iteration can never take the path formed by lines `9` and `10` only.  
 * All traces start by `pattern_A` or `pattern_C`: so `pattern_B` corresponds to the path formed by lines `9` and `10`  
* `pattern_B`'s values are a subset of `pattern_A`'s values, as the path formed by lines `9` and `10` is included in the path formed by lines `8`, `9` and `10`  
 * So `pattern_A` corresponds to the path formed by lines  `8`, `9` and `10`  
* By elimination, `pattern_C` corresponds to the path formed by lines  `4` and `5`

Last observation, at the end of the algorithm, we know that `a = 0` (stop
condition of the loop) and that `b = gcd(y, m) = 1` (because `m` is prime, see
later). With these pieces of information, we can easily inverse the execution
of the algorithm and recover the inverted value `y` from a known sequence of
patterns.

```python  
def inv_gcd_from_trace(trace, m):  
   a = 0  
   b = 1  
   for ch in trace[::-1]:  
       if ch == "A":  
           a = (a * 2) + b  
           a, b = b, a  
       elif ch == "B":  
           a = (a * 2) + b  
       elif ch == "C":  
           a *= 2  
       else:  
           assert False  
   return a  
```

This is implemented in `first__extract_Z.py`.

### Remind me, why have we done that ?  
As a reminder, the ECDSA signature algorithm is the following:

![](./imgs/alg1.png "ECDSA signature algorithm")

The point multiplication at line 3 is performed using the famous double-and-
add algorithm:

![](./imgs/alg2.png "double-and-add algorithm")

For performance reasons, and as stated in the challenge information, the `R`
point is represented in the Jacobian coordinate system during the scalar-
multiplication, i.e. are given three coordinates : `(x * Z**2, y * Z**3, Z)`,
with `(x,y)` being the point coordinates in the affine coordinate system.

In order to get back affine coordinate (`(X / Z**2, Y / Z**3)`, with `(X,Y,Z)`
the point in Jacobian coordinates), an inversion of `Z` modulo `p` (the prime
of the curve's field) must be done: this is what has been captured.

In conclusion, at this point, we are able to compute the `Z` coordinate of the
`R` point computed at line 3 of the ECDSA signature algorithm. This will allow
us to retrieve information about some bits of the `k` used in the scalar
multiplication.

## Extract bits on `k`

Now that we have the `Z` coordinate of the `R` point at the end of the double-
and-add algorithm, let's try to infer information on the scalar `k`.

### "Double" algorithm

Given the information in the challenge, we can first take a look at the
algorithm doubling a point represented in the Jacobian coordinate system:

![](./imgs/alg4.png "double algorithm in Jacobian system")

`(X1, Y1, Z1)` being the coordinates of the point that is doubled and `(X3,
Y3, Z3)` the resulting point.

As we know the value `Z` at the end of the double-and-add algorithm, we try to
express `Z1` (the value before the double operation) as a function of `Z3`,
expressing `X1` and `Y1` (Jacobian coordinates) as functions of the affine
coordinates `(x1, y1)`:  
```  
Z3 = (Y1 + Z1)**2 - YY - ZZ  
Z3 = (Y1**2 + 2 * Y1 * Z1 + Z1**2) - Y1**2 - Z1**2  
Z3 = 2 * Y1 * Z1  
Z3 = 2 * (y1 * Z1**3) * Z1  
Z3 = 2 * y1 * Z1**4  
Z1 = fourth_root(Z3 / (2 * y1))  
```

Let's denote by `Z_i` the `Z` coordinate of the `R_i` point after loop
iteration `i` in the double-and-add algorithm : we have then the relation
`Z_{i+1} = fourth_root(Z_i / (2 * y_i))` (and let's not forget that iteration
`i+1` comes **before** iteration `i` in the double-and-add algorithm).

If `k_i = 0`, then `fourth_root(Z_i / (2 * y_i))` must have a solution. By
logical equivalence, if `fourth_root(Zi / (2 * y_i))` does not have a
solution, then `k_i = 1`.

*N.B. : the term `y_i` the equations above corresponds to the affine coordinate of `R_i`. The data provided by the challenge contains the coordinates of `R_0 = kG` for each signature: we will be able to keep track of the affine coordinates of `R_i` in our approach.*

### "Add" algorithm

We do the same deductions for the "add" algorithm, represented bellow:

![](./imgs/alg3.png "add algorithm in Jacobian system")

`(X1, Y1, Z1)` and `(X2, Y2, Z2)` being the coordinates of the points that are
added together, and `(X3, Y3, Z3)` the resulting point.

```  
Z3 = ((Z1 + Z2)**2 - Z1Z1 - Z2Z2) *  H  
Z3 = ((Z1**2 + 2 * Z1 * Z2 + Z2**2) - Z1**2 - Z2**2) *  (U2 - U1)  
Z3 = (2 * Z1 * Z2) *  (X2 * Z1Z1 - X1 * Z2Z2)  
Z3 = (2 * Z1 * Z2) *  (x2 * Z2**2 * Z1**2 - x1 * Z1**2 * Z2**2)  
Z3 = 2 * (Z1 * Z2)**3 *  (x2 - x1)  
```

Reading the ECDSA signature algorithm, we note that the second point in the
addition is always `G` (the generator of the curve `secp256k1`), and since it
is constant, we can safely assume its Jacobian coordinates are simply `(x_G,
y_G, 1)` (*i.e.* `Z_G = 1`).

Let's denote by `T_i` the point `R_i` before the addition and after the
doubling in the loop of the double-and-add algorithm. We express `Z_{T_i}` as
a function of `Z_i` using the equation previously derived :

```  
Z_i = 2 * (Z_{T_i} * Z_G)**3 *  (x_G - x_T)  
Z_i = 2 * Z_{T_i}**3 *  (x_G - x-T)  
Z_{T_i} = cube_root(Z_i / (2 * (x_G - x_T)))  
```

Once again, if `k_i = 1`, then `cube_root(Z_i / (2 * (x_G - x_T)))` must have
a solution. By logical equivalence, if `cube_root(Z_i / (2 * (x_G - x_T)))`
does not have a solution, then `k_i = 0`.

*N.B. : for those who eventually followed a bit too much the paper mentionned at the start of the write-up, here's a gotcha: the paper tells us to try and compute `cube_root(Z_i / (x_G - x_T))` (not `cube_root(Z_i / (2 * (x_G - x_T)))`), because the add algorithm in Jacobian coordinates is implemented a slightly different way on their target.*

### Bits extraction  
For each `Z_0` extracted in the power trace, we can try and find solutions for
`cube_root(Z_0 / (2 * (x_G - x-T)))` and `fourth_root(Z_0 / (2 * y_0))`. If
one of them is impossible, we have successfully determined the bit `k_0`, and
thus are able to compute `R_1` by computing `R_1 = R_0 / 2` if `k_0 = 0`, or
`R_1 = (R_0 - G) / 2` if `k_0 = 1`.

If both equations bear solutions, we can even explore the 2 possibilities
hoping some "dead path" appear later (i.e. both `cube_root(Z_i / (2 * (x_G -
x-T)))` and `fourth_root(Z_i / (2 * y_i))` have no solutions) allowing us to
backtrack. This has been (no so elegantly) implemented in the script
`second__recover_nonces_bits.py` (requires Sage).

## Find the private key

### Strategies to get the key  
*This part well described in section 6.3 of the paper mentioned in the start of this write-up; you really should read it instead of what follows, which is a crude digest.*

We have now recovered a few bits of the secret nonce `k` used in thousands of
ECDSA signatures. We can now recover the private key `alpha` used in each
signature equation, solving an instance of the *Hidden Number Problem*.

All in all, we define the variables `c_i` as the low significant bits leaked
in the previous step (with `i` in `[0;100000[`, one for each leak) and `l_i`
the number of leaked bits in `c_i`.  
We define `a_i` as ![](./imgs/formula4.png "a_i formula"), `t_i` and `u_i` as
![](./imgs/formula3.png "t_i and _u_i formulas"), and `v_i` as
![](./imgs/formula5.png "v_i formula").

With these scalars, we define the vectors `x`, `y` and `u` as
![](./imgs/formula6.png "x, y and u vectors").

Finally, the matrix `B` is defined as follows :

![](./imgs/formula1.png "B")

The paper shows that solving the *Closest Vector Problem* expressed in
![](./imgs/formula7.png "CVP") (knowing `B` and `u`) yields `x` and hence the
private key `alpha` (as its last coordinate).

Moreover, the paper also states that solving the *Shortest Vector Problem* for
the lattice generated by the rows of the following `B_hat` matrix can also
yield `alpha`.

![](./imgs/formula2.png "B hat")

Once reduced, the lattice may contain the basis vector `(y, -n)`, will holds
`alpha` as its penultimate coordinate.

### Implementation  
We implemented the second strategy (solving the `SVP` problem). Our goal is to
keep the dimension of `B_hat` as low as possible (for the lattice reduction to
be quick), but it should contain enough information to be able to compute the
solution with a reasonable probability.

In order to be efficient, we only keep leaks that contains strictly more than
5 bits (we have around 1150 of them in our sample).

Also, instead of using all our samples at once, we will select random samples
of a given size to construct the `B_hat` matrix. The paper states that since
the private key is 256 bits, we should need at least 42 leaks of size 6 (since
256 / 6 = 42). We thus start with a batch size of 42, try the attack a few
times, and if it does not yield the key, increase a little the batch size.

```python  
import random  
sample_size = 256 // 6  
nb_tries = 0  
while True:  
   print(f"############# RANDOM BATCH of size {sample_size} ############## ")  
   indices = random.sample(range(len(u)), sample_size)  
   u_i, t_i, l_i = list(), list(), list()  
   for i in indices:  
       u_i.append(u[i])  
       t_i.append(t[i])  
       l_i.append(l[i])  
   flag = attack(u_i, t_i, l_i)  
   if flag is not None:  
       print(f"FLAG is : {flag}")  
       break  
   nb_tries += 1  
   if nb_tries == 5:  
       nb_tries = 0  
       sample_size += 5  
   print()

```

The attack eventually works, with a batch size of around 70 :

```  
$ sage last__lattice_based_attack.py  
############# RANDOM BATCH of size 42 ##############  
0 candidates for private key found  
       but no key found...

############# RANDOM BATCH of size 42 ##############  
0 candidates for private key found  
       but no key found...  
[...]  
############# RANDOM BATCH of size 72 ##############  
20 candidates for private key found  
       but no key found...

############# RANDOM BATCH of size 72 ##############  
6 candidates for private key found  
FLAG is : b'CTF{0n(3464!n1|=a|_|_1nToMy|*|?0j3ct1v3w4y5....}'  
```  

Original writeup (https://github.com/Team-Izy/Donjon-
CTF-2020-writeups/tree/main/side-channel/projective-signature).