# S2DH Writeup

### RCTF 2022 - crypto 769 - 7 solves

> [下载附件](_media_file_task_2ca138ee-f38f-4783-ae50-537dc868006e.zip)

#### Analysis

After unzipping the attachment, we get [s2dh.ipynb](s2dh.ipynb) file.
Apparently, the challenge implements plain
[SIDH](https://en.wikipedia.org/wiki/Supersingular_isogeny_key_exchange)
protocol. Anyone who is unfamiliar with this ~broken~ protocol can first start
with this great article: [Supersingular isogeny key exchange  
for beginners](https://eprint.iacr.org/2019/1321.pdf). Simply speaking, SIDH
relies on the assumption that finding walks between supersingular elliptic
curve is hard.

For our profit, lets inspect the codeblocks one by one.

Define constants and check `p` is prime.

```python  
a = 43  
b = 26  
p = 2^a*3^b - 1  
assert p in Primes()  
```

Define supersingular elliptic curve `E: y ^ 2 = x ^ 3 + x` over `GF(p ^ 2)`.

```python  
K._= GF(p^2, modulus=x^2+1)  
E = EllipticCurve(K, [1, 0])  
```_

Generate public base point `Pa`, `Qa` for Alice, and `Pb`, `Qb` for Bob. Make
sure that the points are safe from [torsion point
attack](https://eprint.iacr.org/2022/654.pdf).

```python  
Pa = E(0)  
while (2^(a-1))*Pa == 0:  
   Pa = 3^b * E.random_point()  
Pa  
Qa = Pa  
while Pa.weil_pairing(Qa, 2^a)^(2^(a-1)) == 1:  
   Qa = 3^b * E.random_point()  
Qa  
Pb = E(0)  
while (3^(b-1))*Pb == 0:  
   Pb = 2^a * E.random_point()  
Pb  
Qb = Pb  
while Pb.weil_pairing(Qb, 3^b)^(3^(b-1)) == 1:  
   Qb = 2^a * E.random_point()  
Qb  
```

Generate Alice's secret key `Sa`, `Ta`, and Bob's secret key `Sb`, `Tb`.
Compute isogenies and make an exchange.

```python  
Sb = randint(0, 3^b-1)  
Tb = randint(0, 3^b-1)  
R = Sb * Pb + Tb * Qb  
psi = E.isogeny(R)  
Eb, psiPa, psiQa = psi.codomain(), psi(Pa), psi(Qa)  
Eb, psiPa, psiQa

Sa = randint(0, 2^a-1)  
Ta = randint(0, 2^a-1)  
R = Sa*Pa + Ta * Qa  
phi = E.isogeny(R)  
Ea, phiPb, phiQb = phi.codomain(), phi(Pb), phi(Qb)  
Ea, phiPb, phiQb  
```

Tip: when you run the upper code segment, computing isogeny will take forever.
To overcome this, supply `algorithm="factored"` parameter to `isogeny` method
to speed things up, like `E.isogeny(R, algorithm="factored")`.

Now bob can compute shared isogeny, and gain shared elliptic curve. The
[j-invariant](https://en.wikipedia.org/wiki/J-invariant) will be the final
shared secret.

```python  
J = Eb.isogeny(Sa*psiPa + Ta*psiQa,
algorithm='factored').codomain().j_invariant()  
```

Xor encrypt flag, using value of `J`. Our goal is to recover `J`.

```python  
flag = open("flag.txt","r").read()  
assert flag[:5] == "RCTF{" and flag[-1] == "}"  
flag = flag[5:-1]  
int.from_bytes(flag.encode()) ^^ ((int(J[1]) << 84) + int(J[0]))  
```

#### SIDH is broken in 2022 - Castryck-Decru Attack

Apply [Castryck-Decru Attack](https://eprint.iacr.org/2022/975), which is an
efficient key recovery attack on SIDH.
[issikebrokenyet.github.io](https://issikebrokenyet.github.io) shows the
overview of the impact of the attack. We even have a [sagemath implementation
of the attack](https://github.com/jack4818/Castryck-Decru-SageMath).

#### Change the starting curve

However we must modify the source code in order to apply to this challenge
because, the starting curve used in sagemath code has the form `E: y ^ 2 = x ^
3 + 6 * x ** 2 + x` over `GF(p ^ 2)`, which is different from problem setting.

According to the [original paper](https://eprint.iacr.org/2022/975), it says
the attack can be also applied to `E`. See section 3.1:

> `E_start: y ^ 2 = x ^ 3 + x`, we have the automorphism `i : (x, y) -> (−x,
> sqrt(y))` and we simply let `2i = [2] ◦ i`.

Therefore, we use automorphism to generate endomorphism `two_i`.

```python  
K._= GF(p^2, modulus=x^2+1)  
PR.<x> = PolynomialRing(K)  
# starting curve updated, not E_start = EllipticCurve(Fp2, [0,6,0,1,0])  
E = EllipticCurve(K, [1, 0])  
E.set_order((p+1)^2)_

phi = EllipticCurveIsogeny(E, x)  
E1728 = phi.codomain()

for iota in E1728.automorphisms():  
   P = E1728.random_point()  
   if iota(iota(P)) == -P:  
       two_i = phi.post_compose(iota).post_compose(phi.dual())  
       break  
```

Now apply `CastryckDecruAttack` method using `two_i` and recover `recovered`.

```python  
recovered = CastryckDecruAttack(E, Pa, Qa, Eb, psiPa, psiQa, two_i,
num_cores=num_cores)  
```

`recovered` satisfies the following equation:

```python  
Sa * Pa + Ta * Qa == Pa + recovered * Qa  
```

Therefore we finally evaluate shared secret `shared` using `recovered` by
computing j-invariant of codomain of isogeny.

```python  
shared = Ea.isogeny(phiPb + recovered * phiQb,
algorithm='factored').codomain().j_invariant()  
```

Xor to recover flag:

```python  
c = 243706092945144760206191226817331300960683091878992  
key = ((int(shared[1]) << 84) + int(shared[0]))  
flag = b"RCTF{" + long_to_bytes(c ^^ key) + b"}"  
```

We finally get flag:

```  
RCTF{SIDH_isBr0ken_in_2O22}  
```

Full exploit code: [solve.sage](solve.sage) requiring
[castryck_decru_shortcut.sage](castryck_decru_shortcut.sage.sage),
[helpers.py](helpers.py), [public_values_aux.py](public_values_aux.py),
[richelot_aux.sage](richelot_aux.sage), [speedup.sage](speedup.sage),
[uvtable.sage](uvtable.sage): from [github.com/jack4818/Castryck-Decru-
SageMath](https://github.com/jack4818/Castryck-Decru-SageMath)

Problem source: [s2dh.ipynb](s2dh.ipynb), converted to [s2dh.sage](s2dh.sage)  

Original writeup (https://github.com/pcw109550/write-
up/tree/master/2022/RCTF/S2DH).