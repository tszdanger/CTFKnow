# dyrpto Writeup

### PlaidCTF 2020 - crypto 250 - 66 solves

#### Analysis

Textbook RSA with 4096 bit `N` and `e = 3` was given. The flag is stored at
`msg` element of protobuf. First serialize protobuf(having length of `mlen =
271`), add 24 byte padding and encrypt to get two ciphertext `ct1` and `ct2`.
Buffer's `id` element will be incremented from 0 to 1, making difference
between ciphertexts. The challenge setting/exploit code is based on this
[awesome writeup: Confidence CTF 2015 rsa1](http://mslc.ctf.su/wp/confidence-
ctf-2015-rsa1-crypto-400/).

#### Coppersmith's short pad attack

The 24 byte padding is too short, making system vulnerable to [short pad
attack](http://en.wikipedia.org/wiki/Coppersmith%27s_Attack#Coppersmith.E2.80.99s_Short_Pad_Attack).
Also I must consider the difference of serialized result occured by increment
of `id` element. By knowing the length of serialized output `mlen = 271`, I
generated dummy value to observe the difference. By studying [google protobuf
serialization algorithm](https://developers.google.com/protocol-
buffers/docs/encoding), I found out that original flag length is `266`.
Difference was found at the second byte of serialization result: `00` to `01`.

```  
0800128a024...  
0801128a024...  
```

I must consider the delta of plaintexts to apply short pad attack. The second
byte difference can be compensated by embedding information. Turn on `(2152 =
(271 - 3) * 8)` bit, and shift right `192` to consider padding. Therefore, use
value `1 << (2152 + 192)` to generate `g2` required for attack.

```python  
PRxy.<x,y> = PolynomialRing(Zmod(N))  
PRx.<xn> = PolynomialRing(Zmod(N))  
PRZZ.<xz,yz> = PolynomialRing(Zmod(N))

g1 = x ** e - ct1  
g2 = (x + y + (1 << (2152 + 192))) ** e - ct2

q1 = g1.change_ring(PRZZ)  
q2 = g2.change_ring(PRZZ)

h = q2.resultant(q1)  
h = h.univariate_polynomial()  
h = h.change_ring(PRx).subs(y=xn)  
h = h.monic()

kbits = 192  
beta = float(sqrt((kbits / N.nbits()) * (7 / 6)))  
epsilon = beta ** 2 / 7

set_verbose(2)  
roots = h.small_roots(X=2 ** kbits, beta=beta, epsilon=epsilon)  
set_verbose(0)  
diff = roots[0]

if diff >= (1 << kbits):  
   diff = N - diff  
   ct1, ct2 = ct2, ct1  
assert diff < (1 << kbits)  
```

I could calculate the delta `diff` of two random 24 byte paddings.

#### Franklin-Reiter related message attack

Now use `diff` to recover plaintext. Two plaintexts are highly related, and
suffices the criteria to apply [Franklin-Reiter related message
attack](http://en.wikipedia.org/wiki/Coppersmith%27s_Attack#Franklin-
Reiter_Related_Message_Attack).

```python  
x = PRx.gen()  
g1 = (x + (1 << (2152 + 192))) ** e - ct1  
g2 = (x + diff) ** e - ct2

# gcd  
while g2:  
   g1, g2 = g2, g1 % g2

g = g1.monic()  
assert g.degree() == 1

msg = -g[0]  
flag = l2b(msg)  
print(flag)  
```

Below is the output:

```python  
b'\x08\x00\x12\x8a\x02I never know what to put into these messages for CTF
crypto problems. You gotta pad the length but flags can only reasonably be so
long. Anyway, the flag should be coming any moment now... Ah, here it comes!
The flag is:
PCTF{w0w_such_p4d_v3ry_r34l1st1c_d0g3_crypt0}\xb4\xac\r\xc1\x1d:\xfd\xf0\x11W\x17\x9e\xb9"6\xfe\'\xe4\x0b\x82\xfc\xe9\xfa@'  
```

Dicard some strings to get the real flag:

```  
PCTF{w0w_such_p4d_v3ry_r34l1st1c_d0g3_crypt0}  
```

Orignal problem: [generate_problem.py](generate_problem.py),
[output.txt](output.txt)

Exploit code: [solve.sage](solve.sage) requiring [output.py](output.py)  

Original writeup (https://github.com/pcw109550/write-
up/tree/master/2020/PlaidCTF/dyrpto).