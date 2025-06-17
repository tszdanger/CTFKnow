# Baby crypto revisited Writeup

### LINE CTF 2022 - crypto 138 - 48 solves

> Last time, our side-channel attack was quite easy. But our victim found out
> about our sneaky attack and increased the size of nonce. Fortunately, we
> could still capture the first half of the nonce, which is 64-bit this time.
> Now please help us to find out the encryption key again. The victim is using
> the secp160r1 curve. The following is the captured data: r, s, k, and hash
> respectively. Flag is LINECTF{<encryption key>}, e.g. LINECTF{0x1234}

>
> [Babycrypto_revisited_b1f108dea290b83253b80443260b12c3cadc0ed7.txt](Babycrypto_revisited_b1f108dea290b83253b80443260b12c3cadc0ed7.txt)

#### Analysis

ECDSA signature pair `r`, `s` with partial nonce `k_` and message hash `h` are
given. There are `num_samples = 100` pairs given. According to the
description, nonce size is 128 bits, but we know the half of it. Curve order
size of secp160r1 is 160 bits, so `160 - 64 = 96` bit is known. Our goal is to
recover the private key `d`.

### Reduction: Biased Nonce Attack

Because we know the MSBs of `k`, we can generate new signature/message pairs
which their MSBs are fixed.

Let `k = k_ + a`, where `a` is 64 bits. `k` and `k_` are 128 bit size each. We
can make signature `r_new`, `s_new` which are generated using nonce `a` with
hash `h_new` using `r`, `s`, `h`, `k_`. How?

```python  
r     = (k * G).x()  
# k * G can be recovered although we do not know k, by using r which is x
coord of EC  
r_new = (a * G).x() = (k * G - k_ * G).x()  
s     = kinv * (h + r * d)  
s * k = h + r * d  
s * (k_ + a) =  h + r * d  
s * a = h - s * k_ + r * d  
rinv * r_new * s * a = rinv * r_new * (h - s * k_) + rinv * r_new * r * d  
rinv * r_new * s * a = rinv * r_new * (h - s * k_) + r_new * d  
```

New signature is finally derived as below:  
```python  
r_new = (k * G - k_ * G).x()  
s_new = rinv * r_new * s  
h_new = rinv * r_new * (h - s * k_)  
```

By converting given signatures using above derivation, we get `num_sample`
signatures, which uses biased nonce.  
The nonce's upper 96 bits will be set to zero. [Biased nonce attack
time!](https://eprint.iacr.org/2019/023.pdf) Solve Hidden number problem using
LLL to obtain secret key `d`. `100` sample was sufficient to recover the
hidden number.

```  
LINECTF{0xd77d10fec685cbe16f64cba090db24d23b92f824}  
```

Problem output:
[Babycrypto_revisited_b1f108dea290b83253b80443260b12c3cadc0ed7.txt](Babycrypto_revisited_b1f108dea290b83253b80443260b12c3cadc0ed7.txt)

exploit driver code: [solve.sage](solve.sage)  

Original writeup (https://github.com/pcw109550/write-
up/tree/master/2022/LINE/Baby_crypto_revisited).