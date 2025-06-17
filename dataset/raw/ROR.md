# ROR (crypto, 260p, 58 solved)

In the task we get a short [encryption
code](https://raw.githubusercontent.com/TFNS/writeups/master/2020-03-07-zer0ptsCTF/ror/chall.py)
and
[results](https://raw.githubusercontent.com/TFNS/writeups/master/2020-03-07-zer0ptsCTF/ror/chall.txt).

The encryption is pretty simple:

```python  
ror = lambda x, l, b: (x >> l) | ((x & ((1<<l)-1)) << (b-l))

N = 1  
for base in [2, 3, 7]:  
   N *= pow(base, random.randint(123, 456))  
e = random.randint(271828, 314159)

m = int.from_bytes(flag, byteorder='big')  
assert m.bit_length() < N.bit_length()

for i in range(m.bit_length()):  
   print(pow(ror(m, i, m.bit_length()), e, N))  
```

It's RSA-like encryption where we encrypt the value, then right-shift it and
encrypt again.  
We know all those encryption results.

One could consider brute-force over 40 bits of entropy we have here, test
every possible `N` and `e` and generate potential RSA decryption exponent.  
However, this won't work because the parameters are generated in such a way,
that this exponent might not exist at all.

The key observation here is that `N` is created in a very strange way, and the
pitfall is including `2^k` as one of the factors.  
This causes `N` to always be an even number!

One of the properties of even numbers is that remainder from division will
retain the least significant bit.  
This is because:

```  
x % 2*y == z <=> x == 2*y*k + z  
```

It's clear that `2*y*k` has to be even, and if `x` was odd then `z` has to be
odd, and conversly if `x` was even then `z` has to be even as well.

While we have modular power and not just modular division in the task, it
makes no difference because raising odd number to any power gives odd number
and same goes for even numbers (with powers > 0).

This means that each of the encryption results we know, retains the LSB of the
plaintext.  
And since the encryption shifts flag to the right every time, all bits are
leaked.

We can recover this by:

```python  
lines = open("chall.txt", 'r').readlines()  
bits = []  
for line in lines:  
   v = int(line[:-1])  
   bits.append(str(v & 1))  
bits = bits[::-1]  
print(long_to_bytes(int("".join(bits), 2)))  
```

And we get `zer0pts{0h_1t_l34ks_th3_l34st_s1gn1f1c4nt_b1t}`

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-03-07-zer0ptsCTF/ror/README.md).