# diysig Writeup

### zer0pts CTF 2020 - crypto 394

> I made a cipher-signature system by myself. `nc 18.179.178.246 3001`

#### Notice the LSB oracle

The challenge is almost same with [Plaid CTF 2016 Qual:
rabit](https://ctftime.org/task/2293). By suppling arbitrary ciphertext `c`
for `verify()`, I can get LSB of plaintext `m = pow(c, d, n)` This is caused
by the structure of `_hash()`. By observing `Stage 3` of `_hash()`,

```python  
# Stage 3  
H = H | 1 if m & 1 else H & 0xfffffffe  
return H  
```

The parity of `H` and `m` is always same!

#### Binary Search for flag

If I ask the oracle to tell the parity of decrypting `pow(2, e, n) * c % n`,
the result will be always even(decrypted result will be `2 * m`). Perform
modular division by `n` which is odd, we can get two possible results:

1. LSB after modular division is 0: Parity is preserved so `2 * m <= n`.  
2. LSB after modular division is 1: Parity is flipped so `2 * m > n`.

I can generalize the method by knowing the parity of decryption result of
`pow(1 << i, e, n) * c % n`, where `i` is from `1` to bitlength of `n`. By
iteratively halving the solution space(binary searaching) by using the LSB
oracle, I get flag:

```  
zer0pts{n3v3r_r3v34l_7h3_LSB}  
```

Exploit code: [solve.py](solve.py)  

Original writeup (https://github.com/pcw109550/write-
up/tree/master/2020/zer0pts/diysig).