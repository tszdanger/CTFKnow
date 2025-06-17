# Nibelung (crypto, 525p, 22 solved)

A very interesting crypto challenge.  
We get [server
code](https://raw.githubusercontent.com/TFNS/writeups/master/2020-03-07-zer0ptsCTF/nibelung/server.py)
and a
[library](https://raw.githubusercontent.com/TFNS/writeups/master/2020-03-07-zer0ptsCTF/nibelung/fglg.py)
presumably implementing a FiniteGeneralLinearGroup.  
It seems to provide a way to perform operations on Matrices mod p (default p
is random 512 bit prime).

The server turns flag into a matrix, then generates a random matrix `U`,
encrypts the flag and sends the encryption result to us.  
Encryption and decryption is:

```python  
def encrypt(U, X):  
   return U * X * U ** -1

def decrypt(U, X):  
   return U ** -1 * X * U  
```

The results of those operations are elements of `fglg` so matrices mod p.

The server allows us to encrypt and decrypt data at will, but there is a small
twist -> we can only provide data using:

```python  
def bytes2gl(b, n, p=None):  
   assert len(b) <= n * n  
   X = FiniteGeneralLinearGroup(n, p)  
   padlen = n * n - len(b)  
   b = bytes([padlen]) * padlen + b  
   for i in range(n):  
       for j in range(n):  
           X.set_at((j, i), b[i*n + j])  
   return X

def recv_message(n, p):  
   print("Data: ", end="", flush=True)  
   b = base64.b64decode(input())  
   return bytes2gl(b, n, p)  
```

This means we can only encrypt or decrypt matrix with elements `0..255`, so we
can't simply send the encrypted flag for decryption, because the matrix
elements are much bigger than that.

The key observation here is to notice that the name of the library is a lie.  
While it claims to implement a `Group`, in reality what we get is a `Ring`
instead.  
This is also suggested by the task name ->
https://en.wikipedia.org/wiki/Der_Ring_des_Nibelungen

As everyone, I'm sure, remembers from Algebra a Group has only `additive`
operation defined, while a Ring has also a `multiplicative` operation
available.  
It's clearly the case here -> we can both add and multiply matrices provided
by the library.

Going back to Algebra, we know that there are some properties which hold:

```  
(x+y)+z = x+(y+z)  
x*y = y*x  
(x+y)*z = x*z + y*z  
```

Those properties hold just as well with matrices we have.  
This means the encryption and decryption process is homomorphic, for example:
`encrypt(A+B) == encrypt(A)+encrypt(B)`.

This means we can split the encrypted flag into parts, decrypt each one of
them separately, and then combine them back! It's a classic example of
`blinding attack`.

We don't even have to work with whole matrix, we can focus on single cell!  
Notice that:

```  
[A B] = [A 0] + [0 B] + [0 0] + [0 0]  
[C D]   [0 0]   [0 0]   [C 0]   [0 D]  
```

In order to get decrypted value for element `A` we need to perform two
decryptions, one for `255` and another for `A%255`.  
Once we do that we can simply do `dec_matrix(255)*A/255 + dec_matrix(A%255)`
to recover the original value.

We effectively split the value into `x*255 + y`.

We proceed like that for every cell of the encrypted flag and combine the
results:

```python  
def solver(res, p, dec_oracle):  
   n = len(res)  
   recovered = FiniteGeneralLinearGroup(n, p)  
   for i in range(n):  
       for j in range(n):  
           print('recovered', i, j)  
           val = res[i][j]  
           k = val / 255  
           remainder = val % 255  
           payload = list('\0' * n * n)  
           payload[i * n + j] = chr(255)  
           result_255 = dec_oracle("".join(payload))  
           X = create_from_matrix(result_255, n, p)  
           recovered += X * k  
           payload[i * n + j] = chr(remainder)  
           result_remainder = dec_oracle("".join(payload))  
           X = create_from_matrix(result_remainder, n, p)  
           recovered += X  
   return recovered  
```

And once we run this we get `zer0pts{r1ng_h0m0m0rph1sm_1s_c00l}`

Complete solver, including some sanity checks,
[here](https://raw.githubusercontent.com/TFNS/writeups/master/2020-03-07-zer0ptsCTF/nibelung/solver.py)

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-03-07-zer0ptsCTF/nibelung/README.md).