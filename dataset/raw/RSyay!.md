# RSyay! (crypto, 396p)

In the task we get the code running on the server:

```python  
def func(bits):  
   keys = gen_rsa_key(bits, e=65537)  
   p = keys.p  
   q = keys.q  
   m = getPrime(bits + 1)  
   x = pow(p, m, m) * pow(q, m, m) + p * pow(q, m, m) + q * pow(p, m, m) + p *
q + pow(p, m - 1, m) * pow(q, m - 1, m)  
   text = os.urandom(32)  
   print('Plaintext (b64encoded) : ', b64encode(text).decode())  
   print()  
   print(hex(x)[2:])  
   print(hex(m)[2:])  
   print()  
   ciphertext = input('Ciphertext (b64encoded) : ')  
   check(ciphertext)  
```

The idea is pretty simple:

1. There is some random RSA key  
2. We get some prime `m` longer than RSA modulus at least by a single bit  
3. We get a special value `x`, calculated using `p` and `q`  
4. Our goal is to encrypt plaintext provided by the server

Server requires the encryption in form of base64 results of:

```python  
def encrypt(keys, plaintext):  
   from Crypto.Cipher import PKCS1_OAEP  
   encryptor = PKCS1_OAEP.new(keys)  
   return encryptor.encrypt(plaintext)  
```

This means We need to somehow recover the modulus of the RSA key (exponent is
known to be 65537).

For this we have to look at value x:

```  
x = pow(p, m, m) * pow(q, m, m) + p * pow(q, m, m) + q * pow(p, m, m) + p * q
+ pow(p, m - 1, m) * pow(q, m - 1, m)  
```

The key in solving this challenge is to know Euler Totient Theorem
`https://en.wikipedia.org/wiki/Euler's_theorem`

Notice that all calculations in `x` are done `mod m`, and `m` is a prime,
therefore `phi(m) = m-1`.  
Notice that according to the theorem `x^phi(m) mod m == 1`.

Let's modify the equation we have, to use `m-1` exponent wherever we can:

```  
x = pow(p, m, m) * pow(q, m, m) + p * pow(q, m, m) + q * pow(p, m, m) + p * q
+ pow(p, m - 1, m) * pow(q, m - 1, m)  
x = (p^m mod m * q^m mod m) + (p*q^m mod m) + (q*p^m mod m) + (p*q) + (p^(m-1)
mod m * q^(m-1) mod m)  
```

For more readability let's take each part separately:

1.  
```  
(p^m mod m * q^m mod m)  
p*p^(m-1) mod m * q*q^(m-1) mod m  
p*1 * q*1 mod m  
p*q mod m  
p*q  
```

2.   
```  
(p*q^m mod m)  
p*q*q(m-1) mod m  
p*q*1 mod m  
p*q mod m  
p*q  
```

3.   
```  
(q*p^m mod m)  
q*p*p^(m-1) mod m  
q*p*1 mod m  
p*q mod m  
p*q  
```

4.   
```  
p*q  
```

5.  
```  
(p^(m-1) mod m * q^(m-1) mod m)  
1*1 mod m  
1  
```

Notice that we know that `m` is larger than `p*q` because it was selected to
be at least 1 bit longer, so `p*q mod m = p*q`

Now if we combine all of those we get:

```  
x = p*q + p*q + p*q + p*q +1 = 4*pq+1  
x = 4*n+1  
n = (x-1)/4  
```

We can verify this quickly by:

```python  
def sanity():  
   bits = 1024  
   m = getPrime(bits + 1)  
   p = getPrime(bits // 2)  
   q = getPrime(bits // 2)  
   n = p * q  
   x = pow(p, m, m) * pow(q, m, m) + p * pow(q, m, m) + q * pow(p, m, m) + p *
q + pow(p, m - 1, m) * pow(q, m - 1, m)  
   assert n == (x - 1) / 4  
```

Now we can just plug this into the solver:

```python  
def main():  
   host = "crypto.byteband.it"  
   port = 7002  
   s = nc(host, port)  
   for i in range(32):  
       data = receive_until_match(s, "Plaintext \(b64encoded\) :  ")  
       pt = receive_until(s, "\n").decode("base64")  
       receive_until(s, "\n")  
       x = int(receive_until(s, "\n").strip(), 16)  
       m = int(receive_until(s, "\n").strip(), 16)  
       print('x', x)  
       print('m', m)  
       n = recover_n(x, m)  
       print('recovered n', n)  
       key = RSA.construct((long(n), long(65537)))  
       ct = base64.b64encode(encrypt(key, pt))  
       print('ct', ct)  
       send(s, ct)  
   interactive(s)  
```

And after a moment get get: `flag{RSA_1s_th3_str0ng3st_c1ph3r_ind33d_0_0}`

[complete solver
here](https://raw.githubusercontent.com/TFNS/writeups/master/2020-04-12-ByteBanditsCTF/rsyay/solver.py)

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-04-12-ByteBanditsCTF/rsyay/README.md).