Solution for this is the same of in the (2.0) version..

## Solution

Notice that the flag is encrypted using _textbook-rsa_, which means that the
plaintext is malleable. To illustrate the general idea, let us first solve a
simpler version of this problem.

### Simpler version of the problem

If the problem given was the following,

```python  
for i in range(5):  
   if choice == '1':  
       m = bytes_to_long(input('\nPlaintext > ').strip().encode())  
       print('\nEncrypted: ' + str(encrypt(m)))  
   elif choice == '2':  
       c = int(input('\nCiphertext > ').strip())  
       if c == flag_encrypted:  
           print('Ho, ho, no...')  
       else:  
           print('\nDecrypted: ' + str(m))  
```

Since the ciphertext is malleable, then we can mutate the ciphertext in a way
that is predictable to us.

```  
ct_flag     = encrypt(flag)  = flag^e     mod n  
ct_two      = encrypt(2)     = 2^e        mod n  
ct_not_flag = ct_flag*ct_two = (flag*2)^e mod n  
```

Therefore, `decrypted(ct_not_flag) = flag*2`

But this problem _does not allow_ this. So we have to look for a way to
manipulate the ciphertext.

### Solving the current version

Let's say we have the public key `(n, e)`, then we can bypass the `Ho, ho,
no...`

```  
ct_flag     = encrypt(flag)  = flag^e     mod n  
ct_neg      = encrypt(-1)    = -1^e       mod n = -1 mod n  
ct_not_flag = ct_flag*ct_neg = (flag*-1)^e mod n  
```

Which means that `decrypted(ct_not_flag) = flag*-1 mod n`, and we can easily
recover the flag from that.

```python  
e = 65537  
n = get_n()  
m = flag*(n-1) % n  
pt = decrypt(m)  
print(long_to_bytes((pt*(n-1))%n))  
```

But this requires us to be able to get `n` and `e`.

### Getting the public key

Getting `e` is easy because the default value is `e = 65537` and we are left
to find `n`.

It's easy to show that for some `m`, then `m**65537 - encrypt(m)` is a
multiple of `n`, and for some cases,  
```  
n = gcd(m1**65537 - encrypt(m1), m2**65537 - encrypt(m2))  
```

You can get the GCD of several residuals to make it more likely that you have
gotten `n`.

We implement this using,  

```python  
e = 65537  
def get_resid(i):  
	return i**e - encrypt(i)

def get_n():  
	curr = get_resid(bytes_to_long('a'))  
	for i in [bytes_to_long('b'), bytes_to_long('c')]:  
		curr = GCD(curr, get_resid(i))  
	return curr  
```

__For full implementation see the URL__

Original writeup (https://github.com/pberba/ctf-
solutions/tree/master/20181223_xmasctf/crypto-328-santas_list_(2.0)).