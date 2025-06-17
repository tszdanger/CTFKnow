#### Description:  
Small numbers are bad in cryptography. This is why.

#### dhkectf_intro.py  
```python  
import random  
from Crypto.Cipher import AES

# generate key  
gpList = [ [13, 19], [7, 17], [3, 31], [13, 19], [17, 23], [2, 29] ]  
g, p = random.choice(gpList)  
a = random.randint(1, p)  
b = random.randint(1, p)  
k = pow(g, a * b, p)  
k = str(k)

# print("Diffie-Hellman key exchange outputs")  
# print("Public key: ", g, p)  
# print("Jotaro sends: ", aNum)  
# print("Dio sends: ", bNum)  
# print()

# pad key to 16 bytes (128bit)  
key = ""  
i = 0  
padding = "uiuctf2021uiuctf2021"  
while (16 - len(key) != len(k)):  
   key = key + padding[i]  
   i += 1  
key = key + k  
key = bytes(key, encoding='ascii')

with open('flag.txt', 'rb') as f:  
   flag = f.read()

iv = bytes("kono DIO daaaaaa", encoding = 'ascii')  
cipher = AES.new(key, AES.MODE_CFB, iv)  
ciphertext = cipher.encrypt(flag)

print(ciphertext.hex())  
```

#### output.txt  
```  
b31699d587f7daf8f6b23b30cfee0edca5d6a3594cd53e1646b9e72de6fc44fe7ad40f0ea6  
```

----

Let's look at the python script:

The script contains a list of tuples of prime numbers and chooses one tuple
randomly. The primes will be used for a Diffie-Hellman key exchange. The first
prime will be used as generator and the second one as module.  
```python  
gpList = [ [13, 19], [7, 17], [3, 31], [13, 19], [17, 23], [2, 29] ]  
g, p = random.choice(gpList)  
```

After agreeing on the generator, each party generates its secret:  
```python  
a = random.randint(1, p)  
b = random.randint(1, p)  
```

Normally the following would happen:  
- Alice calculates `g^a % p` and sends it to Bob, Bob calculates `g^b % p` and sends it to Alice  
- Alice calculates with the received value from Bob `(g^b % p)^a % p`, Bob does the same  
- Now Alice and Bob have the same secret key: `(g^b % p)^a % p = (g^b)^a % p = g^(b*a) % p = g^(a*b) % p = (g^a)^b % p = (g^a % p)^b % p`.

As the authors use Diffie-Hellman just to generate a key locally, they
simplified this:  
```python  
k = pow(g, a * b, p)  
```

After that the key is converted to string for later use:  
```python  
k = str(k)  
```

As we now have generated a secret key with Diffie-Hellman this key is used in
AES for encrypting the flag.

As AES needs a 128-bit key, we have to blow up our key. The script chooses the
easy way and adds constant padding in front of the key:  
```python  
# pad key to 16 bytes (128bit)  
key = ""  
i = 0  
padding = "uiuctf2021uiuctf2021"  
while (16 - len(key) != len(k)):  
   key = key + padding[i]  
   i += 1  
key = key + k  
```

Then the key is converted to bytes for the AES-Function:  
```python  
key = bytes(key, encoding='ascii')  
```

After that the flag is read from file:  
```python  
with open('flag.txt', 'rb') as f:  
   flag = f.read()  
```

AES needs an initialization vector. The authors decided to use a constant
initialization vector. This has the advantage, that the initialization vector
must not be stored with the encrypted text, so that we can handle the
output.txt easier. On the other side this destroys the reason for the
initialization vector which should prevent that all messages with the same
first block have the same first ciphertext block. As we have only one message,
this is irrelevant.  
```python  
iv = bytes("kono DIO daaaaaa", encoding = 'ascii')  
```

Now the flag is encrypted:  
```python  
cipher = AES.new(key, AES.MODE_CFB, iv)  
ciphertext = cipher.encrypt(flag)  
```

Finally, the encrypted text is written in hex to the given output.txt:  
```python  
print(ciphertext.hex())  
```

  
---  
Now we can try to decrypt the flag. First we need to read the encrypted flag:  
```python  
with open("output.txt", "r") as f:  
   output = bytearray.fromhex(f.read())  
```

As `gpList` is short and the used modules are small, we can simply test all
tuples:  
```python  
for pair in gpList:  
   g, p = pair  
   print(g, p, pair)  
```

As the module is small, we can test all possible `a` and `b`. Without loss of
generality we can assume `b >= a`, since multiplication is commutative.  
```python  
   for a in range(1, p+1):  
       for b in range(a, p+1):  
```  
We have to use `p+1`, because `randInt(a,b)` uses the interval `[a, b]`
whereas `range(a,b)` uses the interval `[a, b)`.

Now we can copy the computation of the key from the provided encryption
script:  
```python  
   #a = random.randint(1, p)  
   #b = random.randint(1, p)  
           k = pow(g, a * b, p)  
           k = str(k)

   #print("Diffie-Hellman key exchange outputs")  
   #print("Public key: ", g, p)  
   #print("Jotaro sends: ", aNum)  
   #print("Dio sends: ", bNum)  
   #print()

           #pad key to 16 bytes (128bit)  
           key = ""  
           i = 0  
           padding = "uiuctf2021uiuctf2021"  
           while (16 - len(key) != len(k)):  
               key = key + padding[i]  
               i += 1  
           key = key + k  
           key = bytes(key, encoding='ascii')

           iv = bytes("kono DIO daaaaaa", encoding = 'ascii')  
```

After initializing AES  
```python  
           cipher = AES.new(key, AES.MODE_CFB, iv)  
```

we can try to decrypt the flag.  
```python  
           cleartext = cipher.decrypt(output)  
```

As we know the beginning of the flag, we can filter the output:  
```python  
           if cleartext[:7] == b'uiuctf{':  
               print(cleartext)  
```

When we now execute the script, we will see the correct flag can be decrypted
with different tuples and even multiple times per tuple:  
```  
[13, 19]  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
[7, 17]  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
[3, 31]  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
[13, 19]  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
[17, 23]  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
[2, 29]  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
```

This has multiple reasons:  
1. We can redistribute the prime factors of `a*b` nearly arbitrary between `a` and `b`.  
2. Because of the module, the resulting `k` will always be in the interval `[0, p-1]`. Since the greatest common divisor between `g` and `p` is `1`, the `0` cannot be reached. So `k` will be always in the interval `[1, p-1]`

With this knowledge, we can simplify the script:  
1. Search the greatest module and use only this module.  
2. Iterate over the interval `[1, p-1]` and try each for `k`.

With this adjustments, we get the following script:  
```python  
from Crypto.Cipher import AES

# find greatest module  
gpList = [ [13, 19], [7, 17], [3, 31], [13, 19], [17, 23], [2, 29] ]  
mod = 0  
for g, p in gpList:  
   if p > mod:  
       mod = p

# open encrypted flag  
with open("output.txt", "r") as f:  
   output = bytearray.fromhex(f.read())

# iterate over all possible keys  
for i in range(1, mod):  
   k = str(i)

   #pad key to 16 bytes (128bit)  
   key = ""  
   i = 0  
   padding = "uiuctf2021uiuctf2021"  
   while (16 - len(key) != len(k)):  
       key = key + padding[i]  
       i += 1  
   key = key + k  
   key = bytes(key, encoding='ascii')

   # initialize AES  
   iv = bytes("kono DIO daaaaaa", encoding = 'ascii')  
   cipher = AES.new(key, AES.MODE_CFB, iv)

   # decrypt flag  
   cleartext = cipher.decrypt(output)

   # check if cleartext is flag and print flag  
   if cleartext[:7] == b'uiuctf{':  
       print(cleartext)  
```

Now we get the flag only once.  
```  
b'uiuctf{omae_ha_mou_shindeiru_b9e5f9}\n'  
```

Due to the small numbers the time difference between both scripts is
negligible (0.90s vs. 0.83s).

Original writeup (https://ctf0.de/posts/uiuctf2021-dhke-intro/).