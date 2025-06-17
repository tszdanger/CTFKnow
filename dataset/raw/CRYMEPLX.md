---  
Category: CRY | 100 pts - 170 solves  
---

# CryMePlx

> Description: Awesome service. Now I don't need to encrypt anything myself! \  
> Connect via: `nc chall.rumble.host 2734`

We had a service to netcat with: `nc chall.rumble.host 2734` and the source
code to download & unzip. \  
Looking at the source code, the program ask for input and then encrypt the
flag and the input with AES-CTR-128 mode.

```python  
from Crypto.Cipher import AES  
from secret import flag  
import os

kwargs = {"nonce": os.urandom(8)}  
key = os.urandom(16)

def encrypt(msg):  
   aes = AES.new(key, AES.MODE_CTR, **kwargs)  
   return aes.encrypt(msg).hex()

print(encrypt(flag))  
q = input("Encrypt this string:").encode()  
print(encrypt(q))  
```

The vulnerability here is that the Nonce is reused for all the encryptions,
and as the name says, it should be used only (n)once. \  
So, the encryption of flag is done with:

`Ciphertext1 = flag ⊕ AES(Key, Nonce)`

and the encryption of user input:

`Ciphertext2 = input ⊕ AES(Key, Nonce)`

Note that we used the same Nonce and Key pair, so we can say that:

`AES(Key, Nonce) = flag ⊕ Ciphertext1`\  
`AES(Key, Nonce) = input ⊕ Ciphertext2`

Therefore:

`flag ⊕ Ciphertext1 = input ⊕ Ciphertext2`\  
`flag = input ⊕ Ciphertext2 ⊕ Ciphertext1`\  
\  
Let's write our exploit:

```python  
from pwn import *  
import binascii

context.log_level = 'debug'  
p = remote('chall.rumble.host', 2734)

enc_flag = binascii.unhexlify(p.recvline().strip())  
input = 'A' * len(enc_flag)  
p.sendlineafter('Encrypt this string:', input)  
enc_input = binascii.unhexlify(p.recvline().strip())

flag = xor(input, enc_input, enc_flag)  
log.success(f'{flag=}')  
```

Original writeup
(https://github.com/simonedimaria/CTF/blob/main/events/CyberSecurityRumble).