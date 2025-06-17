# What the Flip?!  

  
![](https://i.postimg.cc/3RF1MvLx/Immagine.jpg")  

## FLAG:  
`DawgCTF{F1ip4J0y}`  
#  
## Solution  
After a first reading of the [source code](app.py), you immediately notice
that a `username` and `password` are required (which are provided for logging
to be successful). Furthermore, such data will be encrypted (with a specific
format) and will be returned in the form of `ciphertext`.  
```python  
msg = 'logged_username=' + user +'&password=' + passwd

try:  
   assert('admin&password=goBigDawgs123' not in msg)  
except AssertionError:  
   send_msg(s, 'You cannot login as an admin from an external IP.\nYour
activity has been logged. Goodbye!\n')  
   raise

send_msg(s, "Leaked ciphertext: " + encrypt_data(msg)+'\n')  
send_msg(s,"enter ciphertext: ")  
```  
But the problem consists in passing the `username` and `password` check that
the program does in `decrypt_data`.  
```python  
def decrypt_data(encryptedParams):  
   cipher = AES.new(key, AES.MODE_CBC,iv)  
   paddedParams = cipher.decrypt( unhexlify(encryptedParams))  
   print(paddedParams)  
   if b'admin&password=goBigDawgs123' in unpad(paddedParams,16,style='pkcs7'):  
          return 1  
   else:  
          return 0  
```  
The solution to this problem comes from:  
- [operating mode (CBC)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) used to make the encrypt;  
- name of the challenge that refers to a known [Bit (or Byte) Flipping Attack](https://crypto.stackexchange.com/questions/66085/bit-flipping-attack-on-cbc-mode).

## Explanation and implementation of the attack  
This attack involves modifying a bit (or a group) in order to modify part of
the plaintext starting from the ciphertext.  

  
![](https://i.postimg.cc/TPqPMVDS/bOu8Q.png")  

In particular, it exploits the fact that, in the [CBC
Mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC))
decrypt process, each part of the plaintext depends on the ciphertext of the
previous block according to the formula:  

  
![](https://i.postimg.cc/XNxyybXh/Immagine.png")  

  
  
where *nb* is the number of blocks.

So the idea you want to follow is to send _username_ or _password_ with a
modified character so that they pass the check that is done in _decrypt_data_
and then apply the attack.  
By doing so we will know exactly the position of the bit to be modified
because CBC works with 16-bit blocks and knowing what the input is and in
which format the plaintext is to be encrypted, we will have a complete
perception of the composition of the ciphertext.  
So we sent `bdmin` as _username_ and `goBigDawgs123` as _password_ with the
aim of changing the _b_ of the username to _a_.

The _b_ is the 17th character of the
`logged_username=bdmin&password=goBigDawgs123`, so you have to change the
first bit of the first block to have the first bit of the second block
changed.  
| Example | First block | Second block | Third Block |  
|:-:|:-:|:-:|:-:|  
| Plaintext | logged_username= | bdmin&password=g | oBigDawgs123 |  
| Ciphertext | 6e4fd3f004fe5093b2c12c96295ffa9e | 43d90ec26233b96a2d03d245f08acb8e | 5588d537e1b35b73d909951720f165ae |

Now let's examine the hexadecimal of the above example. In particular we will
know that:  
- the hexadecimal value of the byte representing _l_ is _6e_;  
- the hexadecimal value of the byte representing _b_ is _43_.

At this point, considering the CBC decrypt process we can say that:  
- _hex('b') = 0x62 = 0x6e ⊕ dec(0x43)_ and thanks to the commutativity of xor you can have it _dec(0x43) = 0x62 ⊕ 0x6e_;  
- in order to have _a_ in the plaintext one must find that number such that the xor with _dec(0x43)_ gives the value corresponding to the hex of _a_, that is _? ⊕ dec(0x43) = hex('a') = 0x61_. 

Found this hexadecimal value, just replace it in the starting hexadecimal to
get the new ciphertext.

The attack was automated with the following python script.  
```python  
from pwn import *

p = remote("umbccd.io", 3000)

p.recv()  
p.sendline("bdmin")  
p.recv()  
p.sendline("goBigDawgs123")  
p.recv()

leaked = p.recvline().decode().strip().split(": ")[1]  
log.info(f"Leaked ciphertext: {leaked}")

dec = int(leaked[:2], 16) ^ int("0x62", 16)  
enc_a = hex(dec  ^ int("0x61", 16))

new_ciph = enc_a[2:] + leaked[2:]  
log.info(f"New ciphertext:    {new_ciph}")  
p.sendline(new_ciph)  
p.recv()  
print(p.recv().decode())  
```  

Original writeup (https://github.com/hackalcubo/CTF-
Writeups/tree/main/DawnCTF%202021/Crypto/What%20the%20Flip%3F!).