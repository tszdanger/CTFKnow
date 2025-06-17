# Challenge Description

During the Battle for Druidia, the Spaceballs were able to obtain the code for
the Druidia shield gate: 12345. Fortuantely, the Spaceballs had lost that
battle, and Druidia lived to breathe another day. However, these security
breaches were concerning and so Druidia decided to up their security. This is
where you, Spaceballs' top mathematician, comes into play. We are making yet
another ploy for Druidia's fresh air, and we need your help figuring out their
password. We have obtained the hash of the new combination as well as the
algorithm which generated the hash, which we have supplied to you. Find that
combination, the fate of Planet Spaceball rests in your hands!

NOTE: `The "combination" will be in flag format, i.e. shctf{...}`

Author: `monkey_noises`

# Challenge Solution  
We're provided with a python file `luggage_combination.py`  
```py  
from pwn import *

plaintext = b'****************************************'  
key1 = b'****************************************'  
key2 = b'****************************************'

def shield_combination(p, k1, k2):  
   A = xor(p, k1, k2)  
   B = xor(p, k1)  
   C = xor(p, k2)  
   return A + B + C

print(shield_combination(plaintext, key1, key2).hex())  
```  
and an output of the python script `hash.txt`.  
```  
783f3977627a693a320f313e421e29513e036e485565360a172b00790c211a7b117b4a7814510b2d4b0b01465448580a0369520824294c670c3758706407013e271b624934147f1e70187c1c72666949405c5b4550495e5e02390607217f11695a61587c6351536b741d301d6d182c48254e7f4927683d19  
```

There are four main properties we should consider when we solve challenges
using the XOR operator:  
```  
Commutative: A ⊕ B = B ⊕ A  
Associative: A ⊕ (B ⊕ C) = (A ⊕ B) ⊕ C  
Identity: A ⊕ 0 = A  
Self-Inverse: A ⊕ A = 0  
```  
now that we know these properties, we can write a python script to get the
flag:  
```py  
#!/usr/bin/env python3  
from pwn import xor  
from pyperclip import copy

with open("hash.txt", "r") as file:  
   hash = file.read().strip()  
   hash = bytes.fromhex(hash)  
   A = hash[:40]                # p ^ k1 ^ k2          # The first 40 bytes of
hash.txt denotes to the A  
   B = hash[40:80]              # p ^ k1  
   C = hash[80:]                # p ^ k2          # The last 40 bytes (not 41
since we stripped the trailing newline character)

BC = xor(B, C)  # [B ^ C] = [p ^ p ^ k1 ^ k2] = [0 ^ k1 ^ k2] = [k1 ^ k2]  
p = xor(BC, A)  # [A ^ B ^ C] = [A ^ k1 ^ k2] = [p ^ k1 ^ k2 ^ k1 ^ k2] = [p ^
0 ^ 0] = p

flag = p.decode()  
print(flag)  
copy(flag)            # copies the flag to the clipboard

```