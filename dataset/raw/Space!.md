# Space (crypto, 100p, 41 solved)

The challenge code is:

```python  
from hashlib import md5  
from base64 import b64decode  
from base64 import b64encode  
from Crypto.Cipher import AES  
from Crypto.Random import get_random_bytes  
from random import randrange  
import string

alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits  
iv = md5(b"ignis").digest()

flag = "ijctf{i am not the real flag :)}"  
message = b"Its dangerous to solve alone, take this" + b"\x00"*9

keys = []  
for i in range(4):  
   key = alphabet[randrange(0,len(alphabet))] +
alphabet[randrange(0,len(alphabet))]  
   keys.append(key.encode() + b'\x00'*14)

for key in keys:  
   cipher = AES.new(key, AES.MODE_CBC, IV=iv)  
   flag = cipher.encrypt(flag)  
  
for key in keys:  
   cipher = AES.new(key, AES.MODE_CBC, IV=iv)  
   message = cipher.encrypt(message)

print(f"flag= {b64encode(flag)}")  
print(f"message= {b64encode(message)}")  
```

And we know:

```  
Here is your message:
NeNpX4+pu2elWP+R2VK78Dp0gbCZPeROsfsuWY1Knm85/4BPwpBNmClPjc3xA284  
And here is your flag:
N2YxBndWO0qd8EwVeZYDVNYTaCzcI7jq7Zc3wRzrlyUdBEzbAx997zAOZi/bLinVj3bKfOniRzmjPgLsygzVzA==  
```

## Solution overview

So we have a known plaintext-ciphertext pair, encrypted in sequence 4 times
via AES-CBC with known IV, but each AES has a key with only 2 bytes of
entropy.  
We can't really bruteforce them just like that, because 8 bytes would be too
much.  
But we can use meet-in-the-middle approach here:

- Perform 2 encryption rounds of the known plaintext with all possible keys (2+2 bytes of entropy)  
- Store all results in a map `ciphertext -> keys`  
- Perform 2 decryption rounds of the known ciphertext with all possible keys (2+2 bytes of entropy)  
- Look for the decryption step results in the encryptions map  
- Once we find a match, we know all 4 keys and we can decrypt the flag

## Forward step

First we generate encryptions map `2-round-encrypted-plaintext -> keys`.  
To make things a bit faster we run this on multiple cores:

```python  
import itertools  
from Crypto.Cipher import AES  
from crypto_commons.brute.brute import brute

iv = md5(b"ignis").digest()  
msg = b"Its dangerous to solve alone, take this" + b"\x00" * 9  
alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits

def enc_worker(keys):  
   key1, allkeys = keys  
   result = {}  
   for key2 in allkeys:  
       enc_msg = msg  
       cipher1 = AES.new(key1 + '\x00' * 14, AES.MODE_CBC, IV=iv)  
       enc_msg = cipher1.encrypt(enc_msg)  
       cipher2 = AES.new(key2 + '\x00' * 14, AES.MODE_CBC, IV=iv)  
       enc_msg = cipher2.encrypt(enc_msg)  
       result[enc_msg] = (key1, key2)  
   return result

def generate_forward(allkeys):  
   full_result = {}  
   partial_results = brute(enc_worker, [(key1, allkeys) for key1 in allkeys],
processes=7)  
   for partial in partial_results:  
       full_result.update(partial)  
   return full_result  
```

## Backwards step

Now we need to perform similar operation, but use decrypt instead of encrypt
and check if result is in the forward map.  
Again we distribute the work to make it faster:

```python  
def dec_worker(keys):  
   key1, allkeys, ct, flag_ct, forward = keys  
   for key2 in allkeys:  
       msg_c = ct  
       cipher1 = AES.new(key1 + '\x00' * 14, AES.MODE_CBC, IV=iv)  
       msg_c = cipher1.decrypt(msg_c)  
       cipher2 = AES.new(key2 + '\x00' * 14, AES.MODE_CBC, IV=iv)  
       msg_c = cipher2.decrypt(msg_c)  
       if msg_c in forward:  
           print(forward[msg_c], key2, key1)  
           keys = [forward[msg_c][0], forward[msg_c][1], key2, key1]  
           for key in keys[::-1]:  
               cipher = AES.new(key + '\x00' * 14, AES.MODE_CBC, IV=iv)  
               flag_ct = cipher.decrypt(flag_ct)  
           print(flag_ct)  
           return keys

def check_backwards(ct, allkeys, flag_ct, forward):  
   datasets = [(key1, allkeys, ct, flag_ct, forward) for key1 in allkeys]  
   brute(dec_worker, datasets, processes=4)  
```

## Flag

Now we just run this on our inputs:

```  
def solve(ct_flag, ct_message):  
   all_keys = map(lambda x: "".join(x), itertools.product(alphabet, repeat=2))  
   print(len(all_keys))  
   forward = generate_forward(all_keys)  
   print("Generated forward")  
   check_backwards(ct_message, all_keys, ct_flag, forward)

def main():  
   msg = 'NeNpX4+pu2elWP+R2VK78Dp0gbCZPeROsfsuWY1Knm85/4BPwpBNmClPjc3xA284'  
   flag =
'N2YxBndWO0qd8EwVeZYDVNYTaCzcI7jq7Zc3wRzrlyUdBEzbAx997zAOZi/bLinVj3bKfOniRzmjPgLsygzVzA=='  
   solve(flag.decode("base64"), msg.decode("base64"))  
```

And after a moment we get:
`ijctf{sp4ce_T1me_Tr4d3off_is_c00l_but_crYpt0_1s_c00l3r_abcdefgh}`

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-04-25-IJCTF/space/README.md).