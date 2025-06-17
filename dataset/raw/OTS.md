# OTS (crypto, 104+1p, 51 solved)

Once we connect to the server we get
[code](https://raw.githubusercontent.com/TFNS/writeups/master/2020-05-09-SpamAndFlags/code.py),
public key, message and signature, and we're asked to provide new message
containing word `flag` and valid signature.

## Overview

The algorithm is pretty easy to follow:

1. There are 128 chunks of 16 bytes randomly generated to server as key.  
2. Message is padded with lots of zeros and md5 checksum of the message is appended at the end, so that the total message length is exactly 128 bytes.  
3. For `i from 0 to 128` take byte `message[i]` and key chunk `key[i]`, now turn the message byte into an integer `xi` according to ascii table, and perform `255-xi` times `md5` hash recursively on the key chunk, as in `md5(md5(md5(...(md5(key[i])))))`.  
4. Such generated md5 checksum is appended to the signature.

The `public key` in this case is just secret key chunks hashed in this way 255
times for each block, the same as if you hashed a message containing only zero
bytes.

The signature verification takes the message and the signature, and performs
similar hashing, but this time of the signature blocks instead of secret key,
and hashes `xi` times instead of `255-xi`.  
The point is that by doing this, each secret key block gets hashes exactly
`255` times, since it was `255-xi` when generating the signature, and `xi`
when doing verification, so in total just `255`.  
And this should be equal to the public key.

## Vulnerability

Just by looking at the verification logic it should instantly be obvious what
the problem is.  
If we change `k-th` byte in the message from `b` to `a` then the verification
procedure will perform one `md5` operation less than it should on the
signature block, but we can apply `md5` on the `k-th` signature block
ourselves!  
This will cause this signature block to be valid for the new message.

Notice that we can only flip downwards, we can change `b` to `a` but not `a`
to `b`, because we can hash only forward.

There is also one small problem: the whole message checksum is added at the
end of the message.  
If we flip `k-th` byte from `b` to `a` then the entire checksum will change!  
So not only we need to flip the `k-th` signature block by applying one more
`md5`, but we also need to somehow fix the last 16 signature blocks
corresponding to the checksum.

It's easy to notice that in fact this is exactly the same issue - we know the
checksum of original message and we want to change it to something else and
then `flip` the signature blocks by applying proper number of `md5`, so the
signature is valid.

The trick is, as mentioned above, that we can only flip downwards.  
This means that our new checksum for the message needs to have each
corresponding byte smaller than the checksum of original message:

```python  
def is_ok(original_hash, new_hash):  
   valid_ones = 0  
   for a, b in zip(original_hash, new_hash):  
       if a >= b:  
           valid_ones += 1  
   return valid_ones == 16  
```

Fortunately the original message is long and we can randomly flip all bytes
(except for the `flag` word we need) and check if the new checksum is nice or
not.

## Solution

We proceed as follows:

- Original message is something like `My favorite number is 688915709066267095."`, we can flip `vori` to `flag` because each target byte is smaller than original one.  
- Now we want to flip all other character to some random smaller bytes, and calculate the checksum.  
- We can then verify if the new md5 checksum we got has each byte smaller than the original md5 of the message did.  
- If not, then we repeat steps 2 and 3. Once we finally found valid checksum we proceed further.  
- Now we have a new message, we can append new md5 checksum at the end.  
- Finally we can go over the message, calculate the difference between `k-th` byte of the original message and `k-th` byte of new message, and apply `md5` that many times on the `k-th` signature block.

```python  
def solve(msg, signature):  
   original_msg = msg[:]  
   original_hash = calculate_hash(msg)  
   msg = list(msg)  
   for idx, char in zip([5, 6, 7, 8], 'flag'):  
       msg[idx] = char  
   new_msg = flip_hash(msg, original_hash)  
   new_sig = fix_signature(wrap(original_msg), signature, wrap(new_msg))  
   return new_msg, new_sig.hex()

def flip_hash(msg, original_hash):  
   while True:  
       nice_msg = msg[:]  
       for idx in range(len(nice_msg)):  
           if idx in [5, 6, 7, 8]:  
               continue  
           to = random.randrange(ord(' '), ord(nice_msg[idx]) + 1)  
           nice_msg[idx] = chr(to)  
       current_msg = "".join(nice_msg)  
       current = calculate_hash(current_msg)  
       if is_ok(original_hash, current):  
           print(current_msg)  
           break  
   return current_msg

def fix_signature(original_msg, signature, new_msg):  
   signature = binascii.unhexlify(signature)  
   c = chunk(signature, 16)  
   for i in range(len(original_msg)):  
       c[i] = flip_block(c[i], original_msg[i], new_msg[i])  
   return b''.join(c)

  
def calculate_hash(msg):  
   raw = msg.encode('utf-8')  
   raw = raw + b'\x00' * (128 - 16 - len(raw))  
   return hashlib.md5(raw).digest()

def wrap(msg):  
   raw = msg.encode('utf-8')  
   raw = raw + b'\x00' * (128 - 16 - len(raw))  
   raw = raw + hashlib.md5(raw).digest()  
   return raw  
```

We connect to the server, provide new message and signature and get
flag:`SaF{better_stick_with_WOTS+}`

Complete solver
[here](https://raw.githubusercontent.com/TFNS/writeups/master/2020-05-09-SpamAndFlags/ots.py)

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-05-09-SpamAndFlags/ots/README.md).