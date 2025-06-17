# Baby onion

## Description

> Ogres are like onions!

Attached is a `.onion` file.

## Solution

Let's use `file` on the given file. This is ASCII text, so let's read it. We
see a huge hexadecimal string.

We decode it using Python:

```python  
with open("baby.onion", "r") as f:  
   s = f.read()  
decoded = bytes.fromhex(s).decode()  
print(decoded)  
```

Now we see a huge base64 encoded string (there are two `=` at the end which
look like base64 padding).

So let's decode it:

```python  
import base64  
decode_b64 = base64.b64decode(decoded).decode()  
print(decode_b64)  
```

And now we also see a lot of hexadecimal characters. So let's automate the
decryption:

```python  
while True:  
   decoded = bytes.fromhex(decode_b64).decode()  
   print(decoded)  
   decode_b64 = base64.b64decode(decoded).decode()  
   print(decode_b64)  
```

This finally gives us the flag.

Flag: `DawgCTF{b@by_0n10ns_c@n_$t1ll_Mak3_u_cRy!?!?}`

Original writeup (https://github.com/apoirrier/CTFs-
writeups/blob/master/Dawg2020/Coding/Onion.md).