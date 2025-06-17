# Tyrannosaurus Rex

## Problem

> We found this fossil. Can you reverse time and bring this back to life?  
  
  
Download the file below.

[fossil](fossil)

## Solution

We are given a Python source file with an encrypted flag and the function that
was used to encrypt it. Our goal is to understand the encrypt function in
order to be able to reverse it and decrypt the file.

Looking at the encrypt function, we see that the flag is first converted to
base 64, which is stored in the variable `e`.

Then, `z`, a list of integers, is formed by XORing every two consecutive
letters in `e`. The last letter is XORed with the first one, as indicated by
the `% len(e)`.

Finally, `z` is converted to hex using `binascii.hexlify()`.

Since we know the flag format for this CTF, `flag{.*}`, we can run
`base64.b64encode(b'flag')` to see how that would look like in base 64. We get
`b'ZmxhZw=='`. The first character, `Z`, has decimal value `90`.

Using this knowledge, we can reverse the encryption process and decrypt `z`
from right to left. Since the last integer in `z` is the XOR of the last and
first character in the base 64 representation of the flag, we can XOR `90`
with the last character in `z` to get the last character of the flag. This
works because the XOR operation has the following property: `A ^ A = 0`,
therefore `A ^ A ^ B = B`. Using the last character of the flag, we can get
the second-last character, and so on.

This is the decrypt function:

```py  
def dec(ciphertext):  
   z = list(binascii.unhexlify(ciphertext))  
   i = len(z) - 1  
   e = b''  
   last = 90 # base64.b64encode(b'flag')[0]  
   while i >= 0:  
       last ^= z[i]  
       e = chr(last).encode('utf-8') + e  
       i -= 1  
   f = base64.b64decode(e)  
   return f  
```  

Original writeup (https://github.com/SababaSec/ctf-
writeups/tree/master/2020/H@cktivityCon-CTF/Cryptography/Tyrannosaurus%20Rex).