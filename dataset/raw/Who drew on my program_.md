# Who drew on my program 350

## Description

```  
I don't remember what my IV was I used for encryption and then someone painted
over my code :(. Hopefully somebody else wrote it down!

Author: sandw1ch  
```

## Solution

There was a png file linked which showed a script performing an aes encoding.  
We got to see parts of the key, no iv, and about the second half of the
ciphertext.  
Now there's a twist to the challenge - we don't have to have any
cryptographical knowledge to solve this challenge.  
If you read the last line of the description again it says "Hopefully somebody
else wrote it down!".

So I searched for this string which was visible on the picture: "The message
is protected by AES!"

...Apparently RITSEC plain stole this challenge from tmctf!  
Here's an older writeup:
https://github.com/dqi/ctf_writeup/tree/master/2015/tmctf/crypto200

So I took their script and adjusted it to my values:  
```python  
#!/usr/bin/python

from Crypto.Cipher import AES  
import binascii  
import string  
import itertools

# given  
bKEY = "9aF738g9AkI112"

# use null bytes to minimize effect on output  
IV = "\x00"*16

def encrypt(message, passphrase):  
  aes = AES.new(passphrase, AES.MODE_CBC, IV)  
  return aes.encrypt(message)

def decrypt(cipher, passphrase):  
  aes = AES.new(passphrase, AES.MODE_CBC, IV)  
  return aes.decrypt(cipher)

pt = "The message is protected by AES!"  
ct = "9e00000000000000000000000000436a808e200a54806b0e94fb9633db9d67f0"

# find the key using the plaintext and ciphertext we know, since the IV has no
effect on the decryption of the second block  
for i in itertools.product(string.printable, repeat=2):  
  eKEY = ''.join(i)  
  KEY = bKEY + eKEY  
  ptc = decrypt(binascii.unhexlify(ct), KEY)  
  if ptc[16] == pt[16] and ptc[30] == pt[30] and ptc[31] == pt[31]:  
      print "Got KEY: " + str(KEY)  
      fKEY = KEY  
      pt2 = binascii.hexlify(decrypt(binascii.unhexlify(ct), fKEY))[32:]  
      print "Decrypting with CT mostly zeroes gives: " + pt2  
      print "Should be: " + binascii.hexlify(pt[16:])  
# we can now recover the rest of the ciphertext ct by XOR(pt[i], decrypted[i],
since we chose ct 00 in all the positions we are going to recover  
      answer = ""  
      for i in range(13):  
          pi = pt[17+i]  # letters from the plaintext  
          pti = pt2[2*i+2:2*i+4]  # 2 hex letters from decryption of second block  
          answer += "%02X" % (ord(pi) ^ int(pti, 16))  
      rct = ct[0:2] + answer.lower() + ct[28:]  
      print "Which means CT was: " + rct

# now we can decrypt the recovered ct and xor against the pt to recover the IV  
wpt = decrypt(binascii.unhexlify(rct), fKEY)  
IV = ""  
for i in range(16):  
  p = ord(pt[i]) ^ ord(wpt[i])  
  IV += "%02X" % p  
IV = binascii.unhexlify(IV)

# sanity check:  
aes = AES.new(fKEY, AES.MODE_CBC, IV)  
print "Sanity check: " + aes.decrypt(binascii.unhexlify(rct))

# We won!  
print "The IV is: " + IV  
```

And this was the output:

```bash  
Kiwi@Doghouse:~$ python exploit.py  
Got KEY: 9aF738g9AkI112#g  
Decrypting with CT mostly zeroes gives: 727dfa1eaadff9adf8d347e732cc5321  
Should be: 726f7465637465642062792041455321  
Which means CT was:
9e128e7bc9ab9cc9d8b13ec77389436a808e200a54806b0e94fb9633db9d67f0  
Sanity check: The message is protected by AES!  
The IV is: RITSEC{b4dcbc#g}  
```

It worked! :D

Flag: RITSEC{b4dcbc#g}  

Original writeup
(https://github.com/sw1ss/ctf/blob/master/2018-11-19-RITSEC/Who%20drew%20on%20my%20program/Readme.md).https://medium.com/@0x000c0ded/ritsec-ctf-2018-cryptography-who-drew-on-my-
program-350pts-ac6f356276c6

Original writeup (https://medium.com/@0x000c0ded/ritsec-ctf-2018-cryptography-
who-drew-on-my-program-350pts-ac6f356276c6).