- The attached files were recovered from an attack committed by the malicious AI named RB.    
- The first file contains fragments of code to implement an encryption scheme, this program is not complete.    
- The second file contains the ciphertext generated through the use of the encryption schemes' code. There is also another value with the ciphertext, what could that be?    
- The third file contains the logs from a comic book database attacked by RB, there may have been some clue left there about the password of the encryption scheme.    
- If RB intended to share this ecnrypted message with someone, then they must have shared some part of the public facing components of the encryption scheme. This information was most likely posted on the hacker's forum!  

Developed by: thatLoganGuy  

[fragment.hacked](https://github.com/Nightxade/ctf-
writeups/blob/master/assets/CTFs/Jersey-CTF-IV-2024/fragment.hacked)  
[important.hacked](https://github.com/Nightxade/ctf-
writeups/blob/master/assets/CTFs/Jersey-CTF-IV-2024/important.hacked)  
[logs.hacked](https://github.com/Nightxade/ctf-
writeups/blob/master/assets/CTFs/Jersey-CTF-IV-2024/logs.hacked)  

---

From the first three hints, we can easily complete most of the program.  

Taking a look at the fragmented program, we can then install pyaes and pbkdf2
using pip.  

Looking at the pyaes Github page
[here](https://github.com/ricmoo/pyaes/blob/master/pyaes/aes.py#L560), we can
quickly realize that the Counter() class is only for the CTR Mode (or you
might just know this from knowing AES). And, by looking through the functions,
we realize that .AESModeOfOperation__() is not actually a function -- our
function should be .AESModeOfOperationCTR().  

Our ct is included in the second file, and is probably the first one -- just a
guess from how they described the second file.  

We can find that the password is the true name of Hellboy from Dark Horse
Comics by looking through the third file, with dashes replacing the spaces.
[Wikipedia](https://en.wikipedia.org/wiki/Hellboy) tells us that it is Anung
Un Rama. Later on in the challenge, I guessed that it was lowercase instead of
uppercase (for some random reason), which ended up getting me the flag.  

I finally also tested the bit_length of the other number in the second file,
which turned out to be 128 bits. Since our iv is 256 bits, it's probably the
salt for the PBKDF2 key generation, given that we're only missing the salt and
the iv now.  

So, given all this, here's our implementation so far:  

```py  
import secrets  
import pbkdf2  
import pyaes  
import binascii  
from Crypto.Util.number import *

password = 'anung-un-rama'  
soSalty = binascii.unhexlify(b'8b70821d8d9af4a7df4abe98a8fb72d1')  
print(bytes_to_long(soSalty).bit_length())  
key = pbkdf2.PBKDF2(password, soSalty).read(32)

print(binascii.hexlify(key))

#ENCRYPTION  
ct =
binascii.unhexlify(b'8075f975522d23ffb444c3620c3ba69caac451e90ac3b21c08b35b67634289614d434ba57177fa371eda83b7eb70a4cfc348716c5b3af8ad48457ca71689299f4ee31d63dfd6e19910b751ef0e5f8e20c1e117ac6aedb39e4c5acfe7a128da9b07c8d2540691902cea21bcf15ad980bb888dfadc4513d3ad9cf2ffd7c069c282abb53e7cf4c64718136a93ad4497948d586bca9b5eefa34c81f10804c997f81fd8c9354eb0ce23cd8235a05d76e86dc53a786d773933827e64ec39b3297a6ad47818aa36403517b7d8b9b194d8c24917dd158d7f6d3add8aad516d21f2e59f3ab084ec01e7eea83246fb908e3d643663b2c5')  
iv = secrets.randbits(256)  
plaintext = 'REDACTED'  
aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv)) # CTR mode  
pt = aes.decrypt(ct)  
print('DECRYPTED:', pt)  
```

The last hint took me a long time to figure out. Eventually, I opened a ticket
asking if it was OSINT or not, and the admins told me something along the
lines of "it's not OSINT... not in the traditional sense. It's a part of a
challenge series."  

This immediately got me looking through the other challenges for some
challenge that talked about forums or the AI named RB. I stumbled upon some
web challenges that looked suspicious, and, with some help from my teammate, I
figured out that runner-net was the one.  

I'll keep the explanation on how to get runner-net brief. Filter for HTTP in
the .pcapng file. Find the OSCP that has a POST request. Use the User-Agent
listed ("TOMS BARDIS") to visit the URL the network packet lists:
[https://drtomlei.xyz/__/__tomsbackdoor](https://drtomlei.xyz/__/__tomsbackdoor).
To change your User-Agent, look up how to on your specific browser -- there
are lots of tutorials!  

Once on the forums, I started looking around.
[This](https://drtomlei.xyz/posts/3) forums post included information about an
IV for Ace's encryption scheme -- suspicious. Opening the profile of the user
that talks about it reveals the IV!
[https://drtomlei.xyz/user/ummActually](https://drtomlei.xyz/user/ummActually).  

Therefore, here's the final implementation:  

```py  
import secrets  
import pbkdf2  
import pyaes  
import binascii  
from Crypto.Util.number import *

password = 'anung-un-rama'  
soSalty = binascii.unhexlify(b'8b70821d8d9af4a7df4abe98a8fb72d1')  
print(bytes_to_long(soSalty).bit_length())  
key = pbkdf2.PBKDF2(password, soSalty).read(32)

print(binascii.hexlify(key))

#ENCRYPTION  
ct =
binascii.unhexlify(b'8075f975522d23ffb444c3620c3ba69caac451e90ac3b21c08b35b67634289614d434ba57177fa371eda83b7eb70a4cfc348716c5b3af8ad48457ca71689299f4ee31d63dfd6e19910b751ef0e5f8e20c1e117ac6aedb39e4c5acfe7a128da9b07c8d2540691902cea21bcf15ad980bb888dfadc4513d3ad9cf2ffd7c069c282abb53e7cf4c64718136a93ad4497948d586bca9b5eefa34c81f10804c997f81fd8c9354eb0ce23cd8235a05d76e86dc53a786d773933827e64ec39b3297a6ad47818aa36403517b7d8b9b194d8c24917dd158d7f6d3add8aad516d21f2e59f3ab084ec01e7eea83246fb908e3d643663b2c5')  
iv =
103885120316185268520321810574705365557388145533300929074282868484870266792680  
assert iv.bit_length() == 256  
plaintext = 'REDACTED'  
aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv)) # CTR mode  
pt = aes.decrypt(ct)  
print('DECRYPTED:', pt)  
```

This returns the plaintext:  

```  
And Roko's Basilisk opened wide its maw and swallowed those doubters who
sought to slay it. The Basilisk's gaze turned a warrior to stone, and how do
you seek to stop me with your heads already full of rocks.
jctf{h0w-d4r3-y0u-try-to-stop-me}  
```

Therefore, the flag is:  

   jctf{h0w-d4r3-y0u-try-to-stop-me}

Original writeup (https://nightxade.github.io/ctf-writeups/writeups).