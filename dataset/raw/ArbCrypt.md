# Crypto  
I don't know why, but crypto challenges are always fun for me.  
  
  
  
  
## 50 points: WelcomeCrypto  
```  
~C8 =39 A?2V8 73J:C 8FG7 AF?JJC2ECP

DF?LHb=r_>b0%_0520<c8bPN

Author: Loavso  
```  
I'm pretty embarassed this took me as long as it did. I didn't recognize the
cipher right away, but its just a ROT47. Use any <a
href='https://www.dcode.fr/rot-47-cipher'>online decoder you want. The one I
used outputted:  
```  
Org lbh pna'g fbyir guvf punyyratr!

sun{w3lC0m3_T0_da_k4g3!}  
```  
Literally no clue what the first line was supposed to be, but the flag was
valid.

flag: `sun{w3lC0m3_T0_da_k4g3!}`

*Edit*: The first line is a ROT13 after the ROT47: `Bet you can't solve this challenge!` Why they would make the flavor text another step, I have no idea.  
  
  
  
  
  
  
## 50 points: CB1  
```  
We picked up a new numbers station that's been active in the shortwave bands.
We need to figure out how to crack his code.

Here's an example file, crack the cipher and send us the plaintext message.

```  
CB1.wav  
```

NOTE: NON-Standard Flag Format

Author: leviathan  
```  
When I saw this, I thought it would be an audio steganography challenge. But
let's give it a listen! I transcribed:  
```  
Code Number: 6  
Begin Message  
Hotel Kilo Charlie Golf Xray Kilo Zulu November Kilo Oscar Juliette Kilo
Yankee Uniform Lima Sierra Golf Xray India November  
```  
It just repeated after that. The words immediately stood out to me as the NATO
Phonetic Alphabet; it's just the first letter of each word.  
```  
6  
HKCGXKZNKOJKYULSGXIN  
```  
6 seems to suggest a Caesar Cipher. I used this site to decode it with a shift
of 6, and got the flag. The flag was in a nonstandard format, as was said by
the description.

flag: `bewaretheidesofmarch`  
  
  
  
  
  
  
## 100 points: CB2  
```  
That numbers station is still active, they've just switched codes. We need you
to crack it before they switch again.

Here's an example file, crack the cipher and send us the plaintext message.  
```  
CB2.wav  
```  
NOTE: NON-Standard Flag Format

Author: leviathan  
```  
Another audio file. Transcription (already using the NATO Phonetic Alphabet to
replace to letters):  
```  
Codeword: Clarinet  
DBDAABEDDDDCDEACADBBDDADDEABBB  
```  
I got stuck on this one for a while. The key point to notice is that there are
only 5 characters, A-E. So, searching 'Cipher 5 unique letters' this website
popped up. It suggested that it was a polybius square cipher. I used dcode
once again.

![](/Images/2019/SunshineCTF/CB2.PNG)

I entered in the key of CLARINET, chose the no 'j' alphabet for the rest of
the deranged alphabet, and changed 1-5 to A-E. The website has an explanation
for how Polybius works and its pretty simple. The website did its work and
outputted the flag, albeit in uppercase.

flag: `polysquaresrule`

## 100 points: 16-bit-AES  
```  
Why so small?

nc aes.sunshinectf.org 4200

Author: ps_iclimbthings  
```  
This challenge was released at around 13:00 EST on the last day of the
competition that would end at 21:00 EST. Luckily it didn't take too long. It's
an AES challenge, obviously, but the twist was that it used a 16 bit key for a
AES-128 encryption. Running the netcat command gets you:

![](/Images/2019/SunshineCTF/AESnc.PNG)

Okay, so it seems that you get to give it some text, and it outputs the
resulting encrypted version. Pretty simple. Interestingly enough, running it
again confirmed that _the same key was being used each time _. In other words,
at this point there are two ways to go about doing this. I was dumb and
overthought it, so I did it the "legit way": creating a script in python.  
```  
from Crypto.Cipher import AES  
import itertools  
import string  
goal = 'f312cf9c53af89447e652e73b9754a0c'
//asdfasdfasdfasdf encoded using their key  
for combo in itertools.product(string.letters, repeat = 2):     //bash all
combinations of two letters (16 bit)  
	key = ''.join(combo) * 8                                //AES-128 requires a 16 byte key, so hopefully the key is just 8 of the 16 bit key.  
	cipher = AES.new(key, AES.MODE_ECB)  
	msg = cipher.encrypt('asdfasdfasdfasdf')  
	if msg.encode('hex') == goal:  
		print key  
		break  
```  
![](/Images/2019/SunshineCTF/aeskey.PNG)__

Nice. Run the netcat command again, use an online encoder or a python script
to encode their string, and send it back to get the flag.

![](/Images/2019/SunshineCTF/aesflag.PNG)

flag: `sun{Who_kn3w_A3$_cou1d_be_s0_vulner8ble?}`

What was the easier way you ask? Well, since the same key is used each time,
you can just open two different netcat clients, and send the requested string
from one into the input in the other, and let the netcat client do it for you.
:P I like to think mine was more sophisticated.

![](/Images/2019/SunshineCTF/aesrip.PNG)  
  
  
  
  
  
  
## 150 points: CB3  
```  
The number station has switched codes yet again. This one seems similar to the
last cipher used, but we still haven't been able to crack it.

Here's an example file, crack the cipher and send us the plaintext message.  
```  
CB3.wav  
```  
NOTE: NON-Standard Flag Format

Author: leviathan  
```  
Last one in the CB series. Transcription (already using the NATO Phonetic
Alphabet to replace to letters)::  
```  
Codeword: Prideful  
xdxgfvvvxxafvffvadgddxagaafdffff  
```  
Six unique letters: a, d, f, g, v, and x. Searching up 'Cipher six unique
letters' gives you the dumbest cipher I've ever heard of:

![](/Images/2019/SunshineCTF/whytho.PNG)

Simple enough from there. dcode once again has a decoder for this. Nice. I
used the default alphabet and put in 'Prideful' as the permutation key.

![](/Images/2019/SunshineCTF/cb3.PNG)

flag: `g3rm4n3ncrypt10n`

## 200 points: ArbCrypt  
```  
It's pretty ARB-itrary. France0110.  
```  
ciphertext.txt  
```  
Author: Mesaj2000  
```  
Apparently this one was hard enough that they added a hint for it near the end
of the competition, so I'm pretty proud of myself for figuring it out
relatively easily and before the hint. The ciphertext:  
```  
BBcEDAJCDBMIAxUHA3gQBxEXCwdCAwQPDhxCGRMNawYHBRgDDQcNBRAWGxZCABoUAHgQBREEDwIQDgtCCx8DFR4RaxwLGFIWERQVBxdCGQgPBBARChgBaxYSFRQRAgIGDQRCFxwYAgAEGXgHDhgRChQMChgDAlITDQAWFQgGQRcNFAAQQR0LGRsWAghCAhQaa3gGExwMQRMEFRkIEhQNQRUEERYRGxdCChsQBwQFGHgEFwQRGBkLCBcKQREUDgYUElIVGAJoEhUIBQQRGFIWERwWFxAYDhdoBhAOF1IPCAYOCBkYTAEFDBsJQQEHBQIQCxRoFwgXABYID1IQBgYUElIEBwEBF3gADRsEAAcYQRwUFQYUBFIKDRwDBFIaCBcEa1IRDR0ZABsBPgsEFy0KEwMSES0XDi0IBxc9BRQ9UEJSUENRUUdTWA8=  
```  
The '`=`' at the end immediately said 'base64', so I converted it. There
weren't really any printable characters, so from then on, I used cryptii for
this entire challenge, knowing that it might be multiple encryption methods.
From there, I looked at the description for hints. ARB is repeated a lot, so
that might be significant, though its not an encryption method. The next
important thing is '`France0110`'.

'`0110`' is the truth table for XOR, which is a pretty common encryption in
CTFs. It would result in the unprintables as well. XOR requires a key though,
so I used 'ARB' (in hex as '61 72 62' for cryptii). And now it has printables,
and the end even has the flag format! Nice.

There's only one part left: 'France'. Searching up 'French Cryptography'
brings up the Vigenère cipher. Oh duh! Using 'arb' as the key and the standard
alphabet order, I decoded the message. Nice challenge, pretty fun to figure
out.

![](/Images/2019/SunshineCTF/arb.PNG)

flag :`sun{arb_you_happy_to_see_me_1001130519}`

Original writeup (https://github.com/VermillionBird/CTF-
Writeups/blob/master/2019/SunshineCTF/Crypto.md).