# Magically Delicious ![badge](https://img.shields.io/badge/Post%20CTF-
Writeup-success)  
> 100 points  
  
> Solved by r3yc0n1c

## Description  
> Can you help me decipher this message?  
  
> ⭐?? ⭐?? ⭐?? ⭐?? ⭐?? ⭐?? ⭐?? ⭐?? ⭐?⭐ ?? ⭐?? ⭐?? ⭐?? ⭐?⭐ ⭐?? ?? ⭐?? ⭐?? ⭐??
> ⭐?? ⭐?? ⭐?⭐ ⭐?? ⭐?? ?? ⭐?⭐ ⭐?? ?? ⭐?? ⭐?? ⭐?? ?? ⭐?? ⭐?? ⭐?? ⭐?? ?? ⭐?? ⭐??
> ⭐?? ⭐?? ⭐?? ⭐?⭐ ⭐?? ⭐?? ?? ⭐?? ⭐?? ⭐?? ⭐?? ⭐?? ⭐?? ⭐??  
>  
> Note: If you don't see a message above, make sure your browser can render
> emojis.  
  
> Tip: If you're digging into the unicode encoding of the emojis, you're on
> the wrong track!

## Solution  
###  Encription  
* **ASCII** -> **Octal Number** -> **Each Digit** -> **Emoji**  
### Decryption  
* **Emoji** -> **Octal Digit** -> **Octal Number** -> **Emoji**

### Script - [emojidecoder.py](emojidecoder.py)  
```py  
from itertools import *

cipher = "⭐?? ⭐?? ⭐?? ⭐?? ⭐?? ⭐?? ⭐?? ⭐?? ⭐?⭐ ?? ⭐?? ⭐?? ⭐?? ⭐?⭐ ⭐?? ?? ⭐??
⭐?? ⭐?? ⭐?? ⭐?? ⭐?⭐ ⭐?? ⭐?? ?? ⭐?⭐ ⭐?? ?? ⭐?? ⭐?? ⭐?? ?? ⭐?? ⭐?? ⭐?? ⭐?? ??
⭐?? ⭐?? ⭐?? ⭐?? ⭐?? ⭐?⭐ ⭐?? ⭐?? ?? ⭐?? ⭐?? ⭐?? ⭐?? ⭐?? ⭐?? ⭐??".split(' ')

"""  
Brute-force these emojis for the correct octal code  
?,?,? : (0,2,4)  
"""

def breakit(emap):  
	flag = ''  
	for chunk in cipher:  
		octcode = ''					  
		for emoji in chunk:  
			octcode += emap[emoji]  
		flag += chr(int(octcode, 8))	# octal code to ASCII i.e., 163 = 's'  
	print(flag)

def makeit():  
	emomap = {  
	'⭐' : '1',  
	'?' : '6',  
	'?' : '3',  
	'?' : '5',  
	'?' : '7'  
	}

	# permutations of emoji and relative numbers  
	numperms = permutations(['0','2','4'])  
	emo = ['?','?','?']

	for nums in numperms:  
		temp = {}  
		for i in range(len(nums)):  
			temp[emo[i]]=nums[i]  
		emomap.update(temp)  
		# try to break it with every possible emoji-maps  
		breakit(emomap)

if __name__ == '__main__':  
	makeit()  
```  
### Output  
```zsh  
┌──(root ? kali)-[~/Downloads/sun]  
└─# python3 emojidecoder.py  
sun{huCky-oCpAh-EnCo@inG-is-pjE-DEsp-EnCo@inG-mEpjo@}  
sun{huCky-oCpAh-EnCo@inG-is-plE-BEsp-EnCo@inG-mEplo@}  
sun{juSky-oSrQj-UnSoRinW-is-rhU-TUsr-UnSoRinW-mUrhoR}  
sun{juSky-oSrQj-UnSoRinW-is-rlU-PUsr-UnSoRinW-mUrloR}  
sun{lucky-octal-encoding-is-the-best-encoding-method}  
sun{lucky-octal-encoding-is-tje-`est-encoding-metjod}  
```  
## Flag  
> **sun{lucky-octal-encoding-is-the-best-encoding-method}**  

Original writeup (https://github.com/t3rmin0x/CTF-
Writeups/tree/master/SunshineCTF2020/crypto/Magically_Delicious#magically-
delicious-).