# Skywriting v2

## Description

Fortnite Battle Royale contains a variety of weapons and this page lists every
weapon in Fortnite along with their weapon stats like damage, DPS, fire rate,
magazine size, and reload speed.

Note: This was a throwback to the original skywriting which included many big
leaps of intuition.

This problem has now been modified to make it more doable.

Hint 1: I like xoring together the names of "Rifle"s together.

Hint 2: Try googling the first sentence of this problem.

Flag: LjUlMiA9LxI1GTUTNiodECAtUSx5YxY4

## Solution

I solved this challenge in a quite strange [way](wtf.py).

I thought that because the encrypted flag was xored by the keys, it's not
likely that all of the characters were printable.

So first I decoded it with base64.

```  
>>> base64.b64decode('LjUlMiA9LxI1GTUTNiodECAtUSx5YxY4')  
b'.5%2 =/\x125\x195\x136*\x1d\x10 -Q,yc\x168'  
```

Because the flag's first word is 'h', I calculated which number should '.' xor
to become 'h' and xored the whole string with it.  
```  
>>> b = b''  
>>> xor = a[0] ^ ord('h')  
>>> for i in range(24):  
>>>     b += chr(a[i] ^ xor)  
>>> print(b)  
hsctf{iTs_sUpl[Vfk\x17j?%P~  
```  
Surprisingly, the flag's format popped out.

Next, I guessed the second word would be 'sUper' and cauculted which number
should 'l' xor to become 'e'.

This time, only the characters after 'l' were xored by this number.

```  
>>> c = ''  
>>> xor = ord(b[13]) ^ ord('e')  
>>> for i in range(24):  
>>>     if i < 13:  
>>>         c += b[i]  
>>>     else:  
>>>         c += chr(ord(b[i]) ^ xor)  
>>> print(c)  
hsctf{iTs_sUpeR_ob\x1ec6,Yw  
```  
It seemed promising, doing the same guessing thing several times, I recovered
the flag to  
```  
hsctf{iTs_sUpeR_obG:ouS}  
```  
It's super obvious that the answer is 'iTs_sUpeR_obviouS'. (ˊωˋ)

But I didn't know the cases of 'v' and 'i'. Guessing the flag on the server
gave me the answer.

```  
hsctf{iTs_sUpeR_obViouS}  
```

Also, I figured out the intended [solution](solve.py) after the ctf ended.  

Original writeup (https://github.com/kuruwa2/ctf-
writeups/tree/master/HSCTF%206/Skywriting%20v2).