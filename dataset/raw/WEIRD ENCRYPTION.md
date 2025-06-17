# WEIRD ENCRYPTION  
> Points: 377

## Description  
> I made this weird encryption I hope you can crack it.  
>  
>[File](https://mega.nz/file/rt1GiIhb#YZzFsf07O-BVKugJSJoRQkazgs6I_pLMD_zISg6VGt0)  
>  
>[File](https://mega.nz/file/rt1GiIhb#YZzFsf07O-BVKugJSJoRQkazgs6I_pLMD_zISg6VGt0)

## Solution  
The easiest challenge. Just a little logic!

I wrote a script to get the index value of each characters of the ciphertext
from the given `main_string` and store them in a list.

For each letter there existed a pair : **quotient** `c1` and **remainder**
`c2` in the list respectively.

From the script it's clear the divisor in the case is 16 and what we need is
the dividend **ASCII value of letter** and convert it to character.

So I apply a simple arithmetic : **dividend = divisor * quotient + remainder**
to find ASCII values, convert them to character and finally get the text back.

```py  
#!/bin/env python3

with open("Encrypted", "r") as f:  
	ct = f.read().replace("\n", "")

main_string="c an u br ea k th is we ir d en cr yp ti on".split()

st = []  
flag = []  
ch = ""  
i = 0

# To make a list st containing index of characters from main_string  
while i<len(ct):

	if (ct[i]=='c' and ct[i+1]!='r') or ct[i]=='u' or ct[i]=='k' or ct[i]=='d':  
		ch = main_string.index(ct[i])  
		i += 1  
	else:  
		ch = main_string.index(ct[i:i+2])  
		i += 2  
	st.append(ch)

# Calculating ASCII values and converting into character  
for i in range(0,len(st),2):  
	flag.append(chr(16*st[i]+st[i+1]))  
print(''.join(flag))  
```

## Flag  
> Hello. Your flag is DarkCTF{0k@y_7h15_71m3_Y0u_N33d_70_Br3@k_M3}.

Original writeup (https://github.com/t3rmin0x/CTF-
Writeups/tree/master/DarkCTF/Crypto/WEIRD%20ENCRYPTION).