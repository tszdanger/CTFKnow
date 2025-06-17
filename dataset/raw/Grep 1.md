## Grep 1  
![date](https://img.shields.io/badge/date-10.30.2020-brightgreen.svg)
![General category](https://img.shields.io/badge/Category-General-
lightgrey.svg) ![score](https://img.shields.io/badge/score-200-blue.svg)

### Description  
```  
Elaine hid a REGULAR flag among more than 1,000,000 fake ones! The flag was an
EXPRESSION of her love for nactf, so the first 10 characters after "nactf{"
only have the characters 'n', 'a', 'c', and the last 14 characters only have
the characters 'c', 't' and 'f'. There are 52 characters in total, including
nactf{}.  
```

### Attached files  
- flag.zip

### Solution  
Ok this challenge has a similar topic to Grep 0 except that this one will be a
bit more complex. They gave us a 72.3 MB file that contains many counterfiet
flags with the format "nactf{....}". Similar to grep 0, we are looking for a
specific pattern to find the actual flag. They've given a hint about regular
expressions when they ALL CAPS the "regular" and "expression" in the
description. In this challenge, we have to formulate a regular expression to
find patterns according to the description of the real flag.  
- First 10 characters after nactf{ only have the characters 'n', 'a', 'c'  
- Last 14 characters only have the characters 'c', 'f', and 'f'  
- There are 52 characters in total including nactf{}

So this is what I did at first:  
```  
grep
"nactf{[nac][nac][nac][nac][nac][nac][nac][nac][nac][nac]?????????????????????[ctf][ctf][ctf][ctf][ctf][ctf][ctf][ctf][ctf][ctf][ctf][ctf][ctf][ctf]}"
flag.txt  
```  
After doing some research, I found this cheat sheet:
[Link](https://www.rexegg.com/regex-quickstart.html) that helped me solve this
problem (and make it look less messy)

- []: One of the characters in the brackets should match  
- {}: How many times it should be iterated  
- .: Literally any character except a line break

```  
grep "nactf{[nac]{10}.{21}[ctf]{14}}" flag.txt  
```  
This was the correct pattern but I couldn't get it to work for some reason, so
I decided to use sublime's regular expression search on the text file. After
some debugging and playing around, I found the flag!

This took some time for me but it was worth it!

### Flag  
```  
nactf{caancanccnxfynhtjlgllctekilyagxctftcffcfcctft}  
```

Original writeup (https://github.com/JoshuEo/CTFs/tree/master/NACTF_2020).