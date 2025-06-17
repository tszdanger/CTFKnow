# Oh Sheet  
> Points: 200  
  
> Solved by r3yc0n1c

## Description  
> Someone very cheeky decided to encrypt their secret message in Google
> Sheets. What could they be hiding in plain sight?  
  
> Curious! Click on the link below to find out more:  
  
>
> [https://docs.google.com/spreadsheets/d/15PFb_fd6xKVIJCF0b0XiiNeilFb-L4jm2uErip1woOM/edit#gid=0](https://docs.google.com/spreadsheets/d/15PFb_fd6xKVIJCF0b0XiiNeilFb-L4jm2uErip1woOM/edit#gid=0)

## Solution  
### Copy and Clear  
* Make a copy of the Sheet - [Copy of Oh Sheet!](https://docs.google.com/spreadsheets/d/1aYVG9C1-bqtysSSLKuJRA3WoekFO-fTpDww_Lt8VeII/edit?usp=sharing) (without formatting)  
* Clear the formatting [ Format > Clear Formatting ] because they hid some texts by changing the text color to white.  
### The Encryption  
* It uses the Special Functions (e.g. **MID**, **INFERIOR**, **FIND**, etc.) in Google Sheet to encrypt the plaintext.  
* Refer to the [script](apex.py) for details.  
### Decryption  
* Generate the keyspace and try all combos.  
* My python script ([apex.py](apex.py)) to decrypt it.  
### Output  
* I used [pypy3](https://www.pypy.org/) for the first time on windows 10 machine to do this brute-force [[it's relatively faster](https://stackoverflow.com/questions/59050724/whats-the-differences-python3-and-pypy3#:~:text=On%20a%20suite%20of%20benchmarks,in%20beta%2C%20targets%20Python%203.)]

```cmd  
C:\Users\rey\Desktop\pypy3.7-v7.3.2-win32>pypy3.exe C:\Users\rey\Desktop\x.py

[+] Generating keyspace...

['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
'p', 'q', 'r', 's', 't']  
['q']  
['b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']  
['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
'p']  
['f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
'u', 'v', 'w', 'x', 'y', 'z']  
['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n']  
['c']  
['q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']  
['d', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

[+] Starting Brute-force...  
kqjarbcsd -> y hovk evoppogxarlo -> 19  
kqjarbcse -> y hovk etoppogxarjo -> 19  
kqjarbcsf -> y hovk eroppogxarho -> 19  
kqjarbcsg -> y hovk epoppogxarfo -> 19  
kqjarbcsh -> y hovk enoppogxardo -> 19  
. . . . . . . . . . . . . . . . . . . .  
. . . . . . . . . . . . . . . . . . . .  
. . . . . . . . . . . . . . . . . . . .  
tqzpyncxl -> g bkhm ufwpjkszahvw -> 19  
tqzpyncxm -> g bkhm udwpjkszahtw -> 19  
tqzpyncxo -> g bkhm uzwpjkszahpw -> 19  
tqzpyncxr -> g bkhm utwpjkszahjw -> 19  
tqzpyncxs -> g bkhm urwpjkszahhw -> 19  
C:\Users\rey\Desktop\pypy3.7-v7.3.2-win32>pypy3.exe C:\Users\rey\Desktop\x.py
> flag.txt  
```  
## Find a needle in a haystack  
* The haystack - [flag.txt](flag.7z)  
* The Sheet hinted - `Note that the key consists of lowercase letters, and has no repeated letters. It is 9 characters long. Order of characters matters!`. I searched  
for **1 letter words in english** and found ***i*** and ***a*** (makes sense!)  
* Searched for ***i*** related strings and the first result was `sqjarbctd -> i hovk cvyppogxaply -> 19`.  
* Made a wild guess that the plaintext may be `i love cryptography` and got the key `squarectf`.

## Flag  
> **flag{squarectf}**  

Original writeup (https://github.com/t3rmin0x/CTF-
Writeups/blob/master/SquareCTF_2020/Oh%20Sheet/README.md#oh-sheet).