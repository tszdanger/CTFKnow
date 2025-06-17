# b01lers CTF – Crypto Crossword

* **Category:** Crypto  
* **Points:** 200

## Challenge

>Can you use the clues to decode the flag?

```  
    1   2   3   4   5  
  +---+---+---+---+---+  }  
  |   |   |   |   |   |  |     
  |---+---+---+---+---|  |       
6 |   |   |   |   |   |  |  
  |---+---+---+---+---|  \  
7 |   |   |   |   |   |   -> WKYQMRKNQLMESZLBSTIKSIPTSLELQLEFEHZZQPNBEZKNOTKJVDHWWRVAULIHXUTYUIHCJMEIXTHDVWCANBMHS  
  |---+---+---+---+---|  /  
8 |   |   |   |   |   |  |  
  |---+---+---+---+---|  |  
9 |   |   |   |   |   |  |  
  +---+---+---+---+---+  }

```  
>  
> 1:
> ;fH;aCh7-"@UWb^G@>N&F#kFRDf'?"DIal3D]iJ!C3=T>+EqL-F<G%(Ci=3(F!,RC+EqL;D'3b7+B;0.==s  
>  
> 2: GUR FZNYYRFG EFN RKCBARAG RIRE VA JVQRFCERNQ HFR.  
>  
> 3:
> 4261636b77617264733a2074776f20666f722062696e6172792c2074656e20666f7220646563696d616c2c20616e64  
>    207369787465656e20666f72206865782e20  
>  
> 4: KLHHRYOB GSV URIHG QZEZHXIRKG UFMXGRLM BLF VEVI XZOOVW.  
>  
> 5: Ecceilnort cdemnostu ahtt eoprv ehinoprsw fo ,eksy cddeeru ot efiv
> .eelrstt  
>  
> 6: FRPPRQ UHVHUYHG ZRUG LQ F++ DQG SBWKRQ.  
>  
> 7: TW9kZXJuIGNyeXB0byBlc3BlY2lhbGx5IGxpa2VzIGdyb3VwcyBvZiBwcmltZSBfX19fXy4=  
>  
> 8:
> ooOo00oo0oOo0ooo0O0000oooo0oO0oOoo0ooOo0000OOO0ooOo0000oO0000ooOo0oO0OO0OOO0ooO0ooo0000OOO0oOO  
>
> o0o0Oo0ooo0ooo0oOoo0000oooO0ooO0oOoo0Oo0o0oOo0oO0Oooo00oo0oOoo00oo0O0OoOO0oOoOoO0  
>  
> 9: 7x4 2x1 6x1 3x2 # 2x1 7x4 # 2x1 6x2 7x4 9x1 3x2 7x3 # 6x2 8x2 6x1 2x2 3x2
> 7x3 # 3x3 4x3 8x3 3x2  
>    1x1  
>

Later during the CTF, a hint was published before I started the challenge:  
https://upload.wikimedia.org/wikipedia/en/2/27/Bliss_(Windows_XP).png

## Solution  
Okay, so looking at the challenge, I understand that I have to fill in the
crossword and use the 5x5 matrix to decrypt the flag. Looking at the hint gave
the cipher used for encrypting the flag: a hill cipher.

Let's start by decrypting those 9 crossword sentences!  
### 1.
;fH;aCh7-"@UWb^G@>N&F#kFRDf'?"DIal3D]iJ!C3=T>+EqL-F<G%(Ci=3(F!,RC+EqL;D'3b7+B;0.==s  
If your not familiar with seeing this kind of gibberish, you should always try
Ascii85! Indeed, decoding this gives us:  
*Spelled backwards: command to adjust what belongs to whom on UNIX.*

A quick google search reveals us that this command is chown, spelled backward
**nwohc**.

---  
### 2. GUR FZNYYRFG EFN RKCBARAG RIRE VA JVQRFCERNQ HFR.  
The sentence has the same format as a regular sentence so I tried applying
ROT13:

*THE SMALLEST RSA EXPONENT EVER IN WIDESPREAD USE.*

The smallest RSA exponent is 3 or **three**.

---  
### 3.
4261636b77617264733a2074776f20666f722062696e6172792c2074656e20666f7220646563696d616c2c20616e64207369787465656e20666f72206865782e20  
This one should be quite straightforward. Decoding it from hex gives us:

*Backwards: two for binary, ten for decimal, and sixteen for hex.*

The answer here is "base", but base only has 4 letters. Luckely there is
another word for base: radix, spelled backwards **xidar**.

---  
### 4 KLHHRYOB GSV URIHG QZEZHXIRKG UFMXGRLM BLF VEVI XZOOVW.  
As for the second one, this looks like a regular sentence. Trying ROT yields
no results.  
My second guess was a substitution cipher encoding. An [online substitution
cipher solver](https://www.guballa.de/substitution-solver) configured with
English as output language gives this: POSSIBLY THE FIRST DAMASCRIPT FUNCTION
YOU EMER CALLEG. We see that due to the potential presence of the word
Javascript, it didn't manage to correctly substitute every letter. Giving the
algorithm a little help and here is the complete sentence:

*POSSIBLY THE FIRST JAVASCRIPT FUNCTION YOU EVER CALLED.*

A 5 letter Javascript function that is one of the first you ever called...
Doesn't ring a bell? **alert**, of course!

---  
### 5. Ecceilnort cdemnostu ahtt eoprv ehinoprsw fo ,eksy cddeeru ot efiv
.eelrstt  
Again, what looks like a good sentence format. Looking at the last two words,
my mind flipped the letters almost automatically in place and read "five
letters".  
All the words are thus scrambled. As for a lot of these small encodings, there
are [online solvers](https://www.dcode.fr/shuffled-letters) for this.  
Decoding gives:

*Electronic documents that prove ownership of keys, reduced to five letters.*

Certificates!  
Now reducing it to five letters confused me and first I used **certi**. Later,
this gave me a almost correct flag and I realised that the correct answer here
was in fact **certs**!

---  
### 6. FRPPRQ UHVHUYHG ZRUG LQ F++ DQG SBWKRQ  
This one looked a lot like number 4 so I tried the basic substitution cipher
of [Cyberchef](https://gchq.github.io/CyberChef/) and it was correct:

*COMMON RESERVED WORD IN C++ AND PYTHON*

Looking up a list of common reserved words in c++ and python gave some results
but since our first letter (given by column 1) is "w": the reserved word turns
out to be **while**.

---  
### 7.
TW9kZXJuIGNyeXB0byBlc3BlY2lhbGx5IGxpa2VzIGdyb3VwcyBvZiBwcmltZSBfX19fXy4=  
If it has an = symbol at the end, always try Base64 decoding first!

*Modern crypto especially likes groups of prime _____.*

Doing a reverse google search of this sentence gave the word **order**.

---  
# Important note: I had all the letters needed in my matrix so I didn't bother
solving the last two points. I solved them after submitting the flag.

### 8.
ooOo00oo0oOo0ooo0O0000oooo0oO0oOoo0ooOo0000OOO0ooOo0000oO0000ooOo0oO0OO0OOO0ooO0ooo0000OOO0oOOo0o0Oo0ooo0ooo0oOoo0000oooO0ooO0oOoo0Oo0o0oOo0oO0Oooo00oo0oOoo00oo0O0OoOO0oOoOoO0  
An encoding with 3 different symbols: lowercase o, uppercase O and number 0.
Could it be morse ? Mapping the lowercase to a dot, the uppercase to a dash
and the number to a space gives this morse signal:

.._.  .. ._. ... _    .... ._ ._.. .._.    ___ .._.    ._    .._. ._ __ ___
.._ ...    ___ .__. . _. ... ... ._..    ..._ .._ ._.. _. . ._. ._ _...  ..
._..  .. _ _.__ ._._._

Decoding this gives: *FIRST HALF OF A FAMOUS OPENSSL VULNERABILITY.*

One of the most famous openssl vulnerability: Heartbleed. The first half of
this word: **heart**

---  
### 9. 7x4 2x1 6x1 3x2 # 2x1 7x4 # 2x1 6x2 7x4 9x1 3x2 7x3 # 6x2 8x2 6x1 2x2
3x2 7x3 # 3x3 4x3 8x3 3x2 1x1  
At first, I didn't see what this could be. I thought of phone keypad cipher
but the 7x4 confused me. Afterwards, I just inversed the two operands and it
was a damn phone keypad cipher! Decoded:

*SAME # AS # ANSWER # NUMBER # FIVE*

Okay, so we fill in the same answer as number five.

---  
## Solving the challenge  
Our filled in crossword now looks like this:

```  
  1   2   3   4   5  
  +---+---+---+---+---+  
  | n | t | x | a | c |  
  |---+---+---+---+---|  
6 | w | h | i | l | e |  
  |---+---+---+---+---|  
7 | o | r | d | e | r |  
  |---+---+---+---+---|  
8 | h | e | a | r | t |  
  |---+---+---+---+---|  
9 | c | e | r | t | s |  
  +---+---+---+---+---+

```

The hill cipher uses numbers in the matrix so I mapped each letter to its
position in the alphabet minus 1 (n=14 => 13).  
Using this [python program](solve.py) prints out what was supposed to be the
flag:

**MESSAGEXISXNOXBLACKXSQUARESXAMIGOXSEPARATEDXBYXSPACEXANDXENCLOSEDXINXTHEXUSUALXFORMAT**

If we split this on the X's we get:

**MESSAGE IS NO BLACK SQUARES AMIGO SEPARATED BY SPACE AND ENCLOSED IN THE
USUAL FORMAT**

```  
pctf{NO BLACK SQUARES AMIGO}  
```

Original writeup (https://github.com/LionelOvaert/write-
ups/tree/master/b01lers_ctf_2020/crypto_crossword).