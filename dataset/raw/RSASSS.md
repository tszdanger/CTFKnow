# RSASSS

**Category**: Crypto \  
**Points**: 493 (13 solves) \  
**Author**: A1y

## Challenge

NOTE: You will need to add  
541893472927304311696017462663852715895951883676838007787557872016428N to the  
plaintext to recover the message after decrypting.

Hello Mister H,

I heard that you're one of the city's best private investigator, and I have a  
job for you. My father, who was a very wealthy man, had recently passed away  
(God rest his soul). Unfortunately, he was also a very traditional man. He  
decided to leave everything to his 3 sons, and NOTHING for ME! ME! The person  
who was by his sides taking care of him during his last days! ME! The person  
who stayed at home to take care of everything while his 3 sons went out to
play  
around the world. Anyways, that is why I have decided to take back what should  
be rightfully mine! I took a peak at the will, and know that my father gave  
each of my brother a piece of the puzzle, and only by using all 3 pieces can I  
get the final key, in the format of "bctf{......}". (I think the bctf stands  
for bank certified transaction form or something). Anyways, I made copies of  
all 3 pieces that were given to my brother, and have included them here.  
Additionally, I found a piece of paper that said:

```  
RSA  
@S@  
@S@  
```

Maybe it means something to you?  
> NO IT FUCKING DOESN'T

Finally, I overheard something about how the piece of the key belonging to my  
second brother starts with something like "28322C".

Please help me!

Sign, \  
Miss A1y

Attachments: `RSASSS.zip`

## Overview

We have three text files: `son1.txt`, `son2.txt`, and `son3.txt`.

## Solution

### Part 1

Large N and small e so the ciphertext probably didn't wrap around the modulus.
Just take the e-th root to get the plaintext:  
```python  
N =
97047969232146954924046774696075865737213640317155598548487427318856539382020276352271195838803309131457220036648459752540841036128924236048549721616504194211254524734004891263525843844420125276708561088067354907535207032583787127753999797298443939923156682493665024043791390402297820623248479854569162947726288476231132227245848115115422145148336574070067423431126845531640957633685686645225126825334581913963565723039133863796718136412375397839670960352036239720850084055826265202851425314018360795995897013762969921609482109602561498180630710515820313694959690818241359973185843521836735260581693346819233041430373151  
e = 3  
ct =
6008114574778435343952018711942729034975412246009252210018599456513617537698072592002032569492841831205939130493750693989597182551192638274353912519544475581613764788829782577570885595737170709653047941339954488766683093231757625

pt1 = find_root(ct, e)  
pt1 = cun.long_to_bytes(pt1).decode()  
print(pt1)  
```

Part 1: `(1, 132156498146518935546534654)`

### Part 2

This one is more interesting: `e` and `phi` aren't coprime, which makes  
calculating `d` not possible.

The solution is to calculate some `lam` (should be `lambda`, but that's a  
keyword in python) so that `lam` and `e` are coprime. In this case we can do  
`lam = phi // 128` and use the `lam` as our new `phi`.

Then do:  
```python  
d = cun.inverse(e, lam)  
first_pt = pow(ct, d, N)  
```

This doesn't give us the plaintext, but it does satisfy  
`ct == pow(first_pt, e, N)`. To calculate the rest of the possible plaintexts,  
we can do this:

```  
Let pt be an arbitrary plaintext.

pt^e == ct  (mod N)

(pt * x)^e == ct  (mod N)  
pt^e * x^e == ct  (mod N)  
x^e == 1  (mod N)  
```

If we can find all `x` satisfying `x^e == 1`, then we can recover all the
other  
plaintexts.

Actually `x` is called a  
[Root of unity modulo
n](https://en.wikipedia.org/wiki/Root_of_unity_modulo_n).  
We can calculate these using the method described in section "Finding multiple  
primitive k-th roots modulo n". I ended up a using a dumber method:  
```python  
uns = set()  
i = 1  
while len(uns) < 128:  
   un = pow(i, lam, N)  
   uns.add(un)  
   i += 1  
```

Finally we can use the hint to pick out the correct plaintext (or we can check
if they decrypt to ASCII):  
```python  
pt2 = None  
pts = [(un * first_pt) % N for un in uns]  
pts = [hex(pt) for pt in pts]  
for pt in pts:  
   if "0x28322" in pt:  
       pt = int(pt, 16)  
       pt2 = cun.long_to_bytes(pt).decode()  
       break  
```

Part 2: `(2, 861352498496153254961238645321268413658613864351)`

## Part 3

N is only 202 bits and its factors can be found on
[factordb](http://factordb.com/index.php?query=3213876088517980551083924185487283336189331657515992206038949)

Part 3: `(3, 3145756504701717246281836139538967176547517737056)`

## Final step

Ok so we we have:  
```  
(1, 132156498146518935546534654)  
(2, 861352498496153254961238645321268413658613864351)  
(3, 3145756504701717246281836139538967176547517737056)  
```

That's cool and all, but WHERE THE FUCK IS THE FLAG?? It probably had
something  
to do with this weird hint:  
```  
RSA  
@S@  
@S@  
```

WTF DOES THIS EVEN MEAN? I ended up asking the admin, who gave me the hint
that  
RSA and SSS share the same S. My teammate Leah figured out that it  
stood for Shamir Secret Sharing.

```python  
import shamir  
res = shamir.recover_secret([a, b, c], prime=cun.getPrime(512))  
print(cun.long_to_bytes(res).decode())  
```

Flag (full script in `solve.py`):  
```  
bctf{Mr._Ad1_5ham1r}  
```  

Original writeup (https://github.com/cscosu/ctf-
writeups/tree/master/2021/b01lers_ctf/RSASSS).