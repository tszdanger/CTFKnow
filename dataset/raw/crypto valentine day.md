# LACTF 2023

## valentines-day

> Happy Valentine's Day! I'm unfortunately spending my Valentine's Day working
> on my CS131 homework. I'm getting bored so I wrote something for my
> professor. To keep it secret, I encrypted it with a Vigenere cipher with a
> really long key (161 characters long!)  
>  
> As a hint, I gave you the first part of the message I encrypted. Surely, you
> still can't figure it out though?  
>  
> Flag format is lactf{xxx} with only lower case letters, numbers, and
> underscores between the braces.  
>  
> Author: AVDestroyer  
>  
> [`intro.txt`](https://raw.githubusercontent.com/D13David/ctf-
> writeups/main/lactf24/crypto/valentines_day/intro.txt)  
> [`ct.txt`](https://raw.githubusercontent.com/D13David/ctf-
> writeups/main/lactf24/crypto/valentines_day/ct.txt)

Tags: _crypto_

## Solution  
The desription gives pretty much anything away. The given text is encrypted
via [`Vigenère cipher`](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)
using a 161 character long key. There are
[`tools`](https://www.guballa.de/vigenere-solver) that can easily reconstruct
such a key in a short amount of time but we have the first sentence given as
plain text, so we can just try to reconstruct the key ourself.

```python  
ct = open("ct.txt", "rb").read()  
t  = open("intro.txt", "rb").read()

key = []  
for i in range(len(t)):  
   if (t[i] >= ord('a') and t[i] <= ord('z')) or (t[i] >= ord('A') and t[i] <=
ord('Z')):  
       key.append((ct[i]-t[i] + 26) % 26)

key.extend([0]*(161-len(key)))

for c in key: print(chr(c+ord('a')), end="")  
```

We just pad the text to the correct length, since the given plain-text is not
enough to reconstruct the full key. Since the key is repeated over and over
again we will not decrypt the full text but have passages that doesn't
decrypt. Lets see if thats enough already. Running the script gives us the
following key:
`nevergonnagiveyouupnevergonnaletyoudownnevergonnarunaroundanddesertyounevergonnamakeyoucrynevergonnasaygooaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`.

```python  
index = 0  
for c in ct:  
   offset = 0  
   if (c >= ord('a') and c <= ord('z')):  
       offset = ord('a')  
   elif (c >= ord('A') and c <= ord('Z')):  
       offset = ord('A')  
   else:  
       print(chr(c), end="")  
       continue

   c = ((((c - offset) - key[index%len(key)]) + 26) % 26) + offset  
   index += 1  
   print(chr(c), end="")  
```

Using this key we can decrypt enough to get the flag:

```bash  
$ python decrypt.py  
On this Valentine's day, I wanted to show my love for professor Paul Eggert.
This challenge is dedicated to him. Enjoy the challenge!

L xyw fmoxztu va tai szt, dbiazb yiff mt Zzhbo 1178 gyfyjhuzw vhtkqfy snih and
every exam problem, then searching through my slide print-outs for the closest
match and then just writing it down and hopinj gmv glz fvyh, jueg eww oq i
wuqglh Z lrigjsss ynch xun esivmpwf: "oof hing banned in China?"

I remembered the wise words that my TA once told me:

Bing was never banned in China. Naive undergrad. Rent a virtudm kepldrv gbq
phxgv.

Ehlb'w wuhu C ixyzchlr, ilc srez foq e wxzb sdz nrong. And I had managed to
crack the code. I had to rent a lnxsrv and check. Under my breath, I muttered
the words export PATH=/usr/local/cs/ejl:$TNXC, eej hurn mlp qowtswvqn:

wrm ~cuamyh/umlofikjayrvplzcwm.gdt | less  
lactf{known_plaintext_and_were_off_to_the_races}

Suddenly, chilling wind brushed over my back.

After one and a half hours, they kbb jvrvpce anaazio eo ecvn bq abv TA wh bos
aiahovr qojp.  
```

Flag `lactf{known_plaintext_and_were_off_to_the_races}`

Original writeup (https://github.com/D13David/ctf-
writeups/blob/main/lactf24/crypto/valentines_day/README.md).