# Peculiar Gifts  
**Category** : Misc  
**Author**: EuroStar  
**Description**:  
> Hey! I found these two pictures under the Christmas tree! They seem a little
> bit odd... do you think there might be something hidden inside them? I'll
> let you take a look.  

**Attached files (Gifts.zip)** :  
* GIFTS.jpg  
* XMAS.jpeg

## Intended solution  
The challenge comes with two attached jpeg files. Since this challenge is in
the "misc" category, there is a good change **steganography** was used to hide
the flag in the image.  
  
Since the both files are jpgs, the tool that was most likely used to embed
data in the files is [steghide](http://steghide.sourceforge.net/).  

### Straight-up guessing the password  
  
Steghide however, requires a password to recover hidden data. At this point
you need to channel your inner Guess God and guess that the password "XMAS"
was used for `XMAS.jpeg`.

```  
> steghide --extract -sf XMAS.jpeg -xf - -p "XMAS"  
--- Message from Santa Claus ---

Did you know that base64 can be used for encoding scripts and websites?  
Maybe we can use it for our gifts.  
```

This message hints at the use of base64 for the remaining jpeg file. By
encoding its file name in base64, we can extract the flag:  
```  
> echo -n "GIFTS" | base64  
R0lGVFM=  
> steghide --extract -sf GIFTS.jpg -xf - -p "R0lGVFM="  
X-MAS{l00k$_l!k3_y0u_l1k3_b@sE64}  
```

### Bruteforcing the password

If you, like me, are not psychic, you may struggle with the first step.
Instead of coming up with guesses yourself, you could use a bruteforcer like
[stegseek *](https://github.com/RickdeJager/stegseek) along with a large
wordlist ([crackstations for example](https://crackstation.net/crackstation-
wordlist-password-cracking-dictionary.htm))  
```  
> stegseek XMAS.jpeg crackstation-human-only.txt  
Stegseek version 0.4  
[i] Read the entire wordlist (63941069 words), starting cracker  
[ 62829393 / 63941069 ]  (98,26%)  
[i] --> Found passphrase: "XMAS"

[i] Original filename: "xmas.txt"  
[i] Extracting to "XMAS.jpeg.out"  
```

## Unintended solve, not using a password at all

Turns out there is a really easy way to solve this challenge, because the
author disabled steghides encryption. This allows you to retrieve the flag
directly without needing the correct password  
  
```  
> stegseek --seed GIFTS.jpg -  
Stegseek version 0.4  
[ 823160104 / 4294967295 ]  (19,17%)  
[i] --> Found seed: "45ff2f96"

Plain size: 47,0 Byte(s) (compressed)  
Encryption Algorithm: none  
Encryption Mode:      cbc  
[i] Original filename: "flag.txt"  
[i] Extracting to stdout  
X-MAS{l00k$_l!k3_y0u_l1k3_b@sE64}  
```

\* **Disclaimer**: I wrote this tool, other steghide bruteforcers are
available :) .