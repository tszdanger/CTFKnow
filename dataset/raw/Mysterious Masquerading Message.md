# Mysterious Masquerading Message

> We found a file that looks to be like an ssh private key... but it doesn't
> seem quite right. Maybe you can shed some light on it?

```  
tbbq yhpx:)

-----BEGIN OPENSSH PRIVATE KEY-----  
SWYgeW91IGFyZSByZWFkaW5nIHRoaXMsIHRoZW4geW91IHByb2JhYmx5IGZ  
pZ3VyZWQgb3V0IHRoYXQgaXQgd2Fzbid0IGFjdHVhbGx5IGFuIFNTSCBrZX  
kgYnV0IGEgZGlzZ3Vpc2UuIFNvIHlvdSBoYXZlIG1hZGUgaXQgdGhpcyBmY  
XIgYW5kIGZvciB0aGF0IEkgc2F5IHdlbGwgZG9uZS4gSXQgd2Fzbid0IHZl  
cnkgaGFyZCwgdGhhdCBJIGtub3csIGJ1dCBuZXZlcnRoZWxlc3MgeW91IGh  
hdmUgc3RpbGwgbWFkZSBpdCBoZXJlIHNvIGNvbmdyYXRzLiBOb3cgeW91IG  
FyZSBwcm9iYWJseSByZWFkaW5nIHRoaXMgYW5kIHRoaW5raW5nIGFib3V0I  
GFubm95aW5nIHRoZSBwZXJzb24gd2hvIG1hZGUgdGhpcywgYW5kIHlvdSB3  
YW50IHRvIHJlYWQgdGhlIHdob2xlIHRoaW5nIHRvIGNoZWNrIGZvciBjbHV  
lcywgYnV0IHlvdSBjYW50IGZpbmQgYW55LiBZb3UgYXJlIHN0YXJ0aW5nIH  
RvIGdldCBmcnVzdHJhdGVkIGF0IHRoZSBwZXJzb24gd2hvIG1hZGUgdGhpc  
yBhcyB0aGV5IHN0aWxsIGhhdmVuJ3QgbWVudGlvbmVkIGFueXRoaW5nIHRv  
IGRvIHdpdGggdGhlIGNoYWxsZW5nZSwgZXhjZXB0ICJ3ZWxsIGRvbmUgeW9  
1IGhhdmUgZ290IHRoaXMgZmFyIi4gWW91IHN0YXJ0IHNsYW1taW5nIGRlc2  
tzLCBhbmQgc29vbiB0aGUgbW9uaXRvciB3aWxsIGZvbGxvdy4gWW91IGFyZ  
SB3b25kZXJpbmcgd2hlcmUgdGhpcyBpcyBnb2luZyBhbmQgcmVhbGlzaW5n  
IGl0J3MgY29taW5nIHRvIHRoZSBlbmQgb2YgdGhlIHBhcmFncmFwaCwgYW5  
kIHlvdSBtaWdodCBub3QgaGF2ZSBzZWVuIGFueXRoaW5nLiBJIGhhdmUgZ2  
l2ZW4geW91IHNvbWUgdGhpbmdzLCBhbHRob3VnaCB5b3Ugd2lsbCBuZWVkI  
HNvbWV0aGluZyBlbHNlIGFzIHdlbGwgZ29vZCBsdWNrLiAKNjk2ZTY1NjU2  
NDc0NmY2ZjcwNjU2ZTZjNmY2MzZiNzMKNjk2ZTY5NzQ2OTYxNmM2OTczNjE  
3NDY5NmY2ZTMxMzI=  
-----END OPENSSH PRIVATE KEY-----

00111001 00110000 00111001 00111000 00111000 01100011 00111001 01100010  
01100101 01100110 01100101 00110101 01100101 01100001 00110011 01100110  
00110101 01100001 00111001 00110001 01100101 01100110 01100110 01100101  
00110000 00110011 00110000 00110110 00110000 01100001 00111000 00110111  
00110001 00110100 01100100 01100110 01100011 00110010 00110000 00110000  
00111000 00111000 00110100 00110001 00110101 00110101 00110111 00110000  
01100010 00110011 00111001 00110100 01100011 01100101 00111001 01100011  
01100100 00110011 00110010 01100010 01100101 00110111 00110001 00111000  
```

## Description

There seems to be a lot of classical ciphers/encodings... First message seems
to be a Caesar cipher, the actual SSH key is probably base64 encoded data and
in the end we spot binary encoding.

## Solution

Let's fire [CyberChef](https://gchq.github.io/CyberChef). First message seems
to be [Cesar](https://www.dcode.fr/chiffre-cesar) encrypted, so let's choose
ROT13. It directly outputs `Good luck`.

Then there is this big string that looks like base64 (for instance the `=` in
the end is a hint). So let's choose Base64.

```  
If you are reading this, then you probably figured out that it wasn't actually
an SSH key but a disguise. So you have made it this far and for that I say
well done. It wasn't very hard, that I know, but nevertheless you have still
made it here so congrats. Now you are probably reading this and thinking about
annoying the person who made this, and you want to read the whole thing to
check for clues, but you cant find any. You are starting to get frustrated at
the person who made this as they still haven't mentioned anything to do with
the challenge, except "well done you have got this far". You start slamming
desks, and soon the monitor will follow. You are wondering where this is going
and realising it's coming to the end of the paragraph, and you might not have
seen anything. I have given you some things, although you will need something
else as well good luck.  
696e656564746f6f70656e6c6f636b73  
696e697469616c69736174696f6e3132  
```

Those seem to be hex encoded strings. Let's decrypt them using `From hex`:

```  
696e656564746f6f70656e6c6f636b73 -> ineedtoopenlocks  
696e697469616c69736174696f6e3132 -> initialisation12  
```

Well, this looks like a key and an IV (so there is probably an ARS-CBC
encrypted message somewhere).

Finally, the binary code is decrypted as (using From binary):

```  
90988c9befe5ea3f5a91effe03060a8714dfc20088415570b394ce9cd32be718  
```

But this hex string cannot be decoded by `From hex`. So this is probably our
AES ciphertext. Let's use the `AES Decrypt` tool with the corresponding
ciphertext, key and IV.

Flag: `ractf{3Asy_F1aG_0n_aEs_rAcTf}`

Original writeup (https://github.com/apoirrier/CTFs-
writeups/blob/master/AwesomeCTF2020/Crypto/Mysterious%20Masquerading%20Message.md).