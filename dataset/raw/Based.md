# Based

###### writeup by [phishfood](https://ctftime.org/user/136455)

## Challenge

Download the attachment, work up from there!

[based.txt](./based.txt)

## Solution

This challenge involved working through layers of different encodings and
ciphers.  While none of the ciphers were too difficult to solve (especially
once you identified the hints directing towards them) the challenge made for a
great overview of some of the most common ones.

#### Base64

We start by taking a look at the contents attached file:

```  
R3JhbmRwYSBzZW50IG1lIG9uIGEgdHJlYXN1cmUgaHVudCB0byBnZXQgYSBsb3N0IGZsYWcgYnV0IHRoZSBtYXAgd2FzbnQgY29tcGxldGVkLiBBbGwgSSBzYXcgd2FzIHRoZSBjaXR5IG9mIFJPVCBhbmQgYSBjb2RlZCBtZXNzYWdlOiBKdW5nIGxiaCBqdmZ1IHNiZSB2ZiBuZyAuLi4tIC4uIC0tLiAuIC0uIC4gLi0uIC4gLi4uIC0uLS4gLi0gLi4uIC0gLi0uLiAuIGhmciBndXIgeHJsIFFCZ2piIG5hcSBjZWJpdnFyIGd1ciBjdWVuZnIgVFBJQ0d7TXBjSHBrc2tLYmlman0=  
```

It appears to be [**Base64**](https://en.wikipedia.org/wiki/Base64) encoded (as also hinted by the name of the challenge), and sure enough, running the command `cat based.txt | base64 -d` results in the following:

`Grandpa sent me on a treasure hunt to get a lost flag but the map wasnt
completed. All I saw was the city of ROT and a coded message: Jung lbh jvfu
sbe vf ng ...- .. --. . -. . .-. . ... -.-. .- ... - .-.. . hfr gur xrl QBgjb
naq cebivqr gur cuenfr TPICG{MpcHpkskKbifj}`

#### ROT13

Now we have part of the message decoded, but the second half remains to be
solved:

The first half mentioned something about the "city of ROT," perhaps suggesting
that the next part of the message may be
[**ROT13**](https://en.wikipedia.org/wiki/ROT13) (or some other variation of
ROT) encoded.

Running the second half through [rot13.com](https://rot13.com) results in:

`What you wish for is at ...- .. --. . -. . .-. . ... -.-. .- ... - .-.. . use
the key DOtwo and provide the phrase GCVPT{ZcpUcxfxXovsw}`

#### Morse Code

It's pretty obvious that the dots and dashes are [**Morse
Code**](https://en.wikipedia.org/wiki/Morse_code), or at least we sure hope
they are.

Using the [Morse Code World
Translator](https://morsecode.world/international/translator.html) we get the
phrase:

`vigenerescastle`

#### Vigenère Cipher

The phrase above directs us towards solving the final piece,
`GCVPT{ZcpUcxfxXovsw}` as a [**Vigenère
cipher**](https://en.wikipedia.org/wiki/Vigenère_cipher) using the key
`DOtwo`.

Using these as inputs for a [Vigenère cipher
solver](https://www.boxentriq.com/code-breaking/vigenere-cipher) gives us our
flag:

`DOCTF{WowYoureBased}`