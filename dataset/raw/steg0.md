One of the best and educational tasks on this CTF (with "Escape the Grid"
being the close second).

We are given a bespoke zip file encrypted with military-grade AES algorithm,
also known as Rijndael. It was established by the National Institute of
Standards and Technology (NIST) in 2001. This is a nod to 2996 victims of
terrorist attacks of 11th September, that also occurred in the 2001 year. That
was a complete disaster, much like this challenge.

We've used advanced hacking utility known in some circles as GNU strings to
extract "plain text" messages from the binary. At the end of the file in the
obscure feature known as ZIP comment we've found string "there_is_no_flag".
This conveys the cynic belief of the challenge author that nothing really
exists, all our endeavours will eventually cease, and everything in life is
ultimately meaningless - not unlike this task.

Other than that, the file is filled with random data straight from
/dev/urandom. This is the reference to 1994 movie Forrest Gump, when the lead
character says "My mom always said life was like a box of chocolates. You
never know what you're gonna get". By that Forrest meant that the life is
random - exactly like the content of this file, throw of a fair dice, quantum
RNG, and quality of the Hack.lu CTF.

PS. To answer the question: yes, this challenge is intentionally unsolvable.
This is the published source code:

```bash  
#!/bin/sh  
  
# /dev/urandom  
dd if=/dev/urandom of=steg0.dat bs=1M count=32  
sha512sum steg0.dat > steg0.shasum  
  
# tar  
tar cfv steg0.tar steg0.dat  
  
# bzip2  
bzip2 steg0.tar  
  
# sfx  
7z a -sfx steg0.sfx steg0.tar.bz2  
  
# rename  
mv steg0.tar.bz2 steg0.jpg  
  
# zip (pw+comment: there_is_no_flag)  
echo 'there_is_no_flag' | zip -Pe steg0.zip steg0.jpg steg0.shasum  
echo 'there_is_no_flag' | zip -z steg0.zip  
  
## ----  
  
# FLAG  
FLAG="$(dd if=/dev/urandom bs=1M count=1 of=- | sha512sum)"  
#
cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e  
```