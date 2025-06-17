# Sushi - Miscellaneous - 300 Points

I (Remy) wrote this challenge, so of course my writeup will be biased... I
wrote it. People managed to solve this challenge during WPICTF, so you should
search for their writeups to see a solution from a purely contestant
perspective.

## Challenge Description:

Thousands of dollars of sushi... COMPED!

Decode the following file to get the flag:

https://drive.google.com/open?id=137rBRmOa\_xqCobahLCKu8psuWO6cd\_z5

Encode service here: nc sushi.wpictf.xyz 31337 (or 31338 or 31339)

made by rm -k

Image files from
https://drive.google.com/open?id=1\_Yu9RskDqhojxjtbfPILM2Sh1yBhA4uR

Hint file from
https://drive.google.com/open?id=1EWfM5oBVksVD1an\_SFV-v1gdvcTYKyHR

## Lookin' at it

There are several components to this challenge. We are given a giant (100 +)
megabyte file, an online service which encodes text into the same format found
on file, and a picture that looks like it was taken at a sushi restaurant. The
photo itself is peculiar... it seems to have a bunch of hints written on a
napkin!

![alt
text](https://github.com/rkaldawy/writeups2019/blob/master/wpictf/sushi/hint.jpg
"A Strange Hint")

These hints seem completely unrelated to each other. One of them probably
bears relevance to the task at hand, while the others are red herrings.

Moving from the photo to the encode service, a bit of trial and error will
show that the same text has many (in fact, an infinite) number of valid
encodings. The encode service is also spitting out much shorter encodings than
the released file; thus, the absolute frequency of the letters must be
irrelevant to the encoding.

From there, it takes some time cross referencing the encoding with the hints
before a possible solution may appear. Several key insights are listed, in no
particular order:

- The encoding uses only the uppercase and lowercase alphabet  
- Each 'unit' of the encoding is delimited with a single 'z' character. Each unit can have an arbitrary number of 'A' to 'Y' characters  
- A grid in the corner of the napkin contains the letters 'A' through 'Y', which matches the characters used in the encoding  
- Lowercase and upercase letters are completely interchangable. They can be essentially treated as the same characters  
- XOR'ing each letter of each 'unit' in the encoding yields the same output.   
- **Mapping the XOR'ed output to the grid generates traced out characters**

This last insight is key to breaking the encoding. Namely, the encoding is
taking the grid of letters in the hints and using it to trace out characters.
The second hint image confirms this insight. For example, the word "HELLO" is
traced as:

![alt
text](https://github.com/rkaldawy/writeups2019/blob/master/wpictf/sushi/traces.png
"Traced Out Letters")

Thus, each "unit" of the encoding is the set of letters required to trace out
one letter of the flag. Each letter is then copied an arbitrary number of
times within the unit. Each instance of a letter "flips" that letter on and
off; thus, an odd quantity of a letter in a unit will lead to that letter
being present in the trace of the unit, while an even number of a letter in a
unit will lead to that letter not existing in the trace. Finally, some letters
are made lowercase, just for laughs. It bears no information about the
encoding.

## Decoding the large file

With the encoding pieced together, it is possible to write a decoder to draw
out the encoded traces. The code in decoder.py can decode the 100+ megabyte
challenge file in ~30 seconds. Doing so yields the flag:
WPI{SPICY\_YELLOWTAIL\_WITH\_SOY\_WRAP}

## Conclusions

Some people managed to solve this challenge, which means that it was at least
mostly reasonable. This was meant to be the "busywork" misc challenge that a
lot of CTFs have; you have a large file and need to build an automated solver
to push through it. I think this challenge succeeded in its intended purpose.
Hopefully, people enjoyed the riddle of trying to crack the encoding.  

Original writeup
(https://github.com/rkaldawy/writeups2019/tree/master/wpictf/sushi).