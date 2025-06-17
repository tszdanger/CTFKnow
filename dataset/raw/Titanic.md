# Titanic (ppc, 128p, 34 solved)

## Description

In the task we connect to a server which (afer PoW) shows the problem
description:

```  
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

+ welcome to JPS challenge, its about just printable strings! the number  +  
+ n = 114800724110444 gets converted to the printable `hi all', in each   +  
+ round find the suitable integer with given property caring about the    +  
+ timeout of the submit of solution! all printable = string.printable  :) +  
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++  
|  
whats the nearest number to 1367141302107188991138 that gets converted to the
printable string?  
```

The goal is to find closest number which converted to bytes will be printable.

## Solution

### Native solver for tests

We start off by making a naive solver so we can later check against it:

```python  
def reference_solver(number):  
   v = number  
   while True:  
       if is_printable(long_to_bytes(v)):  
           high = v  
           break  
       else:  
           v += 1  
   v = number  
   while True:  
       if is_printable(long_to_bytes(v)):  
           low = v  
           break  
       else:  
           v -= 1  
   if abs(low - number) < abs(high - number):  
       return low  
   else:  
       return high  
```

If you play around you notice pretty obvious regularity: every payload ends
with either `0x09` or `0x7e`.  
This is pretty clear, if we at some point `lowered` a higher byte, then we
want all lower bytes to be as high as possible, hence `0x7e`, and conversly if
you at some point `raised` some higher byte, then we want all lower bytes to
be as small as possible, hence `0x09`.

### Real solver

Mentioned regularity brings us to the actual solution.  
It's clear that once we find position we want to modify, everything downstream
from that point will be just `0x09` or `0x7e`.  
It might seem that we just need to find a first non-printable byte, but this
is in fact not a correct idea.

A couter-example would be `0x4FD9` where first byte is printable, but in fact
it's better to modify this byte and not the next one.

But we assumed that in this case, maybe it's enough to just check 2 bytes? :)

We used the naive solver to generate mapping between 2 bytes block and the
best result for that configuration.  
Just in case we also generated such mapping for a single byte (for the corner
case where only last byte is non-printable) and run:

```python  
def solve(number):  
   hexes = clean_hex(number).replace("0x", "").replace("L", "")  
   if len(hexes) % 2 == 1:  
       hexes = '0' + hexes  
   chunks = chunk(hexes, 2)  
   res = ''  
   lowest = '09'  
   highest = '7e'  
   for i in range(len(chunks) - 1):  
       c = "".join(chunks[i:i + 2])  
       if c != hexmapping[c]:  
           missing = len(chunks) - i - 2  
           res += hexmapping[c]  
           if int(c, 16) < int(hexmapping[c], 16):  
               res += (lowest * missing)  
           else:  
               res += (highest * missing)  
           break  
       else:  
           res += chunks[i]  
   if len(res) / 2 < len(chunks):  
       res += mapping_small[chunks[-1]]  
   return int(res, 16)  
```

This is not perfect, but it immediately can pass lots of stages!  
Fortunately there are not that many stages and we can run this a couple of
times until we get lucky -> `ASIS{jus7_simpl3_and_w4rmuP__PPC__ch41LEn93}`

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-07-03-ASIS-
quals/titanic/README.md).Titanic - TJCTF  
===

### Challenge  
> I wrapped tjctf{} around the lowercase version of a word said in the 1997
> film "Titanic" and created an MD5 hash of it:
> 9326ea0931baf5786cde7f280f965ebb

So I obviously chose Python 3 as my language to solve this challenge, which is
made perfectly for reading text files, the only problem was getting the right
text files in the first place. So in my mind the pseudo-code for my program
went something like this:

1. Read and open a text file.  
2. Read each word from each line of the text file.  
3. Wrap each word in tjctf{}  
4. Make the wrapped string lowercase.  
5. Hash the lowercase string.  
6. If the md5 hash matches the hash provided in the challenge then stop the program and print the un-hashed version of the wrapped string which matches the hash provided for us.

This was the first version of my script scripter (heh)  
```python3  
import string  
import hashlib

translator = str.maketrans('','', string.punctuation)

with open('titanic_srt.txt', 'r') as file:  
	# read each line  
	for line in file:  
		#read each word which is split by a space  
		for word in line.split():  
			# turn each word into lowercase  
			lower = word.lower()  
			# remove all punctuation  
			lower_no_punc = lower.translate(translator)  
			# wrap in flag   
			encased = 'tjctf{' + lower_no_punc + '}'  
			no_punc_encoded = hashlib.md5(encased.encode())  
			hashed = no_punc_encoded.hexdigest()  
			# print(hashed)  
			if hashed == '9326ea0931baf5786cde7f280f965ebb':  
				print('[*] Hash found!')  
				print(encased)  
				print(hashed)  
				break  
			else:  
				continue  
```  
Now this code actually worked well but I made a critical mistake. While I
learned a bit about the string module, which is really useful for cases like
these where we need to read a text file, I didn't allow for the possibility of
contracted words (e.g., don't, can't, shouldn't). I didn't consider this at
first and wasted some time running this script on about 6 different versions
of the Titanic script as seen in this github repo.

I reached out to the challenge author to audit my code real quick which he
said was technically sound but pointed out my mistake for stripping all
punctuation and he also pointed out another mistake I had made in using the
screenplay for the movie as opposed to an actual transcription of the movie,
because actors are often subject to improvising lines which may not be in the
script. D'oh!

I thought for a moment about how the hell to get a transcription of a movie
and (duh) realized I just needed subtitles. In the following version of my
script I did away with the string module in favor of the re module which I
felt was better suited for stripping away certain punctuation.  
I also cleaned up the srt file a bit using find-and-replace via Sublime 3 in
order to strip away certain `**` tags littered throughout the file.**

```python3  
# hash a string into md5  
import re  
import hashlib

with open('titanic_srt.txt', 'r') as file:  
	# read each line  
	for line in file:  
		# read each word split by space  
		for word in line.split():  
			lower = word.lower()  
			# ezpz regex  
			stripped = re.sub(r'[^\w\d\s\']+' , '', lower)  
			# dont forget to wrap the word in tjctf{} !!  
			wrapped = 'tjctf{' + lower + '}'  
			encoded = hashlib.md5(wrapped.encode())  
			hashed = encoded.hexdigest()  
			# print(wrapped)  
			# print(hashed)  
			if hashed == '9326ea0931baf5786cde7f280f965ebb':  
				print('[*] Hash found!')  
				print(wrapped)  
				print(hashed)  
				break  
```  
Run the code and bingo!  
```  
[*] Hash found!  
tjctf{marlborough's}  
9326ea0931baf5786cde7f280f965ebb  
```

Original writeup (https://github.com/Droogy/write-
ups/tree/master/tjctf/titanic).