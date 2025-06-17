# The Early School  
### Category: Crypto  
### 32 Points  
### 210 Solves  
### Problem description:  
### Welcome to ASIS Early School.  
### Author: Chaocipher  
### Date: 5/1/2018  
### Thanks goes to ASIS for organizing the CTF.  
###
https://github.com/chaocipher/Writeups/blob/master/The%20Early%20School.pdf

## Start  
I downloaded the file from the description. It’s just a 7z file with some
files inside. The archive contained three files:  
	1. file related to the python script. Didn’t need this file so we’ll skip that.  
	2.  file called FLAG.enc.  
	3.  file called the_early_school.py.

## FLAG.enc  
The second file, the FLAG.enc is the encrypted data. I was thinking it’s
fairly large for a flag, so either it was padded heavily through some
operation or it’s buried in there somewhere.

This show the top of the file so you can see it doesn’t match and magic
numbers.  
{Screenshot at the posted link}

This next shot shows a lot of blank space in the file. I noticed this going
all the way down the file this is why I expected padding to be performed.  
{Screenshot at the posted link}

## The_early_school.py  
I worked on this file for a while. Time for honesty; I didn’t understand right
away that this was the file used by ASIS to build the encrypted file in the
first place. I thought this would take in the data and overwrite it with good
output leaving the flag. In hindsight that was dumb and now I have a much
better feel about how these things are done, but never the less, I spent a
bunch of time trying to get this thing to run on my machine until it finally
hit me what was going on here.

Essentially, what’s going on here is that the encryption file is being built
from a string flag that has been imported. It’s converted to binary and sent
to the encryption function. The encryption function is reading the binary in
chunks of two bits and performing some math on it.  
{Code at the posted link}

## Solver.py  
Here is my code to solve the problem. I left some code in there commented
showing how I printed out each component to get a better feel for the
structure of the data. I also left the encryption function in here just for
reference, but it’s not used.

So, I first tried to reverse the math, but couldn’t get that figure out very
easily since the chunk and the math output is concatenated. So, I figured I
would just bruteforce it. By taking in only two bits, the output was finite.
It really could only be four different strings coming out. So, I decide to
write my solver to look for those strings of 3 bits and “case select” my way
to the original binary chunk. Running that 19 rounds gives out the flag. See
below for the solving code.  
{Code at the posted link}  
#### Flag  
#### ASIS{50_S1mPl3_CryptO__4__warmup____}

Original writeup (http://www.bitforksecurity.com/).