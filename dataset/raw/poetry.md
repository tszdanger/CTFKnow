# poetry  
## Chall authors: Captains bluepichu and f0xtr0t and First Mate nneonneo

## Description

On the northern tip o' the Isle of Misque, there be an ol' pirate captain from
ages past. He has many a treasure, and he may be willin' to share — if ye can
help him reminisce about the songs and poems he used to recite with his
hearties!  
Handout

### LimFib  
"There was this one limerick I used to know..." (nc poetry.chal.pwni.ng 1337)  
First solved by

### Astley  
"One of me hearties named Rick liked to stand in front of a fence..." (nc
poetry.chal.pwni.ng 1337)

### Wellerman  
"I think there was this song we used to sing about someone who made rum
flow...?" (nc poetry.chal.pwni.ng 1337)

  

## Solution

As there's not much useful knowledge (unless you find it useful to know that
nop rhymes with pop) this writeup isn't going into all of the details.  
Treat it more like a story then actual writeup.

In case you don't know what the challenge was about, first, I envy you,
second, here's a quick overview, third, I hate challenge authors.

There are three challenges at total.

Our goal is to write x86 (32-bit) assembly code.  
It needs to do a specific thing and the code is tested on some testcases by
emulating it using unicorn.  
Even kids can do this, so of course it's not everything.

Now, the assembly instructions were to be separated with "/" and the code had
to be splitted into lines (putting a newline in a middle of an instruction is
fine) so that the "poetry" constraints were met.  
These constrains were only checked on the words of assembly instructions, the
actual meaning of the instructions doesn't matter for these constrains, only
they're textual representation.

Now, it's not exactly true that the textual representation is what mattered.
What really mattered is how words in the text were "spelled".  
You can see in the `/poetry/poetry/dictionary.arpa` that every word has a
spelling associated (some have more than one).  
Those spellings are composed of phonemes. Each phoneme can either be a vowel
xor consonant. Also, vowels can be "stressed", "unstressed" or **BOTH**.
Actually, most of them are both, which makes our work much easier as you will
come to understand later.

So, the text had to be splitted into a specific number of lines. Each line is
associated with a specific vowel pattern.  
E.g. the pattern "10101010011" means you need exactly 11 vowels the first one
needs to be stressed, the seconds one needs to be unstressed etc. That's why
vowel which can be both stressed and unstressed are useful, as they can fit in
anywhere in the pattern.  
"10?1" means that "0" in the middle is optional, so both "101" and "11" are
fine. There's also "\_" which means that any vowel is fine.

Now comes the most cursed part. Some of the lines have to rhyme. The rhyme
occurs if the suffix of phonemes is equal. And the suffix is taken starting
from the last stressed vowel and to the end of the line (remember that apart
from vowel there are also consonants).  
The last stressed vowel is determined by the line's pattern. So the pattern
like "1010100" means that this suffix is quite long as it takes all phonemes
starting from the third-to-last vowel.

## LibFib

We started with libfib.

Here the code needs to calculate `n`-th fibonacci number mod `2**32`. `n` is
provided on the stack on our output needs to go into `eax`.  
(btw. code is finished when it reaches past the last instruction).

The code needs to form the lymeric.

We wrote short code and after figuring out the basics we managed to turn it
into a limeric.

You can see our solution in [libfim.S](./limfib.S) file.

## Astley

After that I spend about 14-20 hours on astley (not sure how long exactly).

Here the code needs to print "100 bottles of bear" (using write syscall).

The code needs to have the same vowel patterns and rhymes as Rick Astley's
"Never Gonna Give You Up" (don't try to lie, you know it).

I wrote a simple code to estimate if the assembly code is short enough (it's
not perfect, I should have filtered out '?' characters).  
```py  
chall_max_vowel_count = 0  
for x in astley:  
		chall_max_vowel_count += len(x[1])  
my_word_count = 0  
for line in poem.lines():  
		for word in line.words:  
				my_word_count += 1  
my_min_vowel_count = 0  
for line in poem.lines():  
		for word in line.words:  
				mini_vowel = 10000000  
				for pron in word.pronunciations:  
						pron_vowels = sum(isinstance(p, Vowel) for p in pron)  
						mini_vowel = min(mini_vowel, pron_vowels)  
				my_min_vowel_count += mini_vowel  
print(f'{chall_max_vowel_count = }')  
print(f'{my_word_count = }')  
print(f'{my_min_vowel_count = }')  
```  
Btw, that code is probably the most technical thing in this writeup.

I spend some time on golfing the code so the numbers of free vowels left is at
least as big as the number of lines (plus some extra to be sure).  
The code is quite long as the only way to have any strings in the code is to
write them as numbers (hexadecimal or decimal). And the numbers are spelled by
spelling each digit separately (this includes "OW_" "EH_ K S" in "0x1337" xd).  
Then I manually gone line by line tried to make lines as long as possible
while maintaining some rhymes. The code provided with the challenge printed
the first line that didn't match the vowel pattern and spellings of the words
in this line (and it colored the vowels!).  
So I just counted how many more vowel I can put into the line, splitted it
where it needed, potentially adding nops (nops where also useful for rhymes).  
After that I had to fix some rhymes because I made some mistakes, correcting
every mistake was also time-taking as all the lines where packed to the
maximum so I had to go line by line again.  
After debugging a bit, I realized my **HUGE** mistake. I didn't notice that
EVERY chorus section needs to rhyme with all other chorus (choruses?)
sections. I only incorporated "local" rhymes in single sections, not across
all of them.

At that point I had to throw away whole night of work (maybe it wasn't
completely wasted as I got some experience with "poetryizing" assembly code).  
Thanks to the experience I arrived at the idea of using nops for most of the
rhymes (as the rhymes could repeat). But for this I needed to have shorter
assembly code.  
I started from the original code and golfed it much more so I got at least
twice times the number of lines of free vowels left (plus some extra extra to
be sure).  
After that I worked thought the code the same way as before, making sure most
lines end with nop (there are some non-nop rhymes at the begging, as these
rhymes doesn't appear later on).  
Also, there was one rhyme ("g"), which had to be longer than one vowel, so I
put more nops in there.  
In the process I also realized I should check (in the `dictionary.arpa` file)
what other words rhyme with "nop". There are "pop", "setnp", and "bswap", but
in the end I think I only used "pop". Great, now I can tell my friends "Hey,
did you know that nop rhymes with pop?".

The final code/song is in [astley.S](./astley.S) file. You can easily become
my best friend by sending me a video of you singing this on a party (hints at
the end).  
There's also [astley-not-poetry.S](./astley-not-poetry.S) which contains the
code before being turned into a song.

## Wellerman

After spending a lot of time on astley this one took me just a few hours.

Here the problem we've been given is finding the maximum flow in a weighted
symmetric graph. Easy peasy lemon squeezy.

But no, really, it's actually quite easy, the testcases aren't that big (and
weights are very small) so the easiest Ford–Fulkerson algorithm is fine.  
In case you're interested I wrote a short explanation of the algorithm in HTML
comment right here below, as this would be to technical for this light
writeup.  
We're here to speak about poetry.

The code needs to have the same vowel patterns and rhymes to
[this](https://www.youtube.com/watch?v=qP-7GNoDJ5c) sea shanty.

I took me some time to write the code. It turned out very short as it had only
half of the total vowels. Still, I golfed it a bit more to be sure it's short
enough before trying to make a shanty out of it.

The important difference between this challenge and the Astley is that here
the rhymes need to be different (so not using nop everywhere).  
Hopefully in this song, all the rhymes only occur locally in the span of few
lines, except two.  
I decided to use "nop" for one of them and "EH_ K S" for the second. I choosed
"EH_ K S" because there are a lot of words with that suffix: "ax", "bx", "cx",
"dx", "eax", "ebx", "ecx", "edx", "x".

Because my code was very short I didn't try to pack too many code per line, so
it will be easier to edit later on.  
Making this one was quite fun, as it had to contain many different rhymes and
because I wasn't that restricted by my code being too long, as in Astley.

The final code/song is in [wellerman.S](./wellerman.S) file. Please check out
my sick rhymes, I wrote which lines are supposed to rhyme in the comments.  
There's also [wellerman-not-poetry.S](./wellerman-not-poetry.S) which contains
the code before being turned into a song.

  

## Signing Astley

In case you're interesed in singing Astley here are some useful tips:

- **It's much easier with the music.**  
- You have too read through the `dictionary.arpa` file to know spellings of the  
words. Some of them are not obvious. Like "cx" being "K IH_ K S" or "jnz"
being  
"JH EH_ N Z".  
- Numbers are spelled digit by digit.

  

### Writeup Author: Cptn MrQubo  

Original writeup (https://github.com/justcatthefish/ctf-
writeups/tree/master/2023-04-14-PlaidCTF2023/misc_poetry).