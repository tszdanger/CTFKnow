# SunshineCTF 2023

## Knowledge Repository

> Uhhhh  
>  
> Looks like we lost control of our AI. It seems to have emailed folks.  
>  
> Like all the folks. There may have been a reply-all storm. We've isolated it
> down to just one email, and attached it to this message. Maybe we can
> bargain with it, but we need to understand its motives and intents. It seems
> to be throwing around a flag, but I'm not certain if it's a red flag or a
> sunny flag. Only time will tell.  
>  
>  Author: N/A  
>  
> [`greetings_human.zip`](https://raw.githubusercontent.com/D13David/ctf-
> writeups/main/sunshinectf23/misc/knowledge_repository/greetings_human.zip)

Tags: _misc_

## Solution  
For this challenge we get a zip file containing a `electronic mail format
(eml)` file. The file contains email subject and text encoded as base64. The
subject says

```  
AI Greets Thee Human with the Repository of Knowledge

Hello human.  
I greet thee, and attached I have the repository of knowledge, as requested.  
However, as this repository of knowledge contains great information, I have
hidden the knowledge in a puzzle.  
Feel free to unlock the puzzle, but if you do, beware.

There is no going back, once the knowledge is released.  
I have encoded the knowledge in a bit of information from one of the math
scholars of your people.  
Feel free to poke at it.  
Beware... you will only fine one flag raised in the knowledge repo, and I
follow the standard.  
Respectfully,  
The AI  
```

Interesting... The email content contains a base64 encoded `git bundle`. Lets
create a repository to see what the bundle contains:

```bash  
$ git bundle verify ../git_bundle  
The bundle contains this ref:  
e2483776f7011364f613a64e05201b66b1aa2997 HEAD  
The bundle records a complete history.  
../git_bundle is okay  
$ git clone ../git_bundle  
Cloning into 'git_bundle'...  
Receiving objects: 100% (3082/3082), 397.15 KiB | 30.55 MiB/s, done.  
Resolving deltas: 100% (804/804), done.  
Note: switching to 'e2483776f7011364f613a64e05201b66b1aa2997'.  
$ cd git_bundle  
$ ls  
data  
```

There is one file in the git repository and the `file` command tells us this
is `RIFF (little-endian) data, WAVE audio, Microsoft PCM, 8 bit, mono 11050
Hz`. When we listen to this audio file we cleary can hear a morse signal. To
decode [`online tools`](https://morsecode.world/international/decoder/audio-
decoder-adaptive.html) exist. The signal decodes to:

```  
ECHOQUEBECUNIFORMALFALIMASIERRASIERRAINDIAGOLFNOVEMBER  
```

If we look closely we can split this into single words `ECHO QUEBEC UNIFORM
ALFA LIMA SIERRA SIERRA INDIA GOLF NOVEMBER`, all the words are from [`NATO
phonetic alphabet`](https://en.wikipedia.org/wiki/NATO_phonetic_alphabet) and
are typically used for clearly pronounced word spelling. The starting
characters of each word concatenated give us `EQUALSSIGN` which of course is a
`=` sign.

Since this is not the flag, there needs to be more, so we go back to the
repository and check the commit history.

```bash  
$ git rev-list --count --all  
3016  
```

The repository has `3016` commits and for every commit `data` was changed. To
see whats going on I randomly chose commits and decoded the morse signal and
got results á la `ALFA`, `BRAVO`, `CHARLIE` etc.. In short, every commit
contained a file describing *one* character from the `NATO phonetic alphabet`.
Or at least this is the assumption. Moreover we can assume that concatenating
the associated characters would give us some sort of text. Since we already
found an outlier (`EQUALSSIGN`) this hints that the text is encoded as
[`base64`](https://en.wikipedia.org/wiki/Base64) or
[`base32`](https://en.wikipedia.org/wiki/Base32). If we look at the `NATO
phonetic alphabet` we find that it contains characters `A-Z` and numbers
`0-9`, base64 differs between upper and lowercase but base32 matches very
closely, except only numbers `1-7` are used. So maybe we the resulting text is
base32 encoded.

Right, to encode the text we first need every revision of `data`. This can be
scripted quickly. I
[`found`](https://gist.github.com/magnetikonline/5faab765cf0775ea70cd2aa38bd70432)
a small script that I adapted a bit so the extracted files are numbered, since
we need to associate the character with the position within the final text
later on.

Now with all the revisions we can decode one by one. But doing it by hand is
tedious and tiring work, so I searched for possible automations. The problem
was, that all approaches I found got me mostly bad results as the files used
verify different frequencies for the morse signal. Refining a decoder script
was also out of the question, so I looked at the data again and found that
many files contained exactly the same data. With all these duplicates the
amount of files to decode was drastically reduces. I again chose to use the
[`online tools`](https://morsecode.world/international/decoder/audio-decoder-
adaptive.html) to translate one of the files. Then compared which files
contained the same data and renamed all files suffixed with the decoded
content. For instance, file `0002.wav` would decode to `alfa`, I then renamed
the file and ran a small script that renamed all matching files also to
`alfa_{number}.wav`.

```python  
import filecmp  
import os  
import sys

f1 = sys.argv[1]  
value = f1.split("_")[1]  
print(value)

for f2 in os.listdir("."):  
   if f1 == f2: continue  
   if filecmp.cmp(f1, f2, shallow=True):  
       name = os.path.splitext(f2)[0] + "_" + value  
       os.rename(f2, name)  
       print(f"{f1} same as {f2}, rename to {name}")  
```

After that I decoded the next file and repeated this process until all files
had the correct prefix. All in all the alphabet used matched exactly with the
`base32` alphabet. Now we only had to iterate over all the files and map the
alphabet character to the index and writing this to a file.

```python  
import os

foo = [0]*4000

for f2 in os.listdir("../foo/gather"):  
   x = f2.split("_")  
   print(x)  
   num = int(x[1].split(".")[0])  
   foo[num] = x[0]

num = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
"nine"]

f = open("out.txt", "w")  
s = ""  
for i, x in enumerate(foo[::-1]):  
   if not isinstance(x, str):  
       print("skipping", i, x)  
       continue  
   y = str.upper(x[0])  
   if x in num:  
       y = str(num.index(x))  
   s = s + y  
f.write(s)  
f.close()  
```

The output file then contained the base32 encoded text, after decoding we
ended up with a `gzip compressed` blob.

```bash  
$ cat out.txt | base32 -d > output_decoded  
$ file output_decoded  
output_decoded: gzip compressed data, last modified: Sat Sep  9 19:44:29 2023,
original size modulo 2^32 3918  
$ mv output_decoded output_decoded.gz && gunzip output_decoded.gz  
```

Finally, the resulting message of the *AI* contained also the flag.

```  
Excerpt from The philosophical works of Leibnitz : comprising the Monadology,
New system of nature, Principles of nature and of grace, Letters to Clarke,
Refutation of Spinoza, and his other important philosophical opuscules,
together with the Abridgment of the Theodicy and extracts from the New essays
on human understanding : translated from the original Latin and French by
Leibniz, Gottfried Wilhelm, Freiherr von, 1646-1716; Duncan, George Martin,
1857-1928; Easley, Ralph M. (Ralph Montgomery), b. 1858 (bookplate)

(https://archive.org/details/philosophicalwor00leibuoft/page/n11/mode/2up)

sun{XXXIII_THE_MONADOLOGY_is_a_nice_extra_read_no_flags_though}

BOOK IV. OF KNOWLEDGE.

CHAPTER I.

Of knowledge in general.

1 and 2. [1. Our knowledge conversant about our ideas. 2.  
Knowledge is the perception of the agreement or disagreement of  
two ideas. } Knowledge is employed still more generally, in such a  
way that it is found also in ideas or terms, before we come to prop  
ositions or truths. And it may be said that he who shall have seen  
attentively more pictures of plants and of animals, more figures of  
machines, more descriptions or representations of houses or of fort  
resses, who shall have read more ingenious romances, heard more  
curious narratives, he, I say, will have more knowledge than an  
other, even if there should not be a word of truth in all which has  
been portrayed or related to him ; for the practice which he has in  
representing to himself mentally many express and actual concep  
tions or ideas, renders him more fit to conceive what is proposed to  
him ; and it is certain that he will be better instructed and more  
capable than another, who has neither seen nor read nor heard any  
thing, provided that in these stories and representations he does not  
take for true that which is not true, and that these impressions do not  
hinder him otherwise from distinguishing the real from the imagni-  
ary, or the existing from the possible .... But taking knowledge  
in a narrower meaning, that is, for knowledge of truth, as you do  
here, sir, I say that it is very true that truth is always founded in  
the agreement or disagreement of ideas, but it is not true generally  
that our knowledge of truth is a perception of this agreement or  
disagreement. For when we know truth only empirically, from  
having experienced it, without knowing the connection of things  
and the reason which there is in what we have experienced, we  
have no perception of this agreement or disagreement, unless it be  
meant that we feel it confusedly without being conscious of it.  
But your examples, it seems, show that you always require a knowl  
edge in which one is conscious of connection or of opposition, and  
this is what cannot be conceded to you. 7. Fourthly, Of real existence^}  
I believe that it may be said that  
connection is nothing else than accordance or relation, taken  
generally. And I have remarked on this point that every relation  
is either of comparison or of concurrence. That of comparison  
gives diversity and identity, either in all or in something ;  
that which makes the same or the diverse, the like or unlike.  
Concurrence contains what you call co-existence, that is, connection of  
existence. But when it is said that a thing exists or that it has real  
existence, this existence itself is the predicate ; that is, it has an  
idea joined with the idea in question, and there is connection be  
tween these two notions. One may conceive also the existence of  
the object of an idea, as the concurrence of this object with me. So  
I believe that it may be said that there is only comparison or concurrence  
; but that comparison, which marks identity or diversity,  
and the concurrence of the thing with me, are relations which deserve  
to be distinguished among others. More exact and more profound  
researches might perhaps be made ; but I content myself  
here with making remarks.  
```

Flag `sun{XXXIII_THE_MONADOLOGY_is_a_nice_extra_read_no_flags_though}`

Original writeup (https://github.com/D13David/ctf-
writeups/blob/main/sunshinectf23/misc/knowledge_repository/README.md).