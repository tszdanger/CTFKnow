# Misc: made-with-love  
solver: [L3d](https://github.com/imL3d)  
writeup-writer: [L3d](https://github.com/imL3d)  
___  
**Author:** doubledelete  
**Description:**  
> the final makejail

**files (copy):**
[app.py](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/made-
with-love/files/app.py)  

In this challenge we receive a site (and it's code), that allows us to write
and execute a GNU Make recipe, with some restrictions.  
We need to bypass those restrictions and get the flag.  
Essentially, a Make jail.  

## Solution

*This Challenge is the fourth challenge out of a series of 4 challenges.*  

This challenge is a combination of the second and third challanges in this
series:  
1. The shell we receive is `bash` the environment variable `$PATH` being empty. This means we don't have access to any binaries that reside in the serach directories specified by this evironemnt variables. Or, in short, no `cat` ?.  
2. The restrictions on the content are different, we are only allowed to use the special characters: `!@#$%^&*()[]{}<> `

This makes it really easy... just to combine the solution we gave in both
those challenges:  
target name: `source`  
content: `$@ $<`  
...  
We get the flag: `wctf{m4d3_w1th_l0v3_by_d0ubl3d3l3t3}`  

## Afterthought

These challenges gave a unique spin on the regular bash jail challenges.  
They showcased the world of `make`, that aren't usually seen in this field
(other than, of course, in the context of compiling your program).  
Further more, they used variadic parts of the Make lagnauge, which is a very
powerful tool, and allowed the participants to learn them in a unique and
memorable way.  
And, on a personal note, I liked those challenges since they allowed for my
obsolet knowlege of `make` to be useful for once.  
I hope we see more of these challenges in the future (even though they are on
the easier side ;) )  

Happy coding, and thanks for reading!  

Original writeup
(https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/tree/main/made-with-
love).