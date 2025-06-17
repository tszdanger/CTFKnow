# Misc: made-harder  
solver: [L3d](https://github.com/imL3d)  
writeup-writer: [L3d](https://github.com/imL3d)  
___  
**Author:** doubledelete  
**Description:**  
> the third makejail

**files (copy):**
[app.py](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/made-
harder/files/app.py)  

In this challenge we receive a site (and it's code), that allows us to write
and execute a GNU Make recipe, with some restrictions.  
We need to bypass those restrictions and get the flag.  
Essentially, a Make jail.  

## Solution

*This Challenge is the third challenge out of a series of 4 challenges.*  

This challenge seems very similar to the previous ones. It has few minor
changes:  
1. The restrictions on the content are different, we are only allowed to use the special characters: `!@#$%^&*()[]{}<> `

This restriction isn't really restricting when it comes to bash, as we have a
lot we can do with only speical characters (read more about it
[here](https://github.com/C0d3-Bre4k3rs/Misc)). But this is much simpler than
a regular bash jail, as we have the Make language in our side to help here a
little.  

In Make, there are [Automatic
Variables](https://www.gnu.org/software/make/manual/html_node/Automatic-
Variables.html) - variables that are different for each rule that is executed,
based on the target and prerequisites of the rule. These variables are really
useful when writing a Makefile to compile your project...  
And also to places in which you can only use special characters in a make-bash
jail.  
  
So instead of writing `cat flag.txt`, we can set the rule target to be `cat`
and use the follwing content:  
`$@ $<`  
This is being evaluated to `cat flag.txt`, since the `$@` is a variables which
means the target name, and `$<` means the first prerequisite (which
conveniently happens to be `flag.txt`).  
Voilà! We get the flag: `wctf{s0_m4ny_v4r14bl35}`  
  
To the [next
one](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/tree/main/made-
with-love)! ;)  

Original writeup
(https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/tree/main/made-harder).