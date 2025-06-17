# Misc: made-functional  
solver: [L3d](https://github.com/imL3d)  
writeup-writer: [L3d](https://github.com/imL3d)  
___  
**Author:** doubledelete  
**Description:**  
> the second makejail

**files (copy):**
[app.py](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/made-
functional/files/app.py)  

In this challenge we receive a site (and it's code), that allows us to write
and execute a GNU Make recipe, with some restrictions.  
We need to bypass those restrictions and get the flag.  
Essentially, a Make jail.  

## Solution

*This Challenge is the second challenge out of a series of 4 challenges.*  

This challenge seems very similar to the previous one. It has few minor
changes:  
1. The shell we receive is `bash` the environment variable `$PATH` being empty. This means we don't have access to any binaries that reside in the serach directories specified by this evironemnt variables. Or, in short, no `cat` ?.  
2. The restrictions on the content are different, we are not allowed to use the escapte character, `\`.

This challenge is more of a `bash` jail than a `make` one - we need to figure
out how to echo the content of a file only with the [bash
builtins](https://www.gnu.org/software/bash/manual/html_node/Bash-
Builtins.html).  
After looking at all the builtin commands we find the one that can help us in
this case: `source`.  
Source will try to run the files content and parse it as shell commands - when
it will fail it will print the error of the command he didn't find... which is
our flag. Payload:  
`source flag.txt`  
Stderr output:  `b'flag.txt: line 1: wctf{m4k1ng_f1l3s}: No such file or
directory\nmake: *** [Makefile:5: all] Error 127\n' `  
  
To the [next
one](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/tree/main/made-
harder)! ;)  

Original writeup
(https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/tree/main/made-
functional).