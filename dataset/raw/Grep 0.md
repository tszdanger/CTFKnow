## Grep 0  
![date](https://img.shields.io/badge/date-11.01.2020-brightgreen.svg)
![General category](https://img.shields.io/badge/Category-General-
lightgrey.svg) ![score](https://img.shields.io/badge/score-50-blue.svg)

### Description  
```  
Sophia created this large, mysterious file. She might have said something
about grap.. grapes? Find her flag!  
```

### Attached files  
- flag.zip

### Solution  
This zip file contains a looooot of text! (81.7 MB to be exact!) It just said:  
```  
Maybe Here???  
Nop  
Definitely not here  
Look somewhere else  
```  
Repetetively and we know that there is a flag in this gigantic text file. How
the title says it all, but they want us to use "grep". Grep is a powerful tool
used to find patterns within text and display them for you. These patterns my
utilize regular expressions, wildcards, etc to meet your needs (for more
information, look at their man page! Man Page https://man7.org/linux/man-
pages/man1/grep.1.html)  
Now that we understand what grep can do, let's put that to practice. So the
description gave us a little hint that our flag contained a string related to
grapes (But they really mean grep).  
After some testing around I noticed that "gra", "gre", "grep", "grape", and
many other combinations weren't working so I decided to truncate the pattern
into "gr" which worked!  
We can use this simple command that will search for "gr" in the text file:  
```  
grep "gr" flag.txt  
```

### Flag  
```  
nactf{gr3p_1s_r3ally_c00l_54a65e7}  
```

Original writeup (https://github.com/JoshuEo/CTFs/tree/master/NACTF_2020).