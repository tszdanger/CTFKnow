# $hell Game$  
  
**Category: misc**  
**Value: 433**  
**Flag: flag{s0_y0u_th1nk_y0u_c@n_5h311_l1k3_a_b055}**  

## Description

So you think you can $hell, huh?  Let's see if you can find the flag at
`cha.hackpack.club:41714`.  Using a $hell.  _Just_ a $hell...  

## Solution

We are given a shell with basic functionality and no other binaries. We have
to find the flag hidden somewhere in the file system but we cannot even list
the files in the current directory. So, we have to construct a set of tools
with what we have.

Trying different shell builtins we found:  
* functions (func_name()(  ... })  
* pathname expansion ( Using "*" with any other commands, expands it to the list of files in the current directory)  
* echo  
* while  
* for   
* read  
* test  
* others: set, type, alias

So, we start by creating "ls":  
```bash  
$ ls() { echo *; }  
$ ls  
LICENSE-OF-THIS-PATCHED-DASH aux bin dev doc etc inc lib proc sbin src sys tmp  
```  
We seem to be at /, with something that looks like a file and other,
traditional, directories. Maybe the flag is in the file, we need cat.

```bash  
$ cat() { while read l; do echo $l; done < $1; }  
$ cat LICENSE-OF-THIS-PATCHED-DASH  
```

Just a normal license, no flag there.

We can "cd" to the different directories and see that there are mostly text
files filled with different phrases, a lot of them using the word flag but
what we are looking for starts with **flag{**.

We need something like ```grep -RF 'flag{'```.  
The first step is to differentiate between regular files and directories:  
```bash  
$ lf() { for f in $(ls); do test -f $f && echo $f; done; }  
$ ld() { for d in $(ls); do test -d $d && echo $d; done; }  
```

It would also be useful something to cat all the files in the current
directory:  
```bash  
$ catf() { for f in $(lf); do cat $f; done; }  
```

During the CTF, I actually wrote another function to recursively enter all
directories and cat every file. I then searched for the flag in the buffer of
my local terminal.

```bash  
$ catd() { for d in $(ld); do cd $d; catf; catd; cd ..; done; }  
$ catd  
```

That works but it's a little messy, it may create some problems with the
connection or the server if the files are too big and it will depend on the
buffer size of your terminal.  
So, I decided to make a Python script to do the same but one directory at the
time. It is slower but safer.

```python  
import sys  
from pwn import *

HOST = 'cha.hackpack.club'  
PORT = 41714  
CMD_CLEAN_TIMEOUT = 0.3  
CMD_LINE_TIMEOUT = 0.3

def cmd(r, c, decode=True):  
   r.clean(CMD_CLEAN_TIMEOUT)  
   print(c)  
   r.sendline(c)  
   result = []  
   while True:  
       l = r.readline(timeout=CMD_LINE_TIMEOUT)  
       if len(l) == 0:  
           break  
       if decode:  
           result.append(l.strip().decode())  
       else:  
           result.append(l)  
   return result

def cat_files(r):  
   lines = cmd(r, f'catf', False)  
   for l in lines:  
       if b'flag{' in l:  
           pwd = cmd(r, 'pwd')[0]  
           print(f'FLAG: {l.decode()}')  
           print(f'PWD: {pwd}')  
           sys.exit(1)

def cat_dirs(r, path):  
   result = cmd(r, f'cd "{path}"')  
   cat_files(r)  
   for p in cmd(r, 'ld'):  
       cat_dirs(r, p)  
   cmd(r, f'cd ..')

r = remote(HOST, PORT)  
r.sendline("ls() { echo *; }")  
r.sendline("lf() { for f in $(ls); do test -f $f && echo $f; done; }")  
r.sendline("ld() { for d in $(ls); do test -d $d && echo $d; done; }")  
r.sendline("cat() { while read l; do echo $l; done<$1; }")  
r.sendline("catf() { for f in $(lf); do cat $f; done; }")  
r.clean(2) # Clean all the data we got so far  
cat_dirs(r, '/')  
```

These are the last lines after executing the script:  
```bash  
cd ..  
cd "src"  
catf  
ld  
cd "etc"  
catf  
ld  
cd "lib"  
catf  
pwd  
FLAG: flag{s0_y0u_th1nk_y0u_c@n_5h311_l1k3_a_b055}

PWD: /lib/src/etc/lib  
```

I tried to connect again and access that path but it didn't exist. So, I
guess, the flag is placed in a different directory every time you connect.

***Vox Dei***  

Original writeup
(https://github.com/s1ngl3m4l7/voxdei/blob/master/2020_hackpack/hell_game.md).