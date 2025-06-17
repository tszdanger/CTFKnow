# Challenge Name: Cat Me if You Can  
***  
## Challenge

The description (as can be found in CTFtime through [Cat Me if You
Can](https://ctftime.org/task/25009)):  
> There's a flag hiding in plain sight, Our cat has been trying to get it for
> a while now, but it keeps escaping him at the last moment. Can you help him
> out?

No files were provided, only a `nc` command. This is typical of CTF challenges
that are based on connecting to a server.

```  
~$ nc cha.hackpack.club 41708  
bash-5.1$ ls  
flag.txt  
bash-5.1$ cat flag.txt  
hissssss  
cat: flag.txt  
```

The challenge starts with a shell already, and a file named `flag.txt` in the
home directory. But I can't `cat` the file, which is strange. I expected
"permission denied" or something similar.

***

## Exploration  
I guessed maybe this was a phony file, and the actual file is elsewhere.
Running `ls -R /` made me rule that out. Next, I wanted to view the file's
permissions:

```  
bash-5.1$ ls -l flag.txt  
-rw-rw-r-- 1 root root 31 Apr 14 12:24 flag.txt  
```  
So it's probably not a privilege escalation challenge.

***  
## Solution

I know that I can display the contents of a file without using `cat`, which is
through `echo` and `bash`'s [Command
Substitution](https://www.gnu.org/software/bash/manual/html_node/Command-
Substitution.html).

```  
bash-5.1$ echo $(< flag.txt)  
flag{(^._.^)_m3ow_me0w_(^._.^)}  
bash-5.1$  
```

In fact, using `echo` was not needed:

```  
bash-5.1$ $(< flag.txt)  
bash: flag{(^._.^)_m3ow_me0w_(^._.^)}: command not found  
```

I love me some bashism.

I don't think this was the intended solution, but it worked :)