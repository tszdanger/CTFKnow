may your code be under par. execute the getflag binary somewhere in the
filesystem to win  

`nc mc.ax 31774`  

[jail.zsh](https://gthub.com/Nightxade/ctf-
writeups/blob/master/assets/CTFs/Dice-CTF-Quals-2024/jail.zshs)  

---

We're given a "zsh" jail file:  

```bash  
#!/bin/zsh  
print -n -P "%F{green}Specify your charset: %f"  
read -r charset  
# get uniq characters in charset  
charset=("${(us..)charset}")  
banned=('*' '?' '`')

if [[ ${#charset} -gt 6 || ${#charset:|banned} -ne ${#charset} ]]; then  
   print -P "\n%F{red}That's too easy. Sorry.%f\n"  
   exit 1  
fi  
print -P "\n%F{green}OK! Got $charset.%f"  
charset+=($'\n')

# start jail via coproc  
coproc zsh -s  
exec 3>&p 4<&p

# read chars from fd 4 (jail stdout), print to stdout  
while IFS= read -u4 -r -k1 char; do  
   print -u1 -n -- "$char"  
done &  
# read chars from stdin, send to jail stdin if valid  
while IFS= read -u0 -r -k1 char; do  
   if [[ ! ${#char:|charset} -eq 0 ]]; then  
       print -P "\n%F{red}Nope.%f\n"  
       exit 1  
   fi  
   # send to fd 3 (jail stdin)  
   print -u3 -n -- "$char"  
done

```

Looking up zsh, I found out it was essentially just a Unix shell that's
typically used in Macs. It didn't seem to actually impact the problem -- i.e.
most Linux commands work just the same.  

Taking a look through the source code, the only constraints seemed to be 1.
only 6 characters were allowed for use during each session and 2. the
characters of "*", "?", and "\`" were blacklisted. THe blacklisted characters
are two wildcards (\* and ?) and a backtick character, which allows for
certain command executions.  

Immediately, I figured wildcards might be important for this challenge. I
looked up wildcards for Linux, and found [this site](https://tldp.org/LDP/GNU-
Linux-Tools-Summary/html/x11655.htm) documenting all of them. Importantly,
doing something like `[!x]` seemed to be potentially very useful, as it act
basically like a `?`.  

After doing this, I ran `ls -al` on the service. This showed the following:  

```  
total 16  
drwxr-xr-x 1 nobody nogroup 4096 Feb  2 21:56 .  
drwxr-xr-x 1 nobody nogroup 4096 Feb  2 13:31 ..  
-rwxr-xr-x 1 nobody nogroup  795 Feb  2 21:55 run  
drwxr-xr-x 1 nobody nogroup 4096 Feb  2 13:31 y0u  
```

Testing run with `./run` shows that it's just the binary version of the jail
source file. We also have a directory named `y0u`. Let's list that out with
`ls y0u`.  

```  
w1ll  
```

At this point, I figured it was going to be several nested directories
spelling out some message starting with `y0u/w1ll`. Unfortunately, I wasn't
sure how to list the next directories. In fact, I spent the next hour trying
to figure out how to call `ls` on the next file using only 6 characters (I
could only get it to work with 7) or test all possible directory name lengths
with `[!.]` acting as a wildcard.  

Eventually, I realized that `ls` probably had a recursive function... wasted
an hour of my life because of this T^T  

Sending `ls -R` to the service, I got:  

```  
.:  
run  
y0u

./y0u:  
w1ll

./y0u/w1ll:  
n3v3r_g3t

./y0u/w1ll/n3v3r_g3t:  
th1s

./y0u/w1ll/n3v3r_g3t/th1s:  
getflag  
```

So that's our path! `./y0u/w1ll/n3v3r_g3t/th1s/getflag`, Because of our useful
wild card `[!.]`, we can specify our charset as `./[!]` and send
`./[!.][!.][!.]/[!.][!.][!.][!.]/[!.][!.][!.][!.][!.][!.][!.][!.][!.]/[!.][!.][!.][!.]/[!.][!.][!.][!.][!.][!.][!.]`
to execute the getflag binary.  

   dice{d0nt_u_jU5T_l00oo0ve_c0d3_g0lf?}

TL;DR: Not knowing ls had a recursive option cost me an hour of my life.  

Original writeup (https://nightxade.github.io/ctf-writeups/writeups/2024/Dice-
CTF-Quals-2024/misc/zshfuck.html).