# Byte-me (50)

>if you can nc crypto.chal.csaw.io 1003

### Intro

Funny enough, this only had 100 solves by the end, even though it was a mere
50 points. While it was actually just simple ECB, there was a small added
twist that made it a bit more difficult. I admit, I struggled and it took me
several hours to finish, also because I didn't have a readily available ECB
solving framework so I coded one from scratch. Also, since this always relies
on essentially byte-wise bruteforcing, it took a while given the server was
overloaded.

### What is it?

That took me a while. I first thought RSA but a look at the length of the
messages and the increased length when inputting more chars led me to believe
that was some stream cipher. From the discussions on Discord I sorta got that
it was ECB, the best and most secure kind (LOL).

### ECB: a short overview

Basically, ECB works this way:

1. Pad the message to be a multiple of 16  
2. Divide the message in blocks of 16  
3. Encrypt each block separately using the key

What this means is that a) each block is independent from the other blocks, b)
2 identical blocks will have the identical corresponding cipher. Now usually,
these kind of challenges allow for some user input, to which the flag is
concatenated and the whole shabang is then encrypted which helps us like so:

Imagine the flag is ```flag{fakeflag}```. If we send 16*```a```, the service
will encrypt ```aaaaaaaaaaaaaaaaflag{fakeflag}```, which means that the first
block will be only ```a``` and the flag will start from block 2. Now if we
send 15*```a```, the service will encrypt ```aaaaaaaaaaaaaaaflag{fakeflag}```,
thus the first block will be our ```a``` plus the first letter of the flag.
Now we can remember the result of the first block and simply send ```a```*15 +
```c``` looping over printable chars. Sure enough,  ```aaaaaaaaaaaaaaaf```
will ringading. Now just continue doing that by removing a padded ```a``` each
time and you get the flag.

### Solving

In this case, there was an added twist namely that the service would randomly
create a string of aribtrary length and preappend it to the input before
appending the flag. So the string that is encrypted is:

```  
[random][input][flag]  
```

It took me a while to wrap my head around it. What I ended up doing was to
send 64 *```a``` (to give myself enough padding when going through the flag)
and then continue appending '''a'''s until I got back 4 identical blocks
essentially meaning I got back this:

```  
[random (nchars) + 'a'(16-n)][16*'a'][16*'a'][16*'a'][16*'a'][flag (multiple
blocks)]  
```

Now we can simply use the technique outlined above to find the flag. I
automated the entire process which took a while and the solving was slow since
the connection sucked and I had to wait around 0.8s/request but in the end it
worked.

[full code on github]

Original writeup
(https://github.com/Gdasl/CTFs/blob/master/CSAW2019/Crypto/Byte-me/Byte-
me.md).