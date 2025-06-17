This time we get C source code and server address. Main function seems safe,
so I started from set_new_env().  
It reads our input, clears all environment variables, saves our variables and
then attempts to sanitize them.  
Unfortunately readenv() function does not seem to contain any bug. I hoped
this will be another buffer overflow challenge, but  
```c  
fgets(line, sizeof(line), stdin)  
```  
successfully prevents it. filter_env() is more interesting. After sanitizing
variables it sorts them. I tried to find vulnerability there, but it just
sorted all the arrays I gave it without any problems.  
The list of unsafe variables also seems secure (but I knew only LD_PRELOAD, so
maybe I'm wrong). The only code left is  
```c  
for (p = unsafe; *p != NULL; p++) {  
   if (getenv(*p) != NULL) {  
     if (setenv(*p, "", 1) != 0)  
	err(1, "setenv");  
   }  
 }  
```  
It iterates through all unsafe variables, calls getenv with their name as the
parameter and eventually sets them to empty string.  
It's worth to note that we iterate through each unsafe variable only once. And
getenv() returns only one result. setenv() works in a similar way, it just
operates on a first variable with given name.  
However, it seems that system uses the last variable. So if we pass
`LD_PRELOAD` twice and provice our own shared object, we could get code
execution.  
We can use `ltrace` to see which functions does `usr/bin/id` calls.  
The first one is `__libc_start_main`, so we can overwrite it.  
To compile the library we can use:  
```  
gcc obj.c -o obj -shared -fPIC  
```  
(it didn't work for me without -fPIC)

To avoid problems we can base64 encode our binary. Then we have to paste it on
server, decode and pass its path as LD_PRELOAD value in filterenv.

[Final exploit](https://github.com/BOAKGP/CTF-
Writeups/blob/master/Google%20CTF%202018%20Quals%20Beginners%20Quest/Filter%20env/exploit.py)

Flag: `CTF{H3ll0-Kingc0p3}`

Original writeup (https://github.com/BOAKGP/CTF-
Writeups/tree/master/Google%20CTF%202018%20Quals%20Beginners%20Quest/Filter%20env).