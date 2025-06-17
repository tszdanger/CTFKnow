# FireShell CTF Writeups

Fireshell CTF was a decent CTF that took place 1/26/2019. Some of the
challenges were pretty cool, but derivative of past challenges. Some of the
"cons" of the CTF are that there was unscheduled downtime, late-added
challenges, weird dynamic scoring (one of the questions had 3 less solves but
was worth twice as many points as another question) and a language barrier
that made some questions a bit harder than they needed to be.

I'm composing a couple write-ups for the questions I completed that don't have
writeups on ctftime.

# Biggars

### Overview

Given a text file [which I renamed to biggars.py so I could import it easily
into my python code] with the variables e, N, C defined. The question's text
is pretty irrelevant.

### The Solve

Since the question gives the tuple `(e,N,C)` without any further info, we can
immediately assume this is an RSA question (see reference 1). In short, we
know `M^e = C mod N` and want to find `d` such that `d*e = 1 mod phi(N)` so we
can calculate `C^d = M mod N`. Most of the time RSA questions are solved by
computing `phi(N)` after factoring `N`. Sometimes we calculate `d` directly.

Most `N` are around 1024-4096 bits... Taking a look at this one, it is over
500,000 bits long. This is very fishy and my intuition here is that `N` can be
factored (and probably very quickly). My first step for RSA problems is always
to pop `N` into [factordb.com](factordb.com), but it is too large for the
server. The alternative is to enter a `sage` shell and utilize their built-in
number theory functionality. Import the three variables into the shell so we
can use them, and `factor(N)` to see that `N` can be fully factored in
milliseconds! This is good news, and makes the rest of the problem fairly
straightforward.

Sage is a real workhorse here. `p = euler_phi(N)` calculates euler's totient
for us. Then `d = inverse_mod(e, p)` calculates the multiplicative inverse of
`e mod p`, our decryption exponent. Now a quick calculation of `M =
pow(C,d,N)` and...

*10 minutes later*

Ok, the calculation still isn't complete, it looks like the numbers may be too
big to compute efficiently. To be on the safe side I open a new terminal tab
running a `pypy` shell on my Linux laptop alongside the original `sage` tab,
and a regular python shell on my beefier desktop to see if either will finish
more quickly, and let them compute for awhile. After ~30 minutes, the original
sage computation finishes first, yielding the number `M =
2285997671207389169910475407268635357578225559267332896350087006464155634525015356776294350090`.
Intuitively, this is a good number to see because if one of my previous steps
was incorrect, then `M` would essentially be random bits with length ~= to the
length of `N`. Since `M` is so small, it is unlikely to be wrong. My first
instinct is to convert this integer to its ascii value, which can be done with
the pyCrypto library function long_to_bytes: `from Crypto.Util.number import
long_to_bytes`, and finally `print(long_to_bytes(M))`, which yields the flag!

### References

1. [https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Operation](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Operation)  
1. [http://www.sagemath.org/](http://www.sagemath.org/)  
1. [https://github.com/dlitz/pycrypto](https://github.com/dlitz/pycrypto)

# Python Learning Environment

### Overview

This question gives a link to a webpage with a hint that implies we are in
some sort of limited web shell for python. We have a text box that POSTs our
input to the server and responds with the output of our commands. Some basic
recon reveals the python web shell is pretty strict and probably want to
execute system code to read a file or interact somehow with the OS.

It becomes clear pretty quickly that we can't directly interact with the OS.
The webpage has a javascript filter that parses the request and removes
certain keywords. The request will print simply a `syntaxerror on line X`
whenever something goes wrong, which isn't very descriptive. From my
experimentation, I gather:

1. Some strings such as `'os'` and `'subprocess'` are illegal and removed by the javascript filter  
2. The __builtins__ attribute is cleared - this means no builtin functions such as int(), chr(), etc. Notably, we can't import or use __import__  
3. Square brackets `[`, `]` are illegal and removed  
4. Ints are messed with, I didn't figure out exactly how but most ints are converted into another int - so I avoided them completely  
5. Only the variable `test` is allowed. I'll add a little more challenge by making this a 1-liner. [I was apparently incorrect about this, but it affected my solve]

I generally follow along with the first reference below. The general strategy
is to:

1. Access the base object class  
1. Use that to access the warnings.catch_warnings subclass  
1. Follow the members to the `__builtins__` attribute of this class  
1. Use **this** `__import__` to import subprocess  
1. subprocess.check_output() to run commands

You can follow along at home in a regular python shell by following the
guidelines above.

### The Solve

First, doing `test = {}.__class__.__base__.__subclasses__()` works fine and as
expected. We now have the classes list.

Second, we need to access the catch_warnings subclass. In our case, it is the
59th element of the list, but we can't directly access it using brackets, and
even if we could, we can't directly use an int. So we need an alternative.
`dir(test)` gives a list of the methods we can use. `__getitem__` would work,
but it gets filtered out by the javascript, so I went with `pop(X)`, which
returns the element at the `X` position. This dir also gives us a solution to
the `int` problem - `index`.

Next, we can build a tuple to return us the proper int:
`(('a')*59+('b')).index('b')` returns 59. Let's add this in to our command:
`test =
{}.__class__.__base__.__subclasses__().pop((('a')*59+('b')).index('b'))()`. We
can append `._module.__builtins__` without issue to get a dict, from which we
need to access the value corresponding to the key `'__import__'`.

Fourth, run `print test.keys()` to show we need the 109th value from this
list. We could access the corresponding values list and return our value with
`test.values()[109]`, but we need to use the same `pop`/`index` workaround as
before to get to the `__import__` function: `test =
{}.__class__.__base__.__subclasses__().pop((('a')*59+('b')).index('b'))()._module.__builtins__.values().pop((('c')*109+('d')).index('d'))`
is the function object for `__import__`! Now we can call it to import
subprocess, but since `'subprocess'` is blacklisted, a simple bypass `'sub' +
'pro' + 'cess'` bypasses this.

Finally, since subprocess is imported, we can interact with the system using
`subprocess.check_output(cmd)`. First, to enumerate our test system let's run
`'ls'` with `subprocess.check_output('ls')`: `print
{}.__class__.__base__.__subclasses__().pop((('a')*59+('b')).index('b'))()._module.__builtins__.values().pop((('c')*109+('d')).index('d'))('subprocess').check_output('ls')`
prints the directory. Luckily, one of the file names is the flag and we are
done!

### References

1. https://gynvael.coldwind.pl/n/python_sandbox_escape  
1. http://wapiflapi.github.io/2013/04/22/plaidctf-pyjail-story-of-pythons-escape/  

Original writeup
(https://github.com/FSUMitch/WriteUps/blob/master/FireShell%20CTF%202019/readme.md#biggars).