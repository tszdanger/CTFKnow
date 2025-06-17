# brie-man

**Category**: misc \  
**Difficulty**: easy \  
**Points**: 200 points (39 solves) \  
**Author**: yyyyyyy

Do you ever dream of solving a famous open question?

(Now that we have your attention: Sorry, this challenge has nothing to do with
Brie. ?)

Download: [brie_man.tar.xz](brie_man.tar.xz)

## Overview

Very short challenge:

```python  
#!/usr/bin/env sage  
import re

if sys.version_info.major < 3:  
   print('nope nope nope nope | https://hxp.io/blog/72')  
   exit(-2)

rx = re.compile(r'Dear Bernhard: Your conjecture is false, for ([^ ]{,40}) is
a counterexample\.')

s = CC.to_prec(160)(rx.match(input()).groups()[0])

r = round(s.real())  
assert not all((s==r, r<0, r%2==0))     # boring

assert not s.real() == 1/2              # boring

assert zeta(s) == 0                     # uhm ok  
print(open('flag.txt').read().strip())  
```

The problem is referencing the  
[Riemann hypothesis](https://en.wikipedia.org/wiki/Riemann_hypothesis).

## Solution

> Solved with @ndrewh

Satisfying the `assert` statements doesn't seem to be possible, but after  
playing around with it for a while, I noticed some weird behavior:

```python  
sage: CC.to_prec(160)('2i')  
Traceback (most recent call last):

 File "/home/plushie/.local/lib/python3.8/site-
packages/IPython/core/interactiveshell.py", line 3437, in run_code  
   exec(code_obj, self.user_global_ns, self.user_ns)

 File "<ipython-input-1-71bddf1253b5>", line 1, in <module>  
   CC.to_prec(Integer(160))('2i')

 File "/usr/lib/python3/dist-packages/sage/rings/complex_field.py", line 387,
in __call__  
   return Parent.__call__(self, x)

 File "sage/structure/parent.pyx", line 900, in
sage.structure.parent.Parent.__call__
(build/cythonized/sage/structure/parent.c:9218)  
   return mor._call_(x)

 File "sage/structure/coerce_maps.pyx", line 161, in
sage.structure.coerce_maps.DefaultConvertMap_unique._call_
(build/cythonized/sage/structure/coerce_maps.c:4556)  
   raise

 File "sage/structure/coerce_maps.pyx", line 156, in
sage.structure.coerce_maps.DefaultConvertMap_unique._call_
(build/cythonized/sage/structure/coerce_maps.c:4448)  
   return C._element_constructor(x)

 File "/usr/lib/python3/dist-packages/sage/rings/complex_field.py", line 413,
in _element_constructor_  
   sage_eval(x.replace(' ',''), locals={"I":self.gen(),"i":self.gen()}))

 File "/usr/lib/python3/dist-packages/sage/misc/sage_eval.py", line 202, in
sage_eval  
   return eval(source, sage.all.__dict__, locals)

 File "<string>", line 1  
   2i  
    ^  
SyntaxError: unexpected EOF while parsing  
```

Checking `_element_constructor_()` in `complex_field.py`, we see this mildy  
suspicious comment.

```python  
               # TODO: this is probably not the best and most  
               # efficient way to do this.  -- Martin Albrecht  
               return ComplexNumber(self,  
                           sage_eval(x.replace(' ',''), locals={"I":self.gen(),"i":self.gen()}))  
```

At the end of the backtrace, we also see

```python  
return eval(source, sage.all.__dict__, locals)  
```

```  
$ nc 65.108.178.230 7904  
Dear Bernhard: Your conjecture is false, for print(open('flag.txt').read()) is
a counterexample.  
hxp{0NE_M1LL10N_D0LLAR5}  
```

## Note

This snippet was likely a hint, since the linked write-up shows a similar  
solution for a challenge from DEF CON Quals 2020.

```python  
if sys.version_info.major < 3:  
   print('nope nope nope nope | https://hxp.io/blog/72')  
   exit(-2)  
```  

Original writeup (https://github.com/cscosu/ctf-
writeups/tree/master/2021/hxp_ctf/brie-man).