# extended-fibonacci-sequence (251 solves/ 379 points)  
## Description  
hmm, fibonacci is fun, right?

``nc extended-fibonacci-sequence.hsc.tf 1337``

P.S: This chall was made by an anonymous CS Club member :)

[Extended Fibonacci Sequence
New.pdf](https://hsctf.storage.googleapis.com/uploads/fd42dceca6a9c52aff6414a7521c5033abfc8be076d2e978f38ac7049e6ce7ac/Extended%20Fibonacci%20Sequence%20New.pdf)  
## Solution  
Despite few solves, I had an easier time with this than [not-really-
math](https://github.com/BASHing-thru-
challenges/HSCTF-2021-Writeups/tree/main/algo/not-really-math).  
I wrote a basic python function ``fib(n)`` that gives me the Fibonacci number
in the sequence F<sub>n</sub> using recursion:  
```python3

def fib(n):  
   if n <= 1:  
       return n  
   return fib(n - 1) + fib(n - 2)

```  
I did the same thing for the Extended Fibonacci sequence S<sub>n</sub> again
with recursion:  
```python3

def exFib(n):  
   if n <= 0:  
       return "0" + str(fib(n))  
   return exFib(n - 1) + str(fib(n))

```  
At this point I could find the summation of the series using a for loop and a
list. I used a string slice to grab the last 11 digits of the number and sent
it to the nc server  
with pwntools.

After attempting I realised my fib calculations were way to slow. I used a
library called functools to easily cache previously calculated fibs to speed
up the program and it  
did the trick.

Final script:  
```python3

from pwn import *  
import functools  
import re

@functools.lru_cache(None)  
def fib(n):  
   if n <= 1:  
       return n  
   return fib(n - 1) + fib(n - 2)

@functools.lru_cache(None)  
def exFib(n):  
   if n <= 0:  
       return "0" + str(fib(n))  
   return exFib(n - 1) + str(fib(n))

def addList(list):  
   total = 0  
   for num in list:  
       total += num  
   return total

io = process(['nc', 'extended-fibonacci-sequence.hsc.tf', '1337'])  
io.recvline()  
while True:  
   try:  
       data = io.recvuntil(":").decode()  
   except EOFError:  
       print(io.recvline().decode())  
       quit()  
   n = int(re.search("(\d{1,})\n", data).group(0))  
   print("[RECIEVE]: " + str(n))  
   summ = []  
   for i in range(1, n + 1):  
       summ.append(int(exFib(i).lstrip('0')))  
   final = str(addList(summ))  
   final = final[len(final) - 11:]  
   io.sendline(final)  
   print("[SEND]: " + final)

```  
Run the script and out pops the flag!  
## Flag  
``flag{nacco_ordinary_fib}``  

Original writeup (https://github.com/BASHing-thru-
challenges/HSCTF-2021-Writeups/tree/main/algo/extended-fibonacci-sequence).