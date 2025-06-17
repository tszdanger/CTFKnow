# Welcome to the Casino  
**Category :** algo

## Description :  
Have a warmup algo challenge.

nc not-really-math.hsc.tf 1337

not-really-math.pdf (documentation regarding the algorithm)

## Solution :  
This is simple python script where it connects and reads the data line by line
using pwntools.  
```  
#!/usr/bin/env python3

import sys  
from pwn import *

HOST = 'not-really-math.hsc.tf'  
PORT = 1337

def operator(given_str):  
   new_str = '((' + given_str.replace('a', '+').replace('m', ')*(') + ')) %
(2**32 - 1)'  
   return str(eval(new_str))

conn = remote(HOST, PORT)  
print(conn.recvline())  
given_str = conn.recvline()  
print(given_str.decode('utf-8'))  
conn.send(operator(given_str.decode('utf-8').replace('\n', '')) + "\n")

for i in range(11):  
   given_str = conn.recvline()  
   print(given_str.decode('utf-8'))  
   conn.send(operator(given_str.decode('utf-8').replace('\n', '')[2:]) + "\n")

#while True:  
print(conn.recvline())  
```

Here the core logic is *operator()* function where the received string is
taken and modified for the python eval function.

a replaced with `+`

m replaced with `)*(`

Note: add `(` & `)` at begining & ending as required.  
# Flag :  
flag{yknow_wh4t_3ls3_is_n0t_real1y_math?_c00l_m4th_games.com}

Original writeup
(https://github.com/kalyancheerla/writeups/blob/main/2021/hsctf_8/not-really-
math/operator.py).