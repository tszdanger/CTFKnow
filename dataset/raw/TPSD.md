# TPSD

## Source

Solving Diophantine equations is a notoriously challenging problem in number
theory, and finding non-trivial integer solutions for certain equations is
considered a major open problem in mathematics.

## Exploit

There is no script provided, so we will manually interact with the challange
to get the instructions using python and pwntools.

![Open Url for the Interaction png](https://github.com/AKSLEGION/Crypto-
Writeups/blob/master/Crypto_CTF_2023/TPSD/Interaction.png?raw=true)

- So, the challenge asks us to send 3 integers p,q and r such that `p^3+q^3+r^3 = 1`. It also gives us the range of how long the bit length of p,q and r should be for each level.  
- Also atleast one of those 3 must be prime.

- We can generate p,q and r such that `p^3+q^3+r^3 = 1` by providing the values   
	- `P = 9*(b**4)`  
	- `Q = -3*b-9*(b**4)`  
	- `R = 1+9*(b**3)`

## Script

### 1. Setting the Connection and Function to get p,q and r  
```  
from pwn import *

host=r'05.cr.yp.toc.tf'  
port=11137

from Crypto.Util.number import *  
from math import *  
from sympy import isprime

def find_b(l,r):  
	l = round(((2**l+1)//9)**(1/3))  
	r = round(((2**r+1)//9)**(1/3))  
	for b_ in range(l,r):  
       	a = 9*(b_**3)+1  
       	if isprime(a):  
       		return b_  
```  
- Initialises the connection credentials.  
- R is the lowest absolute number among p,qand r , so we find the range of b such that R is in the given bit range and since we are starting from low to high, R will be pretty low in the range hence P and Q which are higher than R will also be in the range.  
- It checks if R is prime since we need atleast one prime and then returns b.

### 2. Getting the instructions  
```  
while True:  
	try:  
		r=remote(host,port)

		for i in range(9):  
			print(r.recvline())  
```  
- Sets up a connection to the challenge and recieves the Instruction messages.

### 3. Getting the Range and forming the 3 numbers  
```  
		while True:  
			print(r.recvline())  
			range_=r.recvline().decode().strip()  
			l_r=range_.split('(')[1].split(')')[0]  
			left,right=map(int,l_r.split(', '))  
			print(left,right)

			b = find_b(left,right)  
			P = 9*(b**4)  
			Q=-3*b-9*(b**4)  
			R=1+9*(b**3)  
```  
- This goes on as long as there is a EOF error then the first loop breaks as there is r.close and break in except block of code

### 4. Sending the numbers and getting the feedback.  
```  
			s=str(P)+','+str(Q)+','+str(R)  
			print(s)  
			r.sendline(s.encode())  
			print(r.recvline())  
	except:  
		r.close()  
		break  
```  
- Sends the numbers as many times as prompted , gets the flag, hits EOF error and breaks.

## Flag

The flag is CCTF{pr1m3S_in_7ErnArY_Cu8!c_3qu4tI0nS!}

Original writeup (https://github.com/AKSLEGION/Crypto-
Writeups/blob/master/Crypto_CTF_2023/TPSD/Exploit.md).