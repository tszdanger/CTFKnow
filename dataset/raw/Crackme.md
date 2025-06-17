https://waletsec.github.io/posts/2021-03-14-Crackme.html

Original writeup (https://waletsec.github.io/posts/2021-03-14-Crackme.html).We solved this problem mostly blackbox.

Running the binary we get no output, and if we input a string in flag format
like `F#{asdf1234}`, we will get something like `H4c#hZSF0SWI{` with a long
delay, where `H4c` is the start of this challenge's description `H4ck1ng
Fl4m3s In th3 Sh3lL`. If we input the correct flag, we'll probably get the
entire description string as output. So we can simply brutefore the flag byte
by byte. Here is my original script:

```python  
from pwn import *

context.log_level = 'debug'  
chars = '_#G1VWk92{5toOnCQF6zXpifDh8SdYlev uq0RMajKsrHUx}IyTbgAm3L4BcNEZJ7w'  
flag = 'F#{'  
dest = 'H4ck1ng Fl4m3s In th3 Sh3lL'

def sim(a, b):  
	if len(a) * len(b) == 0:  
		return 0  
	i = 0  
	while a[i] == b[i]:  
		i+=1  
	return i

def test(ch):  
	s = process('crackme')  
	s.sendline(flag + ch)  
	ret = s.recv()  
	s.close()  
	return ret

for i in range(len(dest) ):  
	for c in chars:  
		if sim(test(c), dest) == i + 4:  
			flag += c  
			print flag  
			break  
```  
Runing the script, we found the program outputs with a long delay if we
guessed wrong, and the program will output instantly if we guessed right. So
we can just add a timeout when reading the output to accelerate the
bruteforce:  
`ret = s.recv(timeout=1)`  
And we can get the entire flag in a few minutes:  
`F#{M4k3_R3v3rse_gr3at_Ag41N}`

Full script (only timeout added):  
```python  
from pwn import *

context.log_level = 'debug'  
chars = '_#G1VWk92{5toOnCQF6zXpifDh8SdYlev uq0RMajKsrHUx}IyTbgAm3L4BcNEZJ7w'  
flag = 'F#{'  
dest = 'H4ck1ng Fl4m3s In th3 Sh3lL'

def sim(a, b):  
	if len(a) * len(b) == 0:  
		return 0  
	i = 0  
	while a[i] == b[i]:  
		i+=1  
	return i

def test(ch):  
	s = process('crackme')  
	s.sendline(flag + ch)  
	ret = s.recv(timeout=1)  
	s.close()  
	return ret

for i in range(len(dest) ):  
	for c in chars:  
		if sim(test(c), dest) == i + 4:  
			flag += c  
			print flag  
			break  
```