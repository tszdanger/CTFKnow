## Description of the challenge

Welcome to MaaS - Modulo as a Service!

Author: NoobMaster

## Solution

We are presented with the following challenge:

```py  
#!/usr/bin/python3  
import random  
from Crypto.Util.number import *  
flag = open('flag.txt').read()  
alpha = 'abcdefghijklmnopqrstuvwxyz'.upper()  
to_guess = ''  
for i in range(16):  
	to_guess += random.choice(alpha)  
for i in range(len(to_guess)):  
	for j in range(3):  
		inp = int(input(f'Guessing letter {i}, Enter Guess: '))  
		guess = inp << 16  
		print(guess % ord(to_guess[i]))  
last_guess = input('Enter Guess: ')  
if last_guess == to_guess:  
	print(flag)  
else:  
	print('Incorrect! Bye!')  
	exit()  
```

Briefly - the challenge generates a 16 bytes array, containing values from A
to Z. It then asks you to guess the bytes (in a weird way), given the result
``guess % ord(to_guess[i])``, where ``guess`` is your input multiplied by 2^16
and ``ord(to_guess[i])`` is the ascii code of the byte you need to guess.
Then, you are given one "last guess", where you have to input all the 16
bytes, in plaintext.

Our initial idea for this challenge was to test if there perhaps is a number
we can input, that would give different remainders for the given operation.
Then we can map the remainders uniquely to each letter in the alphabet and use
the same guess every time. With the remainders mapped, it is trivial to
recover the letters.

```py  
#!/usr/bin/python3  
alpha = 'abcdefghijklmnopqrstuvwxyz'.upper()

fg = -1 # found g  
sol = {}  
for g in range(10000):  
   mods = []  
   for i in alpha:  
       m = (g<<16) % ord(i)  
       fg = g  
       if m in mods: # if this remainder (m) is already in the mods list, then stop  
           break     # g does not produce unique remainders for all letters  
       mods.append(m)

   if len(mods) == len(alpha): # this condition will only be true if we found
a g with unique remainders  
       print(fg) # print found g  
       for let, rem in zip(alpha, mods):  
           sol[let] = rem # map remainders to letters

       for let, rem in sorted(sol.items(), key=lambda x: x[1]):  
           print(f"{rem} : '{let}',")  
```

We find ``fg = 9152`` that produces unique remainders. We write a script to
automate the interaction with the server:

```py  
#!/usr/bin/env python3

from pwn import *

g = b"9152"

# the map we found earlier  
d = {  
   0 : 'X',  
   2 : 'Z',  
   5 : 'E',  
   6 : 'J',  
   8 : 'L',  
   13 : 'O',  
   20 : 'T',  
   25 : 'I',  
   26 : 'N',  
   32 : 'P',  
   40 : 'D',  
   44 : 'B',  
   47 : 'K',  
   50 : 'G',  
   52 : 'A',  
   54 : 'Y',  
   55 : 'M',  
   56 : 'H',  
   57 : 'U',  
   58 : 'V',  
   62 : 'F',  
   65 : 'C',  
   74 : 'Q',  
   77 : 'W',  
   80 : 'R',  
   82 : 'S'  
}

target = remote('challs.n00bzunit3d.xyz', 51081)  
sol = []  
for i in range(16*3):  
   target.sendline(g)  
   out = target.recvline()  
	# we have 3 guesses, collect output only once, our solution works with one guess only  
   if i % 3 == 0:  
       let = d[int(out.split()[-1])]  
       print(let)  
       sol.append(let)  
target.sendline("".join(sol).encode())  
target.interactive()  
```

After the competition, we saw that the intended solution was to use the 3
guesses for each byte to have 3 remainders for each letter. Checking each of
them would achieve the same uniqueness, therefore avoiding collisions.

Original writeup (https://dothidden.xyz/n00bzctf_2023/maas/).