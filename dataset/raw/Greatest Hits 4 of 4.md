This is what we're given:

```  
flag="REDACTED"  
import random  
import time  
print(time.time())  
#1697043249.53  
time.sleep(random.randint(0, 50))  
random.seed(int(time.time()))  
ct=""  
for c in flag:  
   ct += chr(random.randint(0,255) ^ ord(c))  
print(ct.encode('hex'))  
#a0469bbb0b3a4f06306739032244b0c5119ba66a0d3b5a2322acdd7070bf85690cdf8573212c1b927e0ba624  
```

This problem seems pretty trivial at first! All it does is take the time and
wait for some amount of seconds between 0 and 50 before setting a random seed.  
The below program is a very simple implementation of decryption -- loop
through all possible numberof seconds, perform the XOR, and print if it's all
ASCII.  
```  
import random  
import string  
#import binascii  
import time

def is_ascii(s): # GeeksForGeeks  
   """Return True if string s is ASCII, False otherwise."""  
   return all(c in string.printable for c in s)

c =
"a0469bbb0b3a4f06306739032244b0c5119ba66a0d3b5a2322acdd7070bf85690cdf8573212c1b927e0ba624"  
#c = binascii.unhexlify(c)  
inittime = int(1697043249.53)

for i in range(51):  
   res = ""  
   random.seed(inittime)  
   #print(i, chr(random.randint(0, 255) ^ c[0]))  
   for j in range(0,len(c), 2):  
       res += chr(random.randint(0,255) ^ int(c[j:j+2], 16))  
   if is_ascii(res):  
       print(res)  
```  
But it doesn't work! Why?  
Admittedly, I spent an incredibly long time on this one step trying to figure
out why it wasn't working. But then, I finally came to a realization.  

The source code is written in Python 2, which we can tell by the
.encode("hex") function call. "hex" is not a valid encoding in Python 3.  
Since time.time() changes in Python 2, we need to run this in Python 2! I just
used an online Python 2 interpreter to run it:  

	UDCTF{4hh_m3m0r1es_th4t5_wh4t_1ts_4ll_about}