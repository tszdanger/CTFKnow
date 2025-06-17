## Description

```  
But clearly not tested enough... can you get the flag?

nc 167.172.123.213 12345  
```

Category: Cryptography

## Analysis

First let's look at `otp.py`:

```python  
from random import seed, randint as w  
from time import time

j = int  
u = j.to_bytes  
s = 73  
t = 479105856333166071017569  
_ = 1952540788  
s = 7696249  
o = 6648417  
m = 29113321535923570  
e = 199504783476  
_ = 7827278  
r = 435778514803  
a = 6645876  
n = 157708668092092650711139  
d = 2191175  
o = 2191175  
m = 7956567  
_ = 6648417  
m = 7696249  
e = 465675318387  
s = 4568741745925383538  
s = 2191175  
a = 1936287828  
g = 1953393000  
e = 29545

g = b"rgbCTF{REDACTED}"

if __name__ == "__main__":  
   seed(int(time()))  
   print(f"Here's 10 numbers for you: ")  
   for _ in range(10):  
       print(w(5, 10000))

   b = bytearray([w(0, 255) for _ in range(40)])

   n = int.from_bytes(bytearray([l ^ p for l, p in zip(g, b)]), 'little')  
   print("Here's another number I found: ", n)  
```

That creates a seed based on the current time, prints out 10 "random" numbers
using that seed, then generates 40 more "random" numbers and uses them to xor
the flag stored in `g`, and prints that out as a giant int.

```  
kali@kali:~/Downloads$ python3 otp.py  
Here's 10 numbers for you:  
2112  
8938  
2679  
9362  
2191  
2003  
3016  
9235  
3833  
2887  
Here's another number I found:  183833425864737726945931152645483328541  
```

## Solution

`time()` returns the number of seconds since the epoch, which means we can
measure `time()` locally before and after invoking `otp.py` and have a
relatively small range of seeds to try. We'll know when we found the right
seed because the 10 "random" numbers will match the values from `otp.py`.

```python  
#!/usr/bin/python3  
from pwn import *  
from time import time  
from random import seed, randint

context.log_level='DEBUG'  
start = int(time())  
#p = process(['/usr/bin/python3', './otp.py'])  
p = remote('167.172.123.213', 12345)  
p.recvline() # Here's 10 numbers for you:  
nums = []  
for i in range(10):  
   line = p.recvline().rstrip()  
   nums.append(int(line))

p.recvuntil("Here's another number I found:  ")  
another_num = int(p.recvline().rstrip())  
p.stream()  
end = int(time())

print("start=%u end=%u" % (start, end))  
print(nums)  
print(another_num)

s = start  
while s <= end:  
   seed(s)  
   found = True  
   for i in range(10):  
       r = randint(5, 10000)  
       if r != nums[i]:  
           found = False  
   if found:  
       print("FOUND SEED: %u" % s)  
       break  
   s += 1

g = another_num.to_bytes(40, 'little')  
b = bytearray([randint(0, 255) for _ in range(40)])  
n = bytearray([l ^ p for l, p in zip(g, b)]), 'little'  
print(n)  
```

I tested this locally first, and then just had to run it against the remote
server to get the flag:

```  
kali@kali:~/Downloads$ ./otp_solve.py  
[+] Opening connection to 167.172.123.213 on port 12345: Done  
[DEBUG] Received 0xb1 bytes:  
   b"Here's 10 numbers for you: \n"  
   b'6370\n'  
   b'578\n'  
   b'948\n'  
   b'4674\n'  
   b'4804\n'  
   b'6605\n'  
   b'2529\n'  
   b'4644\n'  
   b'3823\n'  
   b'4330\n'  
   b"Here's another number I found:
14967871060053757142096566772157693944463496219343006011424058102584\n"  
start=1594497862 end=1594497882  
[6370, 578, 948, 4674, 4804, 6605, 2529, 4644, 3823, 4330]  
14967871060053757142096566772157693944463496219343006011424058102584  
FOUND SEED: 1594497882  
(bytearray(b'rgbCTF{random_is_not_secure}\xfeF\xa9Q/O\x93/\xe2\x8d^\xf5'),
'little')  
```

The flag is:

```  
rgbCTF{random_is_not_secure}  
```

Original writeup
(https://github.com/dobsonj/ctf/tree/master/writeups/2020/rgbctf/occasionally_tested_protocol).