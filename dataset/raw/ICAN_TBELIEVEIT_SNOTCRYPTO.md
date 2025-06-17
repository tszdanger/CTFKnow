# ICAN'TBELIEVEIT'SNOTCRYPTO

This is a pretty simple challenge, once you know what is going on.

So the question asks to give two lists `l1` and `l2`, where `l1` contains only
0 and 1, and `l2` only contains 0, 1, and 2. The lists go through the function
`step()` each time, and `count()` counts how many steps it will take for `l1`
and `l2` to reach the state where `l1 = [1]` and `l2 = [0]`. The flag will be
printed if it needs more than 2000 steps.

There are two constraints, namely that `len(l1) == len(l2)` and `len(l1) <
24`. So you can't give a sufficiently large array to pass the test.

This is actually a well-known and studied problem in disguise. It is the
process described in [Collatz
conjecture](https://en.wikipedia.org/wiki/Collatz_conjecture). And `l1` and
`l2` is just a simple conversion from a number to its base-6 form, and for
each digit split across two lists. A simple conversion script looks like this:

```python  
def to_lists(num):  
   l1 = []  
   l2 = []  
   while num:  
       digit = num % 6  
       l1.append(digit & 1)  
       l2.append(digit >> 1)  
       num //= 6  
   return l1, l2

def from_lists(l1, l2):  
   num, mul = 0, 1  
   for i in range(len(l1)):  
       digit = l1[i] | (l2[i] << 1)  
       num += digit * mul  
       mul *= 6  
   return num  
```

The starting value that has the largest total stopping time within the range
of $$6^{24} \approx 10^{18}$$ is written on the Wikipedia page:

> less than 10^17 is 93571393692802302, which has 2091 steps [...]

which is enough for the required 2000 steps. Therefore the exploit is simply
something like this:

```python  
char = ord('f')  
assert(char % 6 == 0)  
l1, l2 = to_lists(93571393692802302)  
str1, str2 = "", ""  
for i in l1:  
   str1 += chr(char + i)  
for i in l2:  
   str2 += chr(char + i)  
print(str1)  
print(str2)  
```

Which gives us output string `fggffgfgfggffffgffgggf` and
`fgghfgghhhhhhghffgggfh`. Input it and we get the flag.

Original writeup (https://www.cis.upenn.edu/~hanbangw/blog/google-
ctf-2021/#icantbelieveitsnotcrypto).