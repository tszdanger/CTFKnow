## Arithmetic  
![date](https://img.shields.io/badge/date-11.02.2020-brightgreen.svg)
![general category](https://img.shields.io/badge/Category-General-
lightgrey.svg) ![score](https://img.shields.io/badge/score-150-blue.svg)

### Description  
Ian is exceptionally bad at arthimetic and needs some help on a problem: x +
2718281828 = 42. This should be simple... right?

```  
HINT: What does uint32_t mean?  
```

### Solution  
I was really stuck on this problem mainly because the math didn't add up (get
it?!) They're asking us to input a number that stands true to the comparison.
But what threw me off was that you CAN'T input negative numbers. A normal
person would think its:  
x = -2718281786  
So I was stuck. Until I looked at the hint. "What does uint32_t mean?".  
uint_32 is the same as an unsigned integer. Ok so that explains why we
couldn't use negatives. But when I searched up "uint_32 vulnerability" I found
a CVE talking something called "integer overflow". What's that you ask?  
Integer overflow occurs when an arithmetic operation (+/-/*//) attempts to
create a numeric value that is outside of the range that can be represented
with a given number of digits.  
Since we know that uint_32 is an integer, we know that its maximum value is
2^32-1 which is 4294967295.  
> Tip: There is also uint_16 (short) and uint_64 (long) which have different
> max values as well!

So an integer overflow occurs when you go over the limit of its expected value
so the value turns into 0.

After this aha moment, I did the maths:  
4294967296 - 2718281828 + 42 = 1576685510

> The reason why I added one to uint_32's maximum value (4294967295) is
> because we also need to account for when the value turns to 0

So once I entered the number, I received the flag!

```  
> nc challenges.ctfd.io 30165  
Enter your number:  
1576685510  
flag: nactf{0verfl0w_1s_c00l_6e3bk1t5}  
```

### Flag  
```  
nactf{0verfl0w_1s_c00l_6e3bk1t5}  
```

Original writeup (https://github.com/JoshuEo/CTFs/tree/master/NACTF_2020).