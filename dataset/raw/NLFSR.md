# NLFSR

## Information  
- category: crypto  
- points: 235

## Description  
Easy lfsr easy crypto

链接：https://share.weiyun.com/5qZbNLR 密码：n9huwc
https://drive.google.com/open?id=1a5GMVZ77CM1rOrayKJcV3UvMwAy-uGsg

## Writeup  
First of all, I solved this challenge together with
[meowmeowxw](https://meowmeowxw.gitlab.io/)

To understand how a general nlsr works, please read this
[article](https://ctf-wiki.github.io/ctf-wiki/crypto/streamcipher/fsr/nfsr/)
from ctfwiki.  
What did we learn from that article? That we must find a strong correlation
between the output and one of the input.  
So we made a little script to retrieve the truth table of  
```py  
(ao * bo) ^ (bo * co) ^ (bo * do) ^ co ^ do  
```

The table retrieved is the following:

![alt text](table.jpg "Truth Table")

Is possible to see that the parameter A has a strong correlation with the
output (75% of times, if A=0 then the output is 0).  
So we can calculate this value using the same approach described in the
article mentioned before. I modified it slightly and the result is the
following code:

```py

mapA = {  
   (0,): 0  
}

def lfsr(r, m):  
   output = ((r << 1) & 0xffffff) ^ (bin(r & m).count('1') % 2)  
   last_bit = (bin(r & m).count('1') % 2)  
   return output, last_bit

def guessA(maps: {}, rang, a, data, res):  
   ma= 0x505a1  
   old_a = a  
   for a in rang:  
       a = old_a  
       good = 0  
       total = 0  
       for j in range(0, len(data)):  
           to_check = ()  
           output = int(data[j])  
           a, a_bit = lfsr(a, ma)  
           to_check += (a_bit, )

           expected_res = maps.get(to_check, None)  
           if expected_res is None:  
               continue  
           if expected_res == output:  
               good += 1  
           total += 1  
       if total != 0:  
           ratio = good * 100 / total  
           if ratio >= 70:  
               res.append(var)

   return sorted(res, reverse=True)

```  
This function will return the values of every number that has a correlation
greater than 70, and only the value 363445 has this property  
Now we can retrieve the value of B. This is possible because, reading the
truth table, if we know the value of A, and the output O, it is possible to
bruteforce the value B having as constraints:  
- If A is 1 and the output is 1, B must be 1.  
- If A is 0 and the output is 0, B must be 1.

Again only 1 value comply with the constraints.  
At this point, we tried to find a correlation with C and D, having A,B and
output. But we did not find any correlation, so we decided to bruteforce
something.  
Since D are only ~40 values, we can try every value of D and use the complete
truth table to retrieve the value of C for that particular D.  
Of course the last possible value of D was the right one, and thank to that we
find the valid value for C.

The values were: A=363445, B=494934, C=4406, D=63.  

Original writeup
(https://github.com/0ssigeno/Writeups/blob/master/de1CTF2020/nlfsr/writeup.md).