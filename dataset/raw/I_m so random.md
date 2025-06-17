## Challenge name:      I'm so Random

### Description:  
> Aplet's quirky and unique so he made my own PRNG! It's not like the other
> PRNGs, its absolutely unbreakable!  
>  
> nc crypto.2021.chall.actf.co 21600  
>  
> P.S: given files: *[chall.py](./chall.py)*

### Solution:

According to code, we can ask the server to give us random number up to 3
times. How server generates random number? Simple, just generates 2 random
number with *Generator* and multiples them.

   class Generator():  
       DIGITS = 8  
       def __init__(self, seed):  
           self.seed = seed  
           assert(len(str(self.seed)) == self.DIGITS)

       def getNum(self):  
           self.seed = int(str(self.seed**2).rjust(self.DIGITS*2, "0")[self.DIGITS//2:self.DIGITS + self.DIGITS//2])  
           return self.seed

   r1 = Generator(random.randint(10000000, 99999999))  
   r2 = Generator(random.randint(10000000, 99999999))

   ...

           if query.lower() == "r" and query_counter < 3:  
               print(r1.getNum() * r2.getNum())

First, I was trying to break generator some how, then I relized there is no
need to break generator. All we need to do is get a random number from server,
try to divide it to r1 and r2 and create next numbers. To verfy that, we get
another random number from server and compare our results to them.

   def find_r(x, y):  
       d = divisors(x)  
       print ('\t|Divisors:\n{0}\n'.format(d))  
  
       for r1 in d:  
           if (valid(r1) == False):  
               continue  
           r2 = x // r1  
           if (valid(r2) == False):  
               continue  
  
           print ('\t|p1: {0}\n\t|p2: {1}\n'.format(r1, r2))  
  
           g1 = Generator(r1)  
           g2 = Generator(r2)  
  
           o = g1.getNum() * g2.getNum()  
           if (o == y):  
               return (r1, r2)  
  
       raise Exception('divisors not found')

Note: For finding divisors, I used sagemath library.

[final exploit.py](./exploit.py)

**Output**

   [+] Opening connection to crypto.2021.chall.actf.co on port 21600: Done  
   [*] Randoms recovery phase  
   [*] Checking divisors:  
       |p1: 15525328  
       |p2: 96681138  
   [*] Checking divisors:  
       |p1: 15628704  
       |p2: 96041641  
   [*] Checking divisors:  
       |p1: 16113523  
       |p2: 93151968  
   [*] Checking divisors:  
       |p1: 19076107  
       |p2: 78685152  
   [*] Checking divisors:  
       |p1: 19671288  
       |p2: 76304428  
   [*] Checking divisors:  
       |p1: 23287992  
       |p2: 64454092  
   [*] Checking divisors:  
       |p1: 26228384  
       |p2: 57228321  
   [*] Guessing phase  
   [+] Next random: 331960767242752  
   [+] Next random: 1995896433251328  
   b"Congrats! Here's your flag:
\nactf{middle_square_method_more_like_middle_fail_method}\n"

**The Flag**

   actf{middle_square_method_more_like_middle_fail_method}  

Original writeup (https://github.com/RaaCT0R/CTF-
Challenges/blob/master/cryptography/angstrom2021/im_so_random/WRITEUP.md).