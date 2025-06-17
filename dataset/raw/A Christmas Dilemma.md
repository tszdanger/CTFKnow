# **A Chrismas Dilemma**

## Points : 205

Santa accidentally mixed up his personal Advanced Algebra problem book with a
children's book that was supposed to be a present! Now, the algebra book
arrived at Little Timmy, who's a math whizz himself. However, he needs your
help, because this problem is just too hard for him to solve on his own!

Server: nc 199.247.6.180 14001

Author: Gabies

When I netcat to the server, it requires captcha!

```  
CAPTCHA!!!  
Give a string X such that md5(X).hexdigest()[:5]=952da.  
```

It can be bruteforce easily using python:

```  
s.recvuntil("Give a string X such that md5(X).hexdigest()[:5]=")  
 target = s.recvuntil(".\n")[:-2]  
 i = 0  
 while True:  
   if hashlib.md5(str(i)).hexdigest()[:5] == target:  
       s.sendall(str(i)+ "\n")  
       break  
   i += 1  
```

After I bypass the captcha :

```  
Ok, you can continue, go on!  
This Christmas' dilemma is:  
Given a random function defined in range (-25, 121) find the global maximum of
the function!  
You can send at most 501 queries including guesses.  
The guessed value must be equal to the real answer up to 2 decimals.

Choose your action:  
[1] Query the value of the function at some point  
[2] Guess the global maximum  
```

It looks like we need to find the maximum value of f(x) with query (121+25) =
146 X value, whic is good because is way more less than 500 query limit

First we collect the f(x) value with all possible value of x with Python:

```  
s.recvuntil("Given a random function defined in range ")  
 functionRange = s.recvuntil(")").replace('(','').replace(')','').replace('
','').split(',')  
 functionRange[0] = int(functionRange[0])  
 functionRange[1] = int(functionRange[1])  
 print "Collecting Y values:"  
 y = []  
 for i in range(functionRange[0],functionRange[1]+1,1):  
   s.sendall("1\n")  
   s.sendall(str(i) + '\n')  
   s.recvuntil(") = ")  
   solution = s.recvuntil('\n')[:-1]  
   print solution  
   y.append(float(solution))  
```

Using the Maximum value we can increase the precision of x value by using x
value minus and add the gap value, and query both x value see which one give
more f(x) value, and the gap will divide by 2 every loop:

```  
x = functionRange[0] + y.index(max(y))  
 print "Max Y: " + str(max(y))  
 maxY = max(y)  
 gap = 0.5  
 while True:  
   s.sendall("1\n")  
   time.sleep(1)  
   s.sendall(str(x+gap) + '\n')  
   s.recvuntil(") = ")  
   solution = float(s.recvuntil('\n')[:-1])  
   s.sendall("1\n")  
   time.sleep(1)  
   s.sendall(str(x-gap) + '\n')  
   s.recvuntil(") = ")  
   solution2 = float(s.recvuntil('\n')[:-1])  
   if solution > maxY:  
     x += gap  
     print "X: " + str(x)  
     print "Y: " + str(solution)  
     maxY = solution  
   elif solution2 > maxY:  
     x -= gap  
     print "X: " + str(x)  
     print "Y: " + str(solution2)  
     maxY = solution2  
   else:  
     gap /= 2  
     print "Continue"  
     continue  
```

Every time after querying, we guess the bigger solution. It will guess until
the answer is correct because of while True:

```  
print "Guessing: " + str(maxY) + " Gap: " + str(gap)  
   s.sendall("2\n")  
   time.sleep(1)  
   s.sendall(str(maxY) + '\n')  
   s.recvuntil("Enter your guess: ")  
   print s.recvuntil(".")  
   gap /= 2  
```

After some debugging we get the flag:

```  
X: 80.5625  
Y: 25.8987586495  
Guessing: 25.8987586495 Gap: 0.0625  
Congratulations! Here's your flag!  
X-MAS{Th4nk5_for_m4k1ng_a_ch1ld_h4ppy_th1s_Chr1stma5}  
```  
The full source code: [Source
Code](https://github.com/Hong5489/XmasCTF/blob/master/pwnbase.py)