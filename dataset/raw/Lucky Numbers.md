We're given a program for which we need to find the "lucky numbers."

Firstly, it provides constraints on the numbers we input:

```  
s=int(data2)  
t=int(data3)  
if s<random.randrange(10000,20000):  
		print("I have the feeling the first number might be too small")  
		continue  
if s>random.randrange(150000000000,200000000000):  
		print("I have the feeling the first number might be too big")  
		continue  
if t>42:  
		print("I have the feeling the second number might be too big")  
		continue  
```

Then, it checks if the value of t provided satisfies the following code:

```  
n=2**t-1  
sent=False  
for i in range(2,int(n**0.5)+1):  
		 if (n%i) == 0:  
				print("The second number didn't bring me any luck...")  
				sent = True  
				break  
if sent:  
		continue  
```

You could analyze this code; but, we don't actually need to know what this
code is doing. Instead, we can just create our own program to do the exact
same thing but test every value of t from 1 to 42.

```  
for t in range(43):  
   n=2**t-1  
   sent=False  
   for i in range(2,int(n**0.5)+1):  
       if (n%i) == 0:  
           #print(f"{t}: The second number didn't bring me any luck...")  
           sent = True  
           break  
   if not sent:  
       print(f"{t}: Worked!")  
```

This gives us an array of t values that work!  
Then, the next section of code tests s and t together.

```  
u=t-1  
number=(2**u)*(2**(t)-1)  
sqrt_num=math.isqrt(s)  
for i in range(1,sqrt_num+1):  
		if s%i==0:  
				A.append(i)  
				if i!=s//i and s//i!=s:  
						A.append(s//i)        
total=sum(A)  
if total==s==number:  
	# print flag  
```

Since we now know t, our only unknown is actually only s. So, we can basically
just run a slightly modified version of this code to find what pairs (s, t)
work.

```  
ts = [1, 2, 3, 5, 7, 13, 17, 19, 31] # 0 left out because 1. it doesn't work
and 2. it causes an error  
for t in ts:  
   A = []  
   u=t-1  
   number=(2**u)*(2**(t)-1)  
   print(number)  
   s = number  
   sqrt_num=math.isqrt(s)  
   for i in range(1,sqrt_num+1):  
       if s%i==0:  
           A.append(i)  
           if i!=s//i and s//i!=s:  
               A.append(s//i)        
   total=sum(A)  
   if total==s==number:  
       print(f"t - {t}, s - {s}: solved!")  
```

After running this program, you should receive several pairs (s, t) that work
and fall within the constraints of the problem. Send any of them using ncat to
get the flag!

	flag{luck_0n_fr1d4y_th3_13th?}