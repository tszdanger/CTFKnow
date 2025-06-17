The main page looked like
http://petushok.2018.ctf.kaspersky.com/?logo=petushok.png  
The picture name can be changed to
http://petushok.2018.ctf.kaspersky.com/?logo=main.py. The main.py name was
guessed. There is an import cococo, lets get it.  
http://petushok.2018.ctf.kaspersky.com/?logo=cococo.py.

We have check function there, the task is to find the check input which gives
1.

The solver:

```  
def check(value):  
   # a lot of code  
   return (a140574420399240, a140574420399456, ..., (a140574419586512 + 1),
(a140574419608064 + 1))

def brute_from(n, condition_idx):  
   end_pos = (condition_idx + 104) % 137

   if condition_idx >= 300:  
       print("flag", hex(n))  
       exit()

   q = check(n)  
   if q[condition_idx % 137] == 1:  
       brute_from(n, condition_idx+1)

   n ^= 1 << end_pos  
   q = check(n)  
   if q[condition_idx % 137] == 1:  
       brute_from(n, condition_idx+1)

brute_from(0, 0)

```