## Description  
```  
You are given an ip and a port to nc to  
nc 34.74.30.191 1337  
```  
## Solution  
* On connecting to the server we see that we are asked to solve a proof of work by calculating the first 4 characters of a SHA256 hash.  
 So using hashlib we can bruteforce that. Here's my script:  
 ``` python  
 def solve_pow(r):  
   for i in string.digits + string.ascii_letters:  
       for j in string.digits + string.ascii_letters:  
           for k in string.digits + string.ascii_letters:  
               for l in string.digits + string.ascii_letters:  
                   prefix = str(i)+str(j)+str(k)+str(l)  
                   new_hash = hashlib.sha256(str(prefix+suffix).encode()).hexdigest()  
                   if new_hash == target_hash:  
                       print("The prefix is",prefix)  
                       return prefix  
 ```  
* After solving the proof of work we are shown the actual challenge which is as shown:  
 ```  
 b'There exists a coin minting machine at Bi0S which is known for its
extermely fast minting process.  
 However out of every batch (N coins) it produces one coin is faulty (have a
different weight compared to the other N-1 coins).  
 You can get information of the xor of the weight of the coins from index i to
index j (both included) by communicating with the minting machine.  
 Find the faulty coin (coin with different weight) with minimum number of
queries, as the minting machine has better things to do than answer your
questions.  
 Multiple batches are produced by the minting machine and it is gaurenteed
that in each batch there is only one defective coin. Your query should be in
the format "i j" (without the quotes) where both i and j should lie in the
range [0, N). You can report the correct position (Of course after solving it)
in the format "! index" (without the quotes) where index lies in the range [0,
N). If you correctly identify the faulty coin for a batch, you will continue
to the next batch. If a query is given in the wrong format or give a wrong
answer you will be rejected.\n'  
   b'\n'  
   b'The number of coins in this batch are 14\n'  
   b'Go ahead, ask some queries\n'  
   ```  
* So the server allows us to ask queries and returns the xors of the weight of all coins in the inculsive range of our query.  
 So if our query was `1 3` it gives the value of `w1 ^ w2 ^ w3`  
* Hence I thought of using a binary search mechanism to solve this.  
 Also we know the weight of all coins except the defective one is the same.  
* Now, lets assume we enter the query `0 5` then if the defective coin is not in this range then we get `0`  
 Because `w0^w1^w2^w3^w4^w5 = 0` (since all weights are equal)  
 However if we get a non zero value then we know the defective coin is in that
range.  
* But the flaw with this logic is that if the length of the range is odd, then we get a non-zero answer.  
 Example: If the coin is not in range `0 4` we still get a non zero answer.  
 Because `w0^w1^w2^w3^w4 != 0` but this gives us the value of the actual
weight of the coin.  
* Hence to get the other condition for the binary seach we need to find the weight of a non-defective coin.  
 To do that we can send in the query `0 0` and `1 1`.  
 If we get the same result for both then thats the weight of a non-defective
coin.  
 If the results vary then we can send a third query `2 2` and that would be
the weight of a non defective coin.  
* Here's the script to find the non-defective weight:  
 ```python  
 def legit_weight(r,n):  
   r.sendline('0 0')  
   r.recvuntil('is ')  
   x = int(str(r.recvuntil('\n'))[2:-3]) # Here x is the result of query 0 0  
   r.sendline('1 1')  
   r.recvuntil('is ')  
   y = int(str(r.recvuntil('\n'))[2:-3]) # Here y is the result of query 1 1  
   if x == y:  
       return x  
   else:  
       r.sendline('2 2 ')  
       r.recvuntil('is ')  
       z = int(str(r.recvuntil('\n'))[2:-3]) # Here z is the result of query 2 2  
       if x == z:  
           return z  
       else:  
           return y  
 ```  
* Now that we know the actual weight of a coin. We can start the binary search such that:  
 - If the range length is even and we get the value `0` , the defective coin is not in that range.  
 - If the range length is odd and we get the value of a non-defective coin , then the defective coin is not in the range.  
 - Finally if the range is reduced to `x x+1` we send a query for `x x`.  
   - If the value of `x x` is that of a non-defective coin , then x+1 is the defective coin.  
   - If the value of `x x` is not that of a non-defective coin, then x is the defective coin.

* Using the above logic and pwntools we can script the solution.  
 Here's my final script:  
```python  
from pwn import *  
import hashlib  
import string  
import random

def solve_pow(r):  
   r.recvuntil('+')  
   suffix = str(r.recvuntil(') '))[2:-3]  
   r.recvuntil('= ')  
   target_hash = str(r.recvuntil('\n'))[2:-3]  
   r.recvline()  
   for i in string.digits + string.ascii_letters:  
       for j in string.digits + string.ascii_letters:  
           for k in string.digits + string.ascii_letters:  
               for l in string.digits + string.ascii_letters:  
                   prefix = str(i)+str(j)+str(k)+str(l)  
                   new_hash = hashlib.sha256(str(prefix+suffix).encode()).hexdigest()  
                   if new_hash == target_hash:  
                       return prefix

def legit_weight(r,n):  
   r.sendline('0 0')  
   r.recvuntil('is ')  
   x = int(str(r.recvuntil('\n'))[2:-3])  
   r.sendline('1 1')  
   r.recvuntil('is ')  
   y = int(str(r.recvuntil('\n'))[2:-3])  
   if x == y:  
       return x  
   else:  
       r.sendline('2 2 ')  
       r.recvuntil('is ')  
       z = int(str(r.recvuntil('\n'))[2:-3])  
       if x == z:  
           return z  
       else:  
           return y

def coin_finder(r):  
   r.recvuntil('are ')  
   n = int(str(r.recvuntil('\n'))[2:-3])  
   r.recvline()  
   low = 0  
   high = n  
   weight = legit_weight(r,n)  
   print('weight',weight)  
   while True:  
       mid =(high+low)//2  
       r.sendline(str(low) + ' ' + str(mid))  
       r.recvuntil('is ')  
       x = int(str(r.recvuntil('\n'))[2:-3])  
       if x == 0:  
           if low == mid:  
               r.sendline(str(low)+' '+str(mid))  
               r.recvuntil('is ')  
               p = int(str(r.recvuntil('\n'))[2:-3])  
               if p==weight:  
                   return mid+1  
               else:  
                   return mid  
           low = mid  
       elif x == weight:  
           if low == mid:  
               r.sendline(str(low)+' '+str(mid))  
               r.recvuntil('is ')  
               p = int(str(r.recvuntil('\n'))[2:-3])  
               if p == weight:  
                   return mid+1  
               else:  
                   return mid  
           low = mid  
       else:  
           high = mid  
           if low == mid:  
               r.sendline(str(low)+ ' '+ str(mid))  
               r.recvuntil('is ')  
               p = int(str(r.recvuntil('\n'))[2:-3])  
               if p == weight:  
                   return mid+1  
               else:  
                   return mid

r = remote('34.74.30.191',1337,level='debug')  
prefix = solve_pow(r)  
r.sendline(prefix)  
print(r.recvline())  
print(r.recvline())  
while True:  
   r.sendline('! ' + str(coin_finder(r)))  
   print(r.recvline())  
```  
* After submitting the value of the defective coin around 8 times, we get the flag.    
 `inctf{1f_y0u_c4n_dr3am_y0u_c4n_s34rch_1n_logn}`