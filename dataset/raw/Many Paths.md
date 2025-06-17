There is 2 kinds of solution.  
1) Simple Dynamic programming solution  
2) Matrix multiplication.

Solving with dynamic programming technique, we can define the 2-dimension dp
array like that  
dp\[i\]\[j\] => number of cases to reach jth node with ith steps.  
The recurrence relation can be denoted with simple for-loop programming.  
If you can reach ath node with Lth steps, and there is path between ath node
and bth node, You can reach bth node from ath node with (L+1)th steps.

But if you try this kind of solution, you can time limit exceed. Because in
server side testcase, N is relatively small, but L value is relatively large.  
Doing some optimization, like using adjacent list instead of adjacent matrix,
implementing problem solver with cpp binary, I could get the flag with this
solution.

Solving with matrix multiplication is the just simple extension from dynamic
programming idea.  
The next recurrence is made of linear combination of previous recurrence.  
In this kind of recurrence, you can transform the dp array mutation into
matrix multiplication.  
We should do matrix multiplcation with L times, it is power of matrix.  
You can reduce computing time consumption with exponential multiplication.  
For example, if you want to get M^16, M^16 = (M^8)^2  
M^8 is also equals to (M^4)^2, something like that.  
You can get power of matrix with time complexity O(lg(L)).

Original writeup (https://eine.tistory.com/entry/Xmas-CTF-2020-write-ups-
focus-on-web-challs).