# listcomp ppm (371)

Solve 3 super easy list-comp challenges!!!  
Short! Shorter!! Shortest!!!

`nc easiest.balsnctf.com 9487`

UPDATE: the challenge runs by python3.6 UPDATE: the original code should
already be list comprehension

## Question 1

The first line would contain a positive integer N. Then there would be N lines
below. Each line contains two integer A and B. Please output the corresponding
A+B.

##### Example Input:  
3  
1 2  
3 4  
5 6

##### Example Output:  
3  
7  
11

Input Length Limit: 75

```python  
# Q1 (67 chars)  
[print(sum(map(int,input().split()))) for i in range(int(input()))]  
```

## Question 2  
This is the knapsack problem that you know. Sasdffan is going to buy some junk
foods. However, he has only limited budgets M. Each junk food would have two
attributes, the cost of buying the junk food and the value of eating the junk
food. The first line contains two positive integers N and M. Then, there would
be N lines below. Each line contains two positive integers v and c. (v: value,
c: cost). Please output the maximum value that Sasdffan could get after
consuming all the junk foods he bought. Caution: Each junk food could only be
bought once.

1000 <= N <= 2000, 1 <= M <= 3000, 1 <= c <= 3000, v > 0

##### Example Input:  
3 5  
1 2  
1 3  
2 2

##### Example Output:  
3

Input Length Limit: 200

```python  
# Q2 short (184 chars)  
[[d.insert(0,[max(s,t+v)for s,t in zip(d[0],[-v]*c+d[0])])for(v,c)in[r()for _
in[1]*N]]==print(max(d[0][:M+1]))for r
in[lambda:map(int,input().split())]for(N,M),d in[(r(),[[0]*3001])]]  
  
# Q2 unrolled  
[  
   [  
   d.insert(0,[max(s,t+v)for s,t in zip(d[0],[-v]*c+d[0])])  
   for(v,c)in[r()for _ in[1]*N]  
   ]  
   ==  
   print(max(d[0][:M+1]))  
   # start here (assignments)  
   for r in[lambda:map(int,input().split())]  
   for(N,M),d in[(r(),[[0]*3001])]  
]  
  
# Q2 normal code  
r = lambda: map(int,input().split())  
N, M = r()  
d = [[0]*3001]  
pairs = [r() for _ in [1]*N]  
for v, c in pairs:  
   new = []  
   for s in range(M+1):  
       if s >= c:  
           new.append( max(d[-1][s],d[-1][s-c]+v) )  
       else:  
           new.append( d[-1][s] )  
   d.append(new)  
print(max(d[-1])  
```

**UPD:** using cool tricks by [@f4lcon](https://twitter.com/_f41c0n), this
becomes 164 chars:  
```python  
[[0for(v,c)in zip(l[::2],l[1::2])for r[::]in[[max(s,t+v)for s,t in
zip(r,[-v]*c+r)]]]==print(max(r))for N,M,*l
in[map(int,open(0).read().split())]for(r)in[[0]*-~M]]

# unrolled:  
[  
   [  
   0  
   for(v,c)in zip(l[::2],l[1::2])  
   for r[::]in[[max(s,t+v)for s,t in zip(r,[-v]*c+r)]]  
   ]  
   ==  
   print(max(r))  
   for N,M,*l in[map(int,open(0).read().split())]for(r)in[[0]*-~M]  
]  
```

## Question 3  
Depth of the tree. There is a size N tree with node index from 0 to N-1. The
first line is an integer N (tree size). Then, there would be N numbers in the
next line each represents the father of the node. (0 is always the root).

10 <= N <= 10000.  
Please notice that for any i, father[i] < i.

##### Example Input:  
3  
0 0 1

##### Example Output:  
2

Input Length Limit: 300

```python  
# Q3 short (101 chars)  
[[d.append(d[p]+1)for p in P]==print(max(d))for _,P,d
in[(input(),map(int,input().split()[1:]),[0])]]

# Q3 unrolled  
[  
   [d.append(d[p]+1)for p in P[1:]]  
   ==print(max(d))  
   # start here:  
   # just assignments  
   for _,P,d in[(input(),map(int,input().split()[1:]),[0])]  
]  
```  
#### Challenge Author: hortune

Original writeup
(https://gist.github.com/hellman/8aa11a9c6628ca2c8214450bf800e5d4).