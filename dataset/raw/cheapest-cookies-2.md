# \[Misc\] - Cheapest Cookies 2

#### Points = 263

## Prompt

Now that Andrew knows which Costco has the cheapest cookies, he has to get
there - as quickly as possible! He has given you 40 roads with the two
endpoint locations and the distance of the road, and he starts at location 0
and the Costco is at location 20. All roads are 2-way roads, meaning you can
go from x to y and from y to x. Please output the minimum distance needed to
reach the Costco, and if there is no possible path, print -1. You will need to
pass fifty tests to get the flag. And don't forget to be fast!

Sample Input:

```  
0 20 18  
4 8 2  
0 4 8  
4 20 6  
```

Sample Output:

```  
14  
```

`nc tjc.tf 31111`

by andy

#### Hints  
\[None\]

## Provided Files

\[None\]

## Write Up

- We are given a set of edges and are asked to find the shortest path between nodes #0 and #20, if it exists.  
- This is a single source, shortest-path problem with positive, undirected edges.  
	- perfect case for Dijkstra's algorithm.  
- I have implemented this before in Java and C++ but I'll do it again in python just for the excercise.  
- I'll be using `pwntools` because it provides an easy way to make connections  
- the code is commented for clarity

```  
from pwn import *

# dijkstra  
def calculate_path(edges):  
   # each node has [distance, prev_node, visited]  
   # for node 0  
   distance = [[0, 0, True]]

   # initialize 20 other nodes  
   for i in range(20):  
       distance.append([1000, -1, False])

   # source node  
   src = 0

   # priority queue for the closest node  
   closest = []

   while len(edges) != 0:  
       # loop through all edges for each node  
       i = 0  
       while i != len(edges):  
           # parse the edge data  
           edge = edges[i].split(' ')  
           first = int(edge[0])  
           second = int(edge[1])  
           weight = int(edge[2])

           other = -1

           # if the current edge has an end touching the src node  
           if first == src:  
               other = second

           elif second == src:  
               other = first

           else:  
               # nothing to be done - move to next edge  
               i += 1  
               continue

           # process the edge  
           # remove from the list to avoid reading it twice  
           edges.pop(i)  
  
           # skip the node if visited - shortest path already found  
           if distance[other][2] == True:  
               continue

           # update the shortest path  
           if distance[other][0] > (distance[src][0] + weight):  
               distance[other][0] = distance[src][0] + weight  
               distance[other][1] = src

               # add to the queue  
               if not closest:  
                   closest.append([distance[other][0], other])  
               else:  
                   j = 0  
                   while j != len(closest):  
                       if distance[other][0] < closest[j][0]:  
                           break   
                       else:  
                           j += 1  
                   closest.insert(j, [distance[other][0], other])

       # no more reachable nodes   
       if not closest:  
           break

       # pop the closest node to node #0  
       next_src = closest.pop(0)  
       src = next_src[1]

       # shortest path to 20 is found - no need to keep going  
       if src == 20:  
           return distance[20][0]  
           break

       # mark node as visited  
       distance[src][2] = True

   if distance[20][0] == 1000:  
       # node 20 is unreachable  
       return -1  
   else:  
       return distance[20][0]

# make connection  
tgt = remote('tjc.tf', 31111)

# initial prompt is different from subsequent prompts  
recieved = tgt.recvuntil(b'answer: ')  
recieved = recieved.decode('ascii').split('\n')

# solve case  
lines = recieved[10:-2]  
ret = str(calculate_path(lines))  
tgt.sendline(bytes(ret, 'ascii'))

# print result  
recieved = tgt.recvline(b': ')  
recieved = recieved.decode('ascii')  
print(recieved)

# handle all cases  
while True:  
   # recieve prompt  
   recieved = tgt.recvuntil(b': ')  
   recieved = recieved.decode('ascii').split('\n')

   # caclulate and send answer  
   lines = recieved[1:-2]  
   ret = str(calculate_path(lines))  
   tgt.sendline(bytes(ret, 'ascii'))

   # recieve and print result  
   recieved = tgt.recvline().decode('ascii')  
   print(recieved)

   if recieved == 'Test 50 passed!\n':  
       # recv until the end of the flag  
       lines = tgt.recvuntil(b'}')  
       lines = lines.decode('ascii').split('\n')  
       for line in lines:  
           print(line)  
       break

```

## Flag

tjctf{w00_w3_have_th3_c00k1es_n0w}

Original writeup (https://github.com/aly-ab/CTF-
writeups/blob/main/notes/tjctf-2022/Misc%20-%20Cheapest%20Cookies%202.md).