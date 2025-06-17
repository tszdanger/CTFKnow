##  Problem Description

```  
               +++     Fireshell CTF - DUNGEON ESCAPE     +++

[+] After being caught committing crimes, you were locked up in a really
strange  
    dungeon. You found out that the jailer is corrupt and after negotiating  
    with him, he showed to you a map with all the paths and the necessary time  
    to cross each one, and explained to you how the dungeon works. In some  
    parts of the dungeon, there are some doors that only open periodically. The  
    map looks something like this:

               4              +-+      1  
       +----------------------+3+-------------+  
      +-+                     +-+             |  
      |C|                              2     +++     4  
      +++                  +-----------------+7+--------------------+  
       |           3      +-+                +-+                    |  
       +------------------+4|        12                            +++  
                          +-+--------------------------------------+E|  
                                                                   +-+

[+] All doors start at time zero together and if a door has time equals to 3,  
    this door will open only at times 0, 3, 6, 9, ... So if you reach a door  
    before it is open, you will need to wait until the door is open.

[+] So, with a map you organized the infos like the following: first it will
be  
    the number of doors and the number of paths. Second it will be a list with  
    the time of all doors. After that each line will contains a path with the  
    time needed to walk this path. For the last it will be the position of your  
    cell (C) and the postion where it is the exit (E).  
  
[+] The jailer said that if you find out the minimum time from your cell to
the  
    exit, he will set you free. In the example, the minimum time is 11.  
```

### Sample Input

```  
5 6  
1 8 3 7 1  
1 2 3  
1 3 4  
2 4 2  
3 4 1  
2 5 12  
4 5 4  
1 5  
```

### Sample Output

```  
11  
```

## Solution

We can interpret it as a graph problem: each door is a vertex and each path is
an undirected edge with a weight assigned. We are to find the shortest path
between the nodes $C$ and $E$.

Since we want to calculate the shortest path, [Dijkstra's
algorithm](https://en.wikipedia.org/wiki/Dijkstra%27s_algorithm) seems like a
good idea. The only thing now is to handle the doors' open times. If we arrive
at a door with open interval $t$ at time $x$, we have to wait until the time
reaches a multiple of $t$ that is $\geq x$, which is $\left\lceil \frac{x}{t}
\right\rceil t$. Therefore when arriving at a new node, we should set its
distance to $\left\lceil \frac{x}{t} \right\rceil t$ instead of $x$ (as in the
usual Dijkstra's).

### Code

Here is a C++ implementation that passes all challenges. The code is not well-
optimized for size or speed for the sake of readability.

```c++  
#include <bits/stdc++.h>

using namespace std;

typedef pair<int, int> pii;

int n, m;  
vector<int> intervals;  
vector<vector<pii>> edges;

int get_open_time(int time, int open_time) {  
   if(time == 0) return 0;  
   return ((time - 1) / open_time + 1) * open_time;  
}

int solve(int start_node, int end_node) {  
   priority_queue<pii, vector<pii>, greater<pii>> Q;  
   vector<bool> visited(n + 1);

   Q.emplace(0, start_node);  
   while(Q.top().second != end_node) {  
       int dist = Q.top().first, node = Q.top().second;  
       Q.pop();  
       if(!visited[node])  
           for(pii &edge : edges[node])  
               Q.emplace(get_open_time(dist + edge.second, intervals[edge.first]), edge.first);  
       visited[node] = true;  
   }  
   return Q.top().first;  
}

int main() {  
   cin >> n >> m;

   intervals.resize(n + 1);  
   for(int i = 1; i <= n; i++)  
       cin >> intervals[i];

   edges.resize(n + 1);  
   for(int i = 1; i <= m; i++) {  
       int u, v, w;  
       cin >> u >> v >> w;  
       edges[u].emplace_back(v, w);  
       edges[v].emplace_back(u, w);  
   }

   int start_node, end_node;  
   cin >> start_node >> end_node;  
   cout << solve(start_node, end_node) << '\n';

   return 0;  
}  
```

### Interaction Script (credit: lys0829)

This task requires an interaction with the server. Here is a python script
that works with the above solution.

```py  
from pwn import *

r = remote('142.93.113.55', 31085)  
r.sendlineafter('runaway: ', 'start')

for chal in range(1, 51):  
   try:  
       # assume the compiled file is ./main  
       sol = process('./main', level='error')

       print(f'Running on test {chal}')  
       r.recvuntil(f'Challenge {chal}:')  
       test = r.recvuntil('The answer is: ')

       sol.send(test)  
       r.send(sol.recvline())  
       result = r.recvline()  
       if 'Correct!' not in result.decode():  
           print(f'Wrong answer on test {chal}')  
           exit(1)

   except Exception:  
       print(f'Runtime error on test {chal}')  
       exit(2)

print(r.recvall().decode())  
# congratulations, you now have the flag!  
```