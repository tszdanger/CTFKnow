After reversing the binary with Ghidra, the general gist of what it does is
the following:

Given a list of numbers, it checks if all numbers from 0 through 14 are
present. If so, and the last number is 0, then it computes the costs of
traveling between adjacent entries in the list, starting from 0. Specifically,
it calculates the cost of 0 -> first element, first element -> second element,
etc. If the sum of these costs is at most 2192, then the flag is printed. The
costs are presented in an array indexed by these pairs of elements.

After extracting the array, the problem reduces to solving the Traveling
Salesman Problem, with an added twist: we're allowed to repeat vertices to
possibly lower the cost. So, the game plan is as follows: first, run an APSP
algorithm such as Floyd-Warshall on the graph of distances between vertices to
generate a new graph containing the minimal distances between vertices. Then,
solve TSP on this new graph to get an optimal solution.

Here is the code for calculating APSP, where the `dist` dictionary stores the
minimal distances.

```  
import numpy as np  
import networkx as nx

# darr is array of (source, dest) -> cost  
G = nx.from_numpy_matrix(np.array(darr), create_using=nx.DiGraph)

pred, dist = nx.floyd_warshall_predecessor_and_distance(G)  
```

Then, we wrote our own code for TSP (for some reason, online code wasn't
giving the right results)

```  
from functools import combinations

def tsp(dists):  
   memo = defaultdict(int) # visited set -> (min cost, last visited in set)  
   n = len(dists)

   for i in range(n):  
       memo[frozenset([i])] = (0, i)

   for size in range(2, n + 1):  
       for comb in combinations(dists.keys(), size):  
           mn = 100000000000000  
           argmin = -1  
           for e in comb:  
               cc = frozenset(set(comb).difference(set([e])))  
               cost, last = memo[cc]  
               if cost + dists[last][e] < mn:  
                   mn = cost + dists[last][e]  
                   argmin = e  
           memo[frozenset(comb)] = (mn, argmin)  
   currset = set([i for i in range(14)])  
   path = []  
   while len(currset) > 0:  
       finc, finl = memo[frozenset(currset)]  
       path.append(finl)  
       currset = currset.difference(set([finl]))

   return memo, path[::-1]  
```

It turns out the minimum cost was 2161, which is within bounds! Now, all that
remains is to discover what changed when we ran shortest paths, and this is
what the `pred` dictionary is for: it stores predecessors in shortest paths.

```  
def discover(x, y):  
   path = [y]  
   while y != x:  
       y = pred[x][y]  
       path.append(y)  
   return path[::-1]  
```

Now, we can take the path from `tsp` and run it through `discover` to find our
final answer and the flag:

`python3 -c 'for r in [6,11,14,7,8,1,5,10,3,12,4,9,7,2,13,0]: print(r)' | nc 147.182.172.217 42000`

gives

```  
i like this tour  
i guess i'll give you the flag now  
flag{r3v_a1g0_cl0s3_3n0ugh_3293011594}  
```