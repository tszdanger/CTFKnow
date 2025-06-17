As per my understanding, this is a variation of the bin packing problem
(although I've heard people refer to it as a "multi-knapsack problem" too).
Given a list of items $I_1, I_2, \ldots I_n$ and coins $C_1, C_2, \ldots C_m$,
for each item $I_n$, we must find a subset of coins $C_1, C_2, \ldots C_k$
such that they sum up to $I_n$, plus a small $\epsilon$. Note that there is a
constraint on $\epsilon$, namely $\sum_{i=0}^{n} \epsilon_n \leq
\sum_{i=0}^{m} C_i + \sum_{n=0}^{n} I_n$.

It is straightforward to write a DP-based memoized subset sum solver that,
given an item and a list of coins, finds the subset of coins that sum up to
the item.

```  
class Solver():  
   def __init__(self):  
       self.memo = {}

   def add_to_memo(self, a, b, val):  
       if a not in self.memo:  
           self.memo[a] = {}  
       self.memo[a][b] = val

   def get_from_memo(self, a, b):  
       if a in self.memo and b in self.memo[a]:  
           return self.memo[a][b]  
       return None

   def subset_sum(self, remaining, coins, start_idx=0, sols=[]):  
       if remaining < 0:  
           return False  
       if remaining == 0:  
           return True

       if start_idx == len(coins):  
           self.add_to_memo(remaining, start_idx, False)  
           return False

       from_memo = self.get_from_memo(remaining - coins[start_idx],  
                                      start_idx)  
       if from_memo: return from_memo

       sol_exists = self.subset_sum(remaining - coins[start_idx],  
                                    coins,  
                                    start_idx=start_idx + 1,  
                                    sols=sols)  
  
       if sol_exists:  
           sols.append(coins[start_idx])  
           return True

       self.add_to_memo(remaining - coins[start_idx], start_idx, False)

       from_memo = self.get_from_memo(remaining, start_idx)  
       if from_memo: return from_memo

       sol_exists = self.subset_sum(remaining, coins,  
                                    start_idx=start_idx + 1, sols=sols)

       self.add_to_memo(remaining, start_idx, sol_exists)

       return sol_exists  
```

However, there are two complications. First, the fact that the sum of the
coins need not exactly equal to the item means that for each item and list of
coins, we have to try different sums. Second, once a subset of coins is used
to buy a certain item, none of them can be used to buy any subsequent items.

After a lot of experimentation, I came up with the following procedure to work
around these issues: For each item and list of coins, randomly set $\epsilon$
to 0 or 1 and check if there's a subset of coins that can buy item +
$\epsilon$. If there is, we're good: Remove this subset of coins from the list
of coins and run this procedure for the next item. If there exists no subset,
then loop $\epsilon$ from 1 to its limit (the difference between the sum of
coins and sum of the remaining items to buy) and check if there's a subset. If
this fails too, return False.

```  
def solve(items, coins):  
   results = []

   for i, item in enumerate(items):  
       sols = []  
  
       if not Solver().subset_sum(item + randint(0, 1), coins, 0, sols=sols):  
           spare_coins = sum(coins) - sum(items[i:])  
           for extra_coin in range(1, spare_coins + 1):  
               sols = []  
               if Solver().subset_sum(item + extra_coin, coins, 0, sols=sols):  
                   break  
           else:  
               return False

       results.append(sols)

       for coin in sols:  
           coins.remove(coin)

   return results  
```

If the above procedure fails, then it means that our randomization didn't
work, so keep retrying till it succeeds.

```  
def _solve(items, coins):  
   i = 1  
   while True:  
       print(f'Attempt: {i}')  
  
       sol = solve(items.copy(), coins.copy())  
  
       if sol:  
           return sol  
  
       print('Attempt failed')  
       i += 1  
```

The only other issue I faced was that it took too long to send my payloads
line-by-line, resulting in my connection getting reset. To fix this, I simply
batched my requests, so that something like this:

```  
for i in range(100):  
   sock.sendall(str(i).encode() + b'\n')  
```

Became this:

```  
payload = b''  
for i in range(100):  
   payload += str(i).encode() + b'\n'  
  
sock.sendall(payload)

```

[Here's](https://github.com/gov-
ind/ctf_solves/raw/main/2022/hsctf/vending_machine/solve.py) the full solve
script.

Original writeup (https://gov-ind.github.io/hsctf_2022).