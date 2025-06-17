# cheater mind

**Category**: misc \  
**Solves**: 4 \  
**Points**: 997 \  
**Author**: deuterium

Hey, I dont want you to win. Mind if i cheat a little bit?

```  
nc misc.zh3r0.cf 1111  
```

Download - [cheater_mind.tar.gz](cheater_mind.tar.gz)

## Overview

We just have to win 6 rounds of  
[Mastermind](https://en.wikipedia.org/wiki/Mastermind_(board_game)), with a
small twist.

Basically there's some secret string we have to guess. After each guess, the  
server will reply with just two numbers:  
1. Number of correct chars in the correct position  
2. Number of correct chars in the wrong position (the server will tamper with  
 this value to make life harder for us)

If we exceed the maximum number of guesses, then we lose.

```python  
from random import randint, random  
from collections import Counter

class Agent:  
   def __init__(self, N, K, mutation, guess_limit):  
       self.N = N  
       self.K = K  
       self.mutation = mutation  
       self.guess_limit = guess_limit  
       self.secret = [randint(1, N) for i in range(K)]  
       print(f"secret = {self.secret}")

   def play(self, guess):  
       if guess == self.secret:  
           return self.K, 0

       # This is where the server tampers with the values  
       mutated = [  
           i if random() > self.mutation else randint(1, self.N) for i in self.secret  
       ]

       bulls = sum(a == b for a, b in zip(mutated, guess))  
       cows = Counter(mutated) & Counter(guess)  
       return bulls, sum(cows.values()) - bulls

   def game(self):  
       try:  
           for guess_no in range(self.guess_limit):  
               guess = list(  
                   map(  
                       int,  
                       input("enter your guess as space separated integers:\n")  
                       .strip()  
                       .split(),  
                   )  
               )  
               bulls, cows = self.play(guess)  
               print(bulls, cows)  
               if bulls == self.K:  
                   return True  
           return False  
       except:  
           print("Error, exiting")  
           exit(1)

# N, K, mutation, guess_limit  
# First three rounds are just normal Mastermind games.  
# Last three rounds have a small probability of mutation, providing unreliable  
# feedback.  
LEVELS = [  
   [6, 6, 0, 7],  
   [8, 6, 0, 8],  
   [8, 8, 0, 9],  
   [6, 6, 0.05, 10],  
   [8, 6, 0.05, 11],  
   [6, 6, 0.1, 12],  
]

print(  
   """Can you beat me at mastermind when I am not so honest?  
https://en.wikipedia.org/wiki/Mastermind_(board_game)"""  
)

for level, (N, K, mutation, guess_limit) in enumerate(LEVELS, start=1):  
   print(  
       "Level {}, N={}, K={}, mutation={}, guess limit={}".format(  
           level, N, K, mutation, guess_limit  
       )  
   )  
   if Agent(N, K, mutation, guess_limit).game():  
       print("level passed, good job")  
   else:  
       print("You noob, try again")  
       exit(1)

from secret import flag  
print("you earned it :", flag)  
```

## Solution

### Short version

1. Find this paper:  
 [Efficient solutions for Mastermind using genetic
algorithms](https://lirias.kuleuven.be/bitstream/123456789/164803/1/kbi_0806.pdf)  
 (maybe a genetic algorithm can handle the unreliable feedback?)  
2. Find this implementation: https://github.com/dogatuncay/mastermind  
3. Patch it to interact with the server (Elixir is hard ?)  
4. Tweak the parameters and evolution loop to handle unreliable feedback better  
5. Win rate: 0.8% (each attempt takes about 1 minute)  
6. Start 10 looped instances in parallel  
7. Take a 2 hour nap  
8. Wake up and get the flag

### Long version

See the next section

Patch for Mastermind solver: [cheat_mind.patch](cheat_mind.patch) \  
Pwntools wrapper script: [client.py](client.py)

Output:  
```  
[+] Opening connection to misc.zh3r0.cf on port 1111: Done  
[DEBUG] Received 0xce bytes:  
   b'Can you beat me at mastermind when I am not so honest?\n'  
   b'      https://en.wikipedia.org/wiki/Mastermind_(board_game)\n'  
   b'Level 1, N=6, K=6, mutation=0, guess limit=7\n'  
   b'enter your guess as space separated integers:\n'  
[*] Level 1, N=6, K=6, mutation=0.0, guess limit=7  
[+] Starting local process '/bin/sh' argv='timeout 45 mix
run_genetic_algorithm 6 6 0.0 7' : pid 547096  
[DEBUG] Received 0x4b bytes:  
   b'Genetic Algorithm guesses : [3, 1, 2, 4, 6, 2]\n'  
...  
   b'Genetic Algorithm guesses : [5, 4, 1, 1, 1, 5]\n'  
   b'I guess:\n'  
   b'[5, 4, 1, 1, 1, 5]\n'  
   b'Enter move results:\n'  
[DEBUG] Sent 0xc bytes:  
   b'5 4 1 1 1 5\n'  
[DEBUG] Received 0x63 bytes:  
   b'6 0\n'  
   b'level passed, good job\n'  
   b'you earned it :
zh3r0{wh3n_3asy_g4m3s_b3come_unnecessarily_challenging}\n'  
[*] Beat level 6  
```

> Note: The author's solution was to encode it as a maxSAT instance:
> [authors_solution.py](authors_solution.py)

## Timeline

- `Saturday 09:45 PM - 11:00 PM`  
 - Start challenge  
 - Read source code, learn rules of Mastermind  
 - Find this paper: [Efficient solutions for Mastermind using genetic algorithms](https://lirias.kuleuven.be/bitstream/123456789/164803/1/kbi_0806.pdf)

- `Saturday 11:00 PM - 11:50 PM`  
 - Try a bunch of shitty Mastermind solvers from GitHub  
 - Find this implementation that actually works: https://github.com/dogatuncay/mastermind

- `Saturday 11:50 PM - Sunday 01:00 AM`  
 - Modify the genetic algorithm to play interactively  
 - Fix bug that makes it get stuck in an infinite loop

- `Sunday 01:00 AM - 01:30 AM`  
 - Write Python wrapper to interact with the challenge server and Mastermind  
   solver  
 - Test results:  
```  
Level 1: 6 x 6, 0.00% mutation,  7 guesses : Solves within 30 seconds  
Level 2: 8 x 6, 0.00% mutation,  8 guesses : Solves within 45 seconds  
Level 3: 8 x 8, 0.00% mutation,  9 guesses : Solves within 2 minutes  
Level 4: 6 x 6, 0.05% mutation, 10 guesses : Often gets trapped in infinite
loop  
Level 5: 8 x 6, 0.05% mutation, 11 guesses : Often gets trapped in infinite
loop  
Level 6: 6 x 6, 0.10% mutation, 12 guesses : Often gets trapped in infinite
loop  
```

- `Sunday 01:30 AM - 03:20 AM`  
 - Tweak genetic algorithm until it can solve levels with unreliable feedback  
   with about 20% of winning, so it has an 0.8% chance of solving the last  
   three levels in succession. Good enough.

- `Sunday 03:20 AM - 04:20 AM`  
 - Modify script to handle failures and run continuously  
 - Deploy 10 instances and pray that one of them will pass all six levels

- `Sunday 04:20 AM - 06:10 AM`  
 - Sleep

- `Sunday 06:10 AM` (20 min before CTF ends)  
 - Check progress on solvers  
 - Turns out 3 instances passed all six levels ?  
 - Submit flag  

Original writeup
(https://github.com/qxxxb/ctf/tree/master/2021/zh3r0_ctf/cheater_mind).