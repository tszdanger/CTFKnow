## Challenge Description

Take a break from the other challenges and play a relxing game of Minesweeper  
I have even solved most of the board for you and marked many of the mines.  
I am completely sure they are correct so you just need to find the remaining
ones.

## Intuition

Looking at the minesweeper map, it's huge, but I noticed that the patterns
look  
like wires and seem to lead to some structure which intuitively resemble logic  
gates. Even more, there are multiple mentions in the code of _circuits_. So I
searched  
on the internet for something related to minesweeper and circuits and found a
[paper from
2015](https://web.math.ucsb.edu/~padraic/ucsb_2014_15/ccs_problem_solving_w2015/NP3.pdf)  
which proves that Minesweeper is np-complete using circuits which look exactly  
like the ones in the challenge.

An initial idea that results is that we could convert the map to a logic
circuit and input it into  
a sat-solver like **z3**. Now... that's kinda complicated.

The map being partially solved, consistent and built like a circuit means that
giving in _input_ to  
each end of the wire (aka putting a bomb or not there), should result in a
unique arrangement for the  
entire map. Intuitively, this means that the whole map can be converted into a
logic formula and fed to  
as sat solver.

## Solution

After some more research, I found a github repo with a minesweeper [sat
solver](https://github.com/FabianGalis/minesweeper-sat)  
which structured the map in a very similar way with the one in the given
challenge. I modified the code such that it fit the problem:

```python  
from pysat.solvers import Solver #for SAT solving  
from itertools import combinations #for combinations in a CNF

import itertools  
import hashlib

# DIMACS codification  
def M(i,j,board_w): return  board_w**1 * i + board_w**0 * j + 1

# find unknown cells next to a cell at i,j  
def unknown_neighbours(board,i,j):  
 neighbours=[]  
 for h in range(i-1,i+2):  
   for w in range(j-1,j+2):  
     if h<len(board) and w<len(board[0]) and h>=0 and w>=0 and (board[h][w]>8): neighbours.append((h,w))  
 return neighbours

# clauses per cell  
def cell_clauses(board,i,j):  
 neighbours=unknown_neighbours(board,i,j)  
 cell_clauses=[]

 #at least n mines  
 for combination in combinations([M(elem[0],elem[1],len(board[0])) for elem in
neighbours],len(neighbours)-board[i][j]+1):  
   cell_clauses.append(list(combination))

 #at most n mines  
 for combination in combinations([-M(elem[0],elem[1],len(board[0])) for elem
in neighbours], board[i][j]+1):  
   cell_clauses.append(list(combination))

 return cell_clauses

# clauses per board  
def board_clauses(board,board_h,board_w):  
 clauses=[]  
 for i in range(board_h):  
   for j in range(board_w):  
  
     if board[i][j]<9:  
       #add self as known safe cell  
       clauses.append([-M(i,j,board_w)])  
       #add surrounding constraints  
       clauses+=cell_clauses(board,i,j)  
     elif board[i][j]==10:  
       #add self as mine cell  
       clauses.append([M(i,j,board_w)])  
 return clauses

#print solution  
def show_solution(board,board_h,board_w,model):  
 bits = []  
 for i in range(board_h):  
   for j in range(board_w):  
     if board[i][j]==9:  
         board[i][j]='m' if M(i, j,board_w) in model else 's'  
     if i == 23:  
         bit = 1 if board[i][j] == 'm' else 0  
         bits.append(bit)  
     flag = hashlib.sha256(bytes(bits)).hexdigest()  
     print(f'Flag: CTF{{{flag}}}')  

def solve_board(board,printing=True):  
 if printing:  
   print("Legend:\n0-8: mines nearby\n9  : unknown\n10 : known mine")

 board_w=len(board[0])  
 board_h=len(board)

 s = Solver(name='cd')  
 s.append_formula(board_clauses(board,board_h,board_w))

 if s.solve():  
   model=s.get_model()  
   show_solution(board,board_h,board_w,model)  
   if printing:  
     print("\nSAT - consistent")  
     print("Model:",model)  
     print("Legend:\n0-8: mines nearby\n9  : unknown\n10 : known mine\nm  : found mine\ns  : found safe")

   return True  
 else:  
   print("\nUNSAT - inconsistent")  
   return False

#board encoding:  
#0-8: mines nearby  
#9  : unknown space  
#10 : known mine

with open('gameboard.txt', 'r') as fin:  
   circuit = fin.read()  
   circuit = circuit.replace(' ', '0')  
   circuit = [list(line) for line in circuit.split('\n') if len(line) > 0]

board_width = len(circuit[0])  
board_height = len(circuit)  
mine_count=0 #smaller than width*height  
unknown_cells=0 #smaller than width*height

board = [[None for x in range(board_width)] for y in range(board_height)]

for i, (x, y) in enumerate(itertools.product(range(board_width),
range(board_height))):  
   val = int(circuit[y][x], 16)  
   if val == 11:  
       val = 10  
   if val == 10:  
       mine_count += 1  
   elif val == 9:  
       unknown_cells += 1

   board[y][x] = val

solve_board(board)  
```

Running this for 1 minute gets the flag.

### Flag

`CTF{d8675fca837faa20bc0f3a7ad10e9d2682fa0c35c40872938f1d45e5ed97ab27}`

Original writeup (https://dothidden.xyz/google_ctf_2023/mine_the_gap).