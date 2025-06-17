# Sound Maze 2.0

When connected we receive the folloing message:

```  
You are in a maze! Find the lenght of smallest path to the end! If there is no
path, the answer must be -1  
Use the keys ASDW to move throw. For each move send one of these letters.  
At any time, send "ANS x", where x is the answer to the problem.  
ROUND 1  
Timeout!  
```

So you have a maze, but no information about its structure other than you can
move up (W), down (S), left (A) and right (D).

At first you have to explore the maze. If we move to any of directions, the
server send a giant base 64 message. If you decode it, you will get a mp3
binary. Opening it, you will hear an information about the current position,
that is one of the following:

- "Welcome to this maze position. Nothing here" - Indicates you are in an empty place.  
- "You cannot come here, this is an wall" - Indicates that will not moved and there is an wall in the place you tried to go.  
- "You can't come here, there is a bomb! Be careful: do not try to come here again" - Indicates that will not moved and there is a bomb in the place you tried to go.  
- "beep beep (...) beep beep BOOM" - Bomb exploded. You lose. Try again  
- "Congratulations! You have reached the end" - Indicates you reach to the maze objective. Now you can send the answer.  
- "" - You do not need information, because you have already been here.

So based in these information we have to explore the unknown maze.

In graph theory the operation to do this is the [depth-first search
(DFS)](https://en.wikipedia.org/wiki/Depth-first_search). In our case we have
to walk trough the maze to explore it, so for each move we have to be at a
neighbor place, that is, when finish to explore a place neighbors, we have to
return to previous place. Parallel to this process we have to draw the map.
The following python3 function implements the algorithm:

```python3  
def dfs(v: tuple = (0, 0), d=0) -> None:  
   global m  
   try:  
       if m.isend((0, 0)):  
           m.d_end = 1  
           return  
       if m.isend(v):  
           m.d_end = d+2  
           return  
       if v in visited or d > m.d_end:  
           return  
       if v != (0, 0):  
           visited.add(v)  
       for c in b'ADSW':  
           c = bytes([c])  
           if new_position(v, c) in visited:  
               continue  
           pos, ev = go(v, c)  
           if pos != v:  
               if ev != VISITED:  
                   m.set(pos, ev)  
               v = pos  
               dfs(v, d+1)  
               v, ev = go(v, op[c])  
           else:   
               m.set(new_position(pos, c), WALL)  
               visited.add(new_position(pos, c))  
   except Exception as err2:  
       print(f'dfs() - {err2}')  
```

It uses other created classes, functions and variables that represents the
following:

- `class Maze`: Stores the explored maze  
- `global m`: Variable of class Maze  
- `m.isend(pos)`: Verifies if the position `pos` have been already explored and is the aimed position  
- `visited`: Visited positions set  
- `new_position(v, c)`: Return next of position `v` in direction of key `c`  
- `pos, ev = go(v, c)`: Go to next of position `v` in direction of key `c` and returns the position after the move and a identifier of what there is in the position you tried to go  
- `m.set(pos, ev)`: Mark the position `pos` content (`ev`) in maze `m`  
- `op[c]`: Dict that indicates the key of opposite direction 

The `dfs` function walks around all the maze, creating all the map. After
that, we have to run a minimum path algorithm to find the answer. As it is a
not weighted graph, a simple [breadth-first search (BFS)
algorithm](https://en.wikipedia.org/wiki/Breadth-first_search) is enough to
geto to answer:

```python3  
def bfs(ini: tuple = (0, 0)) -> int:  
   if m.isend(ini):  
       return 0  
   fila = Queue()  
   fila.put(ini)  
   m.set_d(ini, 0)  
   while not fila.empty():  
       v = fila.get()  
       for c in b'ADSW':  
           c = bytes([c])  
           w = new_position(v, c)    
           if w not in m:  
               continue  
           if m.get_d(w) == INF:     
               m.set_d(w, m.get_d(v)+1)  
               if m.isend(w):  
                   return m.get_d(w)    
               if m.isempty(w):  
                   fila.put(w)    
   return -1  
```

To identify which audio you receive, the following function is an example of
reader of received content:

```python3  
def content() -> bytes:  
   try:  
       cont = read_until(b'=\n\n\n').split(b'\n', 1)[1].split(b'=\n\n\n')[0]  
       sha = sha224(cont)  
       if sha in HASHES:  
           return HASHES[sha]  
       open('test.mp3', 'wb').write(base64.b64decode(cont))  
       print(f'Unknown file!\n{sha}')  
       sys.exit(f'Unknown file!\n{sha}')  
   except Exception as contentErr:  
       raise Exception(f'content() - {contentErr}')  
```

In which you can use any hash to identify the file. If the file is still
unknown, the function save it and ends the solver to you to identify what it
is and update the hashes dictionary.

Putting all together, we have the following script to solve the challenge:

```python3  
#!/usr/bin/python3  
# *-* coding: utf-8 -*-

from queue import Queue

from pwn import *

from datetime import datetime as dt2  
from typing import Tuple, Optional

import base64

host = "soundmaze.pwn2.win"  
port = 31337  
s = remote(host, port)

flag_fmt = b'CTF-BR'

EMPTY, BOMB, WALL, END, BOOM, VISITED = tuple(b'.*#F0Z')  
HASHES = {'052aee2948b3485bb5d12b231b508578146f16720e1c162f22408b55': WALL,  
         '8c3ee205b91aa508bd2548d9f1c2888e7ad299b3e7f94d0e922f996a': END,  
         'd804d31dc67f68e2a4d3de8b9fb8a916771b51f5f12d48c9148f8f21': EMPTY,  
         '1e86360e4439f5af5850067d5ef3f8c09399db19b3cfa308d2923042': BOMB,  
         'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f': VISITED,  
         'b': BOOM}  
INF = 9999999999999999999999999999999999  
ANS = INF

class Maze:  
   def __init__(self) -> None:  
       self.el = {(0, 0): (EMPTY, INF)}  
       self.xL = (0, 0)  
       self.yL = (0, 0)  
       self.d_end = INF  
  
   def __contains__(self, pos: Tuple[int, int]) -> bool:  
       return pos in self.el  
  
   def __str__(self) -> str:  
       return str(self.el)  
  
   def get(self, pos: Tuple[int, int]) -> Optional[int]:  
       if pos in self.el:  
           return self.el[pos][0]  
  
   def set(self, pos: Tuple[int, int], ev: bytes, d: int = INF) -> None:  
       self.el[pos] = (ev, d)  
       self.xL = (min(self.xL[0], pos[1]), max(self.xL[1], pos[1]))  
       self.yL = (min(self.yL[0], pos[0]), max(self.yL[1], pos[0]))  
  
   def set_d(self, pos: Tuple[int, int], d: int) -> None:  
       self.el[pos] = (self.el[pos][0], d)  
  
   def get_d(self, pos: Tuple[int, int]) -> Optional[int]:  
       if pos in self.el:  
           return self.el[pos][1]  
  
   def isempty(self, pos: Tuple[int, int]) -> bool:  
       return self.get(pos) == EMPTY  
  
   def isend(self, pos: Tuple[int, int]) -> bool:  
       return self.get(pos) == END  
  
   def clear(self) -> None:  
       self.__init__()

m = Maze()

def send_line(st):  
   if isinstance(st, str):  
       st = bytes(st, encoding='ascii')  
   s.sendline(st)

def read_until(st: bytes, timeout=1.0) -> bytes:  
   data = s.recvuntil(st, timeout=timeout)  
   return data

def sha224(f: bytes) -> str:  
   if f.endswith(b'.mp3'):  
       b64 = bytes(base64.b64encode(open(f, 'rb').read()))  
   else:  
       b64 = f  
   return hashlib.sha224(b64).hexdigest()

def new_position(pos: Tuple[int, int], c: bytes) -> Tuple[int, int]:  
   if c == b'A':  
       return pos[0]-1, pos[1]  
   if c == b'D':  
       return pos[0]+1, pos[1]  
   if c == b'S':  
       return pos[0], pos[1]+1  
   if c == b'W':  
       return pos[0], pos[1]-1

def content() -> bytes:  
   try:  
       cont = read_until(b'=\n\n\n').split(b'\n', 1)[1].split(b'=\n\n\n')[0]  
       sha = sha224(cont)  
       if sha in HASHES:  
           return HASHES[sha]  
       open('../deploy/test.mp3', 'wb').write(base64.b64decode(cont))  
       print(f'Unknown file!\n{sha}')  
       sys.exit(f'Unknown file!\n{sha}')  
   except Exception as contentErr:  
       raise Exception(f'content() - {contentErr}')

def go(pos: Tuple[int, int], c: bytes) -> Tuple[Tuple[int, int], bytes]:  
   try:  
       send_line(c)  
       cont = content()  
       npos = new_position(pos, c)  
       if cont == BOOM:  
           sys.exit('BOOOOOOOOM')  
       if cont in [EMPTY, END] or (cont == VISITED and m.get(npos) in [EMPTY, END]):  
           return npos, cont  
       return pos, cont  
   except Exception as goErr:  
       raise Exception(f'go() - {goErr}')  
  
  
op = {b'A': b'D', b'D': b'A', b'W': b'S', b'S': b'W'}

visited = set()

def dfs(v: tuple = (0, 0), d=0) -> None:  
   global m  
   try:  
       if m.isend((0, 0)):  
           m.d_end = 1  
           return  
       if m.isend(v):  
           m.d_end = d+2  
           return  
       if v in visited or d > m.d_end:  
           return  
       if v != (0, 0):  
           visited.add(v)  
       for c in b'ADSW':  
           c = bytes([c])  
           if new_position(v, c) in visited:  
               continue  
           pos, ev = go(v, c)  
           if pos != v:  
               if ev != VISITED:  
                   m.set(pos, ev)  
               v = pos  
               dfs(v, d+1)  
               v, ev = go(v, op[c])  
           else:   
               m.set(new_position(pos, c), WALL)  
               visited.add(new_position(pos, c))  
   except Exception as err2:  
       print(f'dfs() - {err2}')

def bfs(ini: tuple = (0, 0)) -> int:  
   if m.isend(ini):  
       return 0  
   fila = Queue()  
   fila.put(ini)  
   m.set_d(ini, 0)  
   while not fila.empty():  
       v = fila.get()  
       for c in b'ADSW':  
           c = bytes([c])  
           w = new_position(v, c)    
           if w not in m:  
               continue  
           if m.get_d(w) == INF:     
               m.set_d(w, m.get_d(v)+1)  
               if m.isend(w):  
                   return m.get_d(w)    
               if m.isempty(w):  
                   fila.put(w)    
   return -1

t0 = dt2.now()  
data = ''  
while True:  
   try:  
       m.clear()  
       data = read_until(b'ROUND', timeout=1)  
       t1 = dt2.now()  
       print(data)  
       if b'BR' in data:  
           data += s.recvall()  
           print(data)  
           break  
       visited = set()  
       dfs()  
       ANS = bfs()  
       send_line(f'ANS {ANS}')  
       print(f'ANS {ANS} {m.d_end}')  
       t2 = dt2.now()  
       print(t2-t1)  
   except Exception as err:  
       print(err)  
       break

data += s.recvall()  
print(data)  
print(dt2.now()-t0)  
```

When it is executed, we get the flag:

```  
b'Congratulations! Here is your FLAG: CTF-
BR{i7_w4S_jUs7_a_S1mp13_BFS_guid3D_bY_b4S3_1G}\n'  
```  

Original writeup
(https://github.com/pwn2winctf/challenges-2020/blob/master/ppc-
Sound%20Maze%202.0/solution/writeup.md).