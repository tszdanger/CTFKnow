*For the full experience with images see the original blog post!*

The challenge files contain a Dockerfile that installs `texlive` and executes
the file `adventure.tex`.  
Looking at that file, it is configured to be executed with `pdflatex` and
contains a block of code and then two data blocks that seem to be encoded in
some way.  
The first macro `\ExplSyntaxOn` reveals that the file uses LaTeX3 code, so
let's look at that first.

## LaTeX3 101

LaTeX3 is an additional interface to provide a modern and consistent
programming syntax in LaTeX.  
It contains library methods for all kinds of tasks like IO, string
manipulation, etc. and provides methods to control macro expansion.

Alan Shawn wrote [a tutorial on his
blog](https://www.alanshawn.com/latex3-tutorial/) that introduces the most
important concepts, methods and data types for programming in LaTeX3.  
I highly recommend you read this article in case you want to take a closer
look at the challenge on your own or would like to write a program in LaTeX3.  
I will still include a short explanation of the concepts relevant to the
challenge though.  
In case you need to look up methods, the [API
documentation](https://ctan.math.illinois.edu/macros/latex/contrib/l3kernel/interface3.pdf)
provides detailed technical explanations.  
I always had a tab open with that document while reading through the challenge
code.

So, how does it work?  
Basically, LaTeX3 introduces a new syntax with `\ExplSyntaxOn` and
`\ExplSyntaxOff` that adjusts the interpretation of some characters like `_`
and a naming convention for methods and variables.  
Public variables follow the format `\<scope>_<module>_<description>_<type>`.  
Public methods on the other hand are named like `\<module>_<description>:<arg-
spec>` where arg-spec defines the parameters that this method expects.  
The basic types are `N and n` which represent a single token or set of tokens
with no manipulation.  
You find an explanation of the types in the tutorial or in the first chapter
of the API docs.  
To control macro expansion the library provides variants of methods that
accept expanded parameter types like `x and e`.  
Those parameters are expanded before being passed into the method.  
To avoid having to define such variants everywhere you can use the methods
`\exp_args:N<args>` with a method and its parameters and define which
parameters you want to expand by using the corresponding args-spec of
`\exp_args`.

To get a better grasp of the syntax let's look at a simple HelloWorld program
first:

```latex  
#!/usr/bin/latex \batchmode \catcode35=14 \input  
\catcode`\#=6  
\documentclass[multi=frame]{standalone}

\ExplSyntaxOn  
\cs_new:Nn\demo_main:  
{  
   \tex_scrollmode:D  
   \tex_message:D  
   {What's~your~name?~}

   \tl_clear:N\l_tmpa_tl

   \ior_get_term:nN  
   {}  
   \l_tmpa_tl

   \exp_args:Nx\iow_term:n  
   {  
       Hello~  
       \tl_use:N\l_tmpa_tl  
       !  
   }

   \tex_batchmode:D  
}

\demo_main:  
\stop  
\ExplSyntaxOff  
```

The call to `\cs_new:Nn` defines our main method.  
We first print the message `What's your name? `.  
Then we clear the temporary variable `\l_tmpa_tl`, store the next input into
it and use it to print our greetings.  
Instead of the `\exp_args:Nx` we could also use `\iow_term:x`.  
I used the same parameters as the challenge itself and thus needed to switch
to [scrollmode](http://latexref.xyz/Command-line-options.html) to stop for
input.

Now, how does `adventure.tex` deobfuscate the main challenge code?  
Looking through the first block of code in the file you will find the
following snippet:

```tex  
\char_generate:nn  
{  
   \int_eval:n  
   {  
       32+\int_mod:nn  
       {  
           71+`#1  
       }  
       {96}  
   }  
}  
{12}  
```

This snippet creates an `other`-category character from a given code point
like this: `chr(32 + (71 + x)%96)`.  
We then created a convert-script ([see
solution.zip](https://ik0ri4n.de/blog/2023/04_hxp-ctf-22-tex-based-
adventure/solution.zip)) to deobfuscate the code and apply basic formatting to
get the interesting challenge code.

## How far can we go with static analysis?

Working in a team is always quicker than working alone.  
As we didn't find any functional tooling for LaTeX3 code we settled vim with
[vimtex](https://github.com/lervag/vimtex) for code highlighting and
implemented a simple renaming script ([see
solution.zip](https://ik0ri4n.de/blog/2023/04_hxp-ctf-22-tex-based-
adventure/solution.zip)) that pulls renames from our HedgeDoc instance.  
That allowed us to go through the program in parallel and apply renames
consistently.  
(The file `challenge.tex` contains all our renames and I will reference both
names for clarity.)  
It does however lack a way to track renames so we had to copy the original
file and reapply all changes if we wanted to adjust a name.  
We then started to look at it by either tracking their usage or just looking
at the most used ones.  
I will explain my process though since my teammates quickly gave up on the
challenge which, in hindsight, sadly did make sense.

When I started working on the challenge we had already finished the
deobfuscation step and a bit of analysis that revealed the challenge game
included a bunch of anti-tampering checks (complex ones, I was told).  
Thus, I started helping with static analysis, more specifically by working on
understanding what happens at the game start.  
The last block of the main challenge code defines a new `world`-Environment
that takes two parameters, the layout args and the content of the block, and
calls the main method with these parameters.  
The main method of the game then parses this data, initializes its layout args
with the given ones, loads the adventure file, prints the loading time and
starts the main loop of the event.

We correctly anticipated that the world data would contain some kind of game
state or configuration as it would make sense to parse that at startup.  
The data was separated into blocks with commas, a big first block and then 25
smaller blocks, each of those base64-encoded.  
The first block is used to initialize a bunch of keys on the global game state
dictionary with hex strings of different lengths or integers.  
Upon startup, only the first of the smaller blocks is parsed.  
They all contain a block of code that (re-)defines some method and set another
batch of game state variables.

I already knew about the game win check so I looked at it again to find out
what part of the game state was relevant for it.  
It compares the variable `EdWG` to the hex-string `000102... 2F30`.  
The only modification of this variable however was some permutation based on
one of six constants and was only called from the method that was defined by
the smaller world blocks.  
It was called like an event hook every time a player placed a key item in a
room and loaded the next block.  
From all that, I could deduce that this was some kind of game-round logic:
placing a key applies the corresponding permutation on `EdWG` and loads the
new values.

I couldn't quite figure out the constant-initialization process by the method
`hxp_bvyZ` though.  
It uses something based on base 36 numbers but with a ton of nested methods
that seemed to contain byte and bit arithmetics and so forth.  
Thus, I gave up on static analysis and asked how difficult it would be to
patch out the anti-tampering checks...

## Dynamics of the game

Now that I asked, I got a pretty solid first guess: "You could try removing
the `\stop` from `hxp_die` (originally `hxp_vEUz`)".  
At least that does work without any problems but I think most anti-tampering
checks are pretty simple and allow for adding debug output anyway.  
Also, just replacing it with an empty method would be best as the change to
batch mode will still affect the program.  
Anyway, I started adding debug output and encrypting the modified code ([see
solution.zip](https://ik0ri4n.de/blog/2023/04_hxp-ctf-22-tex-based-
adventure/solution.zip)).  
This was already shortly before the end of the CTF and I knew I would get
nowhere near completing the challenge in time.  
The modified program did of course load for the same, excruciatingly long time
but I basically did get all the game constants and initial state for free and
also included print statements after variable updates (after each move and
round).  
Having set all this up, I could quickly deduce the basic game logic.

The main game logic is implemented in `hxp_gameInputLoop` (originally
`hxp_tASb`).  
First, the game checks for the winning state as mentioned above and stops with
outputting the win Pdf then.  
Otherwise, it first checks the enemy map `qwsI` (entries with room, direction
and id) and ends with the death of the player upon encounter.  
Then, it outputs noises from some direction for one to three close enemies and
from all directions if there are enemies in all four adjacent rooms.  
Afterward, it handles items and lock rooms.  
First, it uses the item map `NHmX` (position and id) to output all key items
in the current room.  
Then, the game prints the carried items from the map `rzVB`.  
Finally, it looks up the room in the lock map `vpAZ` (position, corresponding
key and id) offers the player to place the key if available.  
The ids are used to load the names from the list `VljH`, by the way.  
After completing all these information steps, the game handles player input
for that step.  
The normal moves permit moving forward and turning left, right and around.  
Also, you could always give up to end the game directly.  
If available, the player can also pick up an item or place it as a key instead
of moving.  
The second action, as already mentioned, starts the next of 25 rounds.  
Finally, the game handles enemy movement.  
Basically, it moves all enemies in their direction (or leaves them where they
are for direction `00`) except for enemies that would cross the player in the
doorway.  
In that case, the enemy just awaits the player in their room on the next turn.

This loop game runs 450 times and warns five rounds before the ceiling breaks
in with the text "The ground shakes. Cracks appear in the walls.".  
So we already need to be pretty quick to pick up the required to finish.  
To get a better feel of the game (and because I had some free time) I wrote a
small visualizer for the game.  
Of course, that required the movement code of the game.  
All in all, it is pretty straightforward (but still not easy to read):

- The variable `EdWG` maps an index to the current position of the room  
- There are 6 additional, stationary rooms  
- Moving uses three axes, in total implemented in 6 maps of adjacent rooms (pairs for forward and backward)  
- Turning left and right changes the axis according to two other maps  
- Turning around flips the last direction bit

The three axes already hint at the structure of the map: a three-by-three
cube.  
In fact, they represent a Rubik's cube where the permutations after each round
are solving steps turning the cube.  
(I often forget to search stuff like those permutation numbers but at least
that information isn't vital for solving the challenge.)  
We have to load the new variables after each round and possibly turn the
player if its field turns for a full simulation.  
Having understood all this, we can play the game and start looking for the
actual solution.

## Solving the maze

I will explain my solution in a bit more detail than the author but I did
finally look at their writeup before writing my solve scripts to avoid
unnecessary delays.  
Having already spent many hours on this challenge, I believe this was the
correct decision.  
So, how do we write a solution for this game challenge?

Looking at the game win check again, we will see that it uses the content of
the variable `kyHu` when calculating the Pdf output.  
According to the author, they decrypt the Pdf here and from analyzing the
usages of `kyHu` we can see it stores the actions of the player.  
Now, the only hint we have is the action limit but we can imagine the author
wants the smallest possible sequence.

But first, how do we solve the Rubik's cube with the permutations provided?  
In theory, there are multiple solutions to do this.  
The author sneakily put enemies at all the positions of lock rooms but one in
the next round though and we would notice that if we'd choose the wrong one.  
However, the correct room is always the first so the odds are pretty high that
you would choose the correct one anyway.

I then wrote a small script to calculate the required keys and when we need to
pick them up.  
It turns out we will have to pick up a lot more keys in the first few rounds
since they aren't available later.  
So you have to watch out to not deadlock yourself once you have the solution
idea by solving the game round by round.

```py  
import game

SOLUTION = []  
SOLUTION_KEYS = []

for i, r in enumerate(game.ROUNDS):  
   if i == len(game.ROUNDS)-1:  
       break

   rooms = []  
   for l in r.lock_rooms:  
       rooms.append(l[0:2])

   for e in game.ROUNDS[i+1].encounters:  
       blocked = e[0:2]  
       if blocked in rooms:  
           rooms.remove(blocked)

   if len(rooms) > 1:  
       exit(1)

   SOLUTION.append(rooms[0])  
   for l in r.lock_rooms:  
       if l[0:2] == rooms[0]:  
           SOLUTION_KEYS.append(l[2:4])

SOLUTION.append(game.ROUNDS[-1].lock_rooms[0][0:2])  
SOLUTION_KEYS.append(game.ROUNDS[-1].lock_rooms[0][2:4])

def check_keys(available_keys: dict[str, int], chain: list[str], encounters:
list[str], key_items: list[str], lock_rooms: list[str], lock: str):  
   for e in encounters:  
       if e[2:4] == "00":  
           blocked = e[0:2]  
           for k in key_items:  
               if k[0:2] == blocked:  
                   key_items.remove(k)  
           for l in lock_rooms:  
               if l[0:2] == blocked:  
                   lock_rooms.remove(l)  
   gathered = []  
   for k in key_items:  
       key = k[2:4]

       if key not in chain:  
           continue

       gathered.append(key)  
       if key in available_keys:  
           available_keys[key] += 1  
       else:  
           available_keys[key] = 1

   available_keys[lock] -= 1

   return (available_keys, gathered)

available_keys = {}  
gathered = {}  
count = 0  
for i in range(len(SOLUTION_KEYS)):  
   r = game.ROUNDS[i]  
   lock = SOLUTION_KEYS[i]

   (available_keys, g) = check_keys(available_keys,  
                                    SOLUTION_KEYS[i:], r.encounters, r.key_rooms, r.lock_rooms, lock)

   if available_keys[lock] < 0:  
       print("Not usable!")  
       break

   if len(g) > 0:  
       count += len(g)  
       gathered[i] = g

print(SOLUTION)  
print(SOLUTION_KEYS)  
print(gathered)  
```

Now, to get the shortest path for each round we can implement a quick BFS just
as the author suggests.  
We need to include our position the enemy movement (I stored the step count
modulo 12 for this and checked before adding a move) and the items we picked
up.  
In python, I had to encode this state as a string (you could use any hashable
type though) to be able to reconstruct the path afterward.  
Then, we can output all the required inputs for this path and run the game
with those inputs.  
I had to close my script though because the game wouldn't otherwise.  
So I entered the container first and extracted the result Pdf after closing my
program.

```py  
import game  
from collections import namedtuple

goal_rooms = ['33', '0A', '1C', '18', '07', '22', '13', '17', '2C', '2B',
'2A',  
             '13', '0F', '16', '01', '0C', '32', '09', '19', '1B', '03', '2D', '15', '1C', '06']  
room_keys = ['3A', '4D', '52', '5C', '3F', '5D', '70', '70', '77', '56', '5D',
'79',  
            '77', '79', '74', '85', '5D', '8B', '56', '85', '8D', '5C', '77', '85', '80']  
pickup = {0: ['3A', '3F'], 1: ['4D', '52', '56'], 2: ['5C', '5D'], 5: ['70',
'74'], 6: ['77', '79'], 7: ['70'], 8: [  
   '80'], 9: ['5D', '77', '5C'], 11: ['85'], 12: ['79'], 14: ['56'], 15:
['5D', '77'], 16: ['8B', '85'], 20: ['8D'], 23: ['85']}

OFFSET = 0x37  
item_names = "yellow mushroom,purple mushroom,blue mushroom,red mushroom,red
key,purple gemstone,yellow gemstone,blue gemstone,mysterious ring,green
mushroom,red potion,yellow potion,purple potion,blue potion,red lock,{a worm-
like creature}{is swimming in a pool of blood}{savaged}{it,{a purple
monkey}{looks evil}{killed}{he,{a giant lobster}{looks angry}{cut in
half}{it,{a mind flayer}{slowly consumes your brain}{killed}{it,{a grue}{looks
hungry}{eaten}{it,{a gelatinous cube}{looks like it contains the remnants of
previous adventurers}{consumed}{it,{[ REDACTED ]}{looks angry at you for
reversing its banking app}{jailed}{it,spell book,red orb,yellow flower,blue
orb,golden ring,purple flower,green herb,red herb,yellow herb,dead bat,purple
key,book case,red rune,blue rune,{Clippy}{is out for revenge}{pierced}{he,blue
key,green gemstone,silver coin,red flower,purple lock,collection box,green
potion,{Bing Sidney}{finally escaped her jail at Microsoft HQ and is out for
revenge}{wiped from existence}{she,{the mighty Bober}{has big
teeth}{eaten}{it,yellow orb,green key,brass key,blue lock,extension cord,red
gemstone,lava smelter,power outlet,yellow rune,green lock,mystery
potion,wooden key,[Object object],purple herb,green flower,human skull,brass
chest,bubbling cauldron,yellow key,green orb,copper coin,vial of acid,wooden
chest,blue herb,iron key,silver ring,glowing rock,stego challenge,yellow
lock,green rune,amulet,signup form,dead lizard,cursed mechanism,animal
bone,purple orb,shallow grave,iron chest,blue flower,purple
rune,scam,blockchain,trash can".split(  
   ',')

# order of neighbors could affect search  
def generate_graph():  
   graph = {}  
   for node in range(0, 0x36):  
       graph[node] = []

   for node in range(0, 0x36):  
       for dir in range(2, 8, 2):  
           neighbor = game.move(node, dir)  
           if neighbor != -1:  
               graph[node].append(neighbor)  
               graph[neighbor].append(node)

   return graph

SearchNode = namedtuple("SearchNode", "pos round keys")

def no_enemies(next: int, last: int, game: game.Game):  
   if game.encounters_at_pos[next] > 0:  
       return False

   for e in game.encounters_map[last]:  
       if e.last_pos == next:  
           return False

   return True

def to_string(node: SearchNode) -> str:  
   out = hex(node.pos)[2:].upper().rjust(2, '0')  
   out += hex(node.round)[2:].upper().rjust(2, '0')  
   out += "|".join(['1' if b else '0' for b in node.keys])  
   return out

def get_path(start: int, sink: SearchNode, from_node: dict[str, SearchNode]):  
   path = [sink.pos]

   curr = sink  
   while to_string(curr) in from_node:  
       path.append(from_node[to_string(curr)].pos)  
       curr = from_node[to_string(curr)]

   path.reverse()  
   return path

def bfs(graph: dict[int, list[int]], start: int, sink: int, g: game.Game,
key_rooms: list[int]):  
   visited: list[SearchNode] = []  
   roundQueue: list[SearchNode] = []  
   nextQueue: list[SearchNode] = []  
   from_node: dict[str, SearchNode] = {}  
   visited.append(SearchNode(start, 0, [False]*len(key_rooms)))  
   roundQueue.append(SearchNode(start, 0, [False]*len(key_rooms)))

   g.step(0, 0)  
   round = 1  
   while True:  
       while roundQueue:  
           m = roundQueue.pop(0)

           for neighbor in graph[m.pos]:  
               next = SearchNode(neighbor, round, m.keys)  
               if next not in visited and no_enemies(next.pos, m.pos, g):  
                   visited.append(next)  
                   nextQueue.append(next)  
                   from_node[to_string(next)] = m  
                   if next.pos == sink and all(next.keys):  
                       return get_path(start, next, from_node)

           if m.pos in key_rooms and not m.keys[key_rooms.index(m.pos)]:  
               new_keys = m.keys.copy()  
               new_keys[key_rooms.index(m.pos)] = True  
               next = SearchNode(m.pos, round, new_keys)  
               if next not in visited and no_enemies(next.pos, m.pos, g):  
                   visited.append(next)  
                   nextQueue.append(next)  
                   from_node[to_string(next)] = m  
                   if next.pos == sink and all(next.keys):  
                       return get_path(start, next, from_node)

       roundQueue = nextQueue

       if len(nextQueue) == 0:  
           print("Failed to find path!")  
           exit(1)  
       nextQueue = []  
       g.step(0, 0)  
       round = (round + 1) % 12

POS = 0x25  
DIR = 6

ACTION_COUNT = 0

start = POS-1  
dir = DIR  
g = game.Game()

res = game.MAP  
for i, k in enumerate(room_keys):  
   res = game.apply_permutation(game.ROUNDS[i].key_to_perm[k], res)

assert res == [hex(i+1)[2:].upper().rjust(2, '0') for i in range(0x36)]

for ROUND in range(25):  
   graph = generate_graph()  
   map = [int(x, 16) for x in game.MAP]  
   end = int(goal_rooms[ROUND], 16)-1

   keys = []  
   key_len = 0  
   if ROUND in pickup:  
       key_len = len(pickup[ROUND])  
       for r in game.ROUNDS[ROUND].key_rooms:  
           if r[2:4] in pickup[ROUND]:  
               keys.append(int(r[0:2], 16) - 1)

       if len(keys) != len(pickup[ROUND]):  
           print("Oh no, double items?")  
           exit(1)

   path = bfs(graph, start, end, g, keys)  
   ACTION_COUNT += len(path)-1

   room_to_id = {}  
   for r in game.ROUNDS[ROUND].key_rooms:  
       if ROUND in pickup and r[2:4] in pickup[ROUND]:  
           if int(r[0:2], 16) in room_to_id:  
               print("Multiple keys to pickup in one room")  
               exit(1)  
           room_to_id[int(r[0:2], 16)-1] = int(r[2:4], 16)

   actions = ""  
   for i in range(len(path)-1):  
       pos = path[i]  
       next = path[i+1]

       if pos == next:  
           actions += "pick up " + item_names[room_to_id[pos] - OFFSET] + '\n'  
           continue  
       if game.move(pos, dir) == next:  
           actions += "go forward" + '\n'  
           continue  
       if game.move(pos, game.turnLeft(pos, dir)) == next:  
           actions += "turn left" + '\n'  
           dir = game.turnLeft(pos, dir)  
           continue  
       if game.move(pos, game.turnRight(pos, dir)) == next:  
           actions += "turn right" + '\n'  
           dir = game.turnRight(pos, dir)  
           continue  
       if game.move(pos, game.turnAround(dir)) == next:  
           actions += "turn around" + '\n'  
           dir = game.turnAround(dir)  
           continue

       print("Prog error")  
       print(hex(pos+1), dir, path)  
       print(graph)  
       exit(1)

   actions += "place " + item_names[int(room_keys[ROUND], 16) - OFFSET] + '\n'  
   actions += room_keys[ROUND] + '\n'  
   with open(f"real/move{ROUND}.txt", "w") as file:  
       file.write(actions)

   print("Round:", ROUND, ", Actions:",  
         ACTION_COUNT, [hex(i+1) for i in path])

   start = path[-1]

   old = game.MAP

   g.end_round(room_keys[ROUND])

   if ROUND < 24:  
       dir = g.fixDirection(start, dir, room_keys[ROUND])

print("All done!")

```

All done, we have the output including a log of the game that finally contains
the rewarding lines: "You see sunlight through a crack in the walls. You are
finally free. Please wait for your reward!".  
After all this effort to get here, it is actually quite fitting that our last
action before is simply "place stego challenge" (in the bin, that is).

## Final remarks

Where flag? You surely noticed that I didn't mention it above.  
This is, sadly, because my solution does not get the flag but only a randomly
colored image...  
I am not sure that this is my fault, however, since there are actually
multiple shortest paths through the maze.  
Take the first round for example: it contains two items to pick up in adjacent
rooms and we could do that in either order without changing the length of our
solution.  
So it is probably for the better that no team seemed to come close to solving
this challenge.  
It would have been a big drama to notice this problem after hours of work and
stress ¯\_(ツ)\_/¯.

In theory, my solver might produce different results both for different graph
generations and depending on the prioritization of items or movement.  
I did not want to try finding the author's solution by chance though since
they didn't provide their sequence in their writeup.

I liked playing this challenge despite its problems and even though it annoyed
me every once in a while at the same time.  
Was it really a good idea to put it in a CTF?  
I am probably not the best to judge that since other teams have come a lot
closer to actually solving the challenge in time.  
However, I still believe it was just too big of a challenge and it sadly
lacked a bit of testing.  
Anyway, I am glad the author took the (probably also enormous amount of) time
to write this interesting challenge and force us to learn some LaTeX3.

Original writeup (https://ik0ri4n.de/hxp-ctf-22-tex-based-adventure).