**No files provided**

**Description**

> Last year, we planned a party but had some issues with multiple people
> working at the same time. This year, we've improved communication, but
> everyone is far away. We need to find the best place to host the after-party
> minimizing total travel time.  
>  
> Note: All of the food needs to be picked up.  
>  
> Can you help? If so, please contact pppr.chal.pwning.xxx:3444.

**Solution**

After logging in, we get a question:

   Would you like the condensed version? [y/N]

Naturally, we start by reading the verbose version. The challenge is described
like this:

   You'll need to answer 141 queries about where we should hold our party.  
   For each query, please respond with the index of the city where the party
should be held and the sum total travel time for everyone to get there (two
space-separated integers). Please find the location that minimizes the total
travel time for everyone. Note that the total travel time will be less than
10^18.  
   In this scenario, there are 12 cities, 14 bidirectional roads between them,
and 4 people that are coming.  
   Here are where all the people are:  
   There is a person at city 11  
   There is a person at city 2  
   There is a person at city 0  
   There is a person at city 9  
   Every person also needs to pick up food from exactly one city on the way to
the party. Here is a list of where all of the good food is:  
   There is good food at city 10  
   There is good food at city 3  
   There is good food at city 7  
   There is good food at city 2  
   Now, I'll tell you about the start city, end city, and travel time for each
road.  
   There is a road that goes from 0 to 1 and takes 152 minutes to travel
along.  
   There is a road that goes from 0 to 4 and takes 586 minutes to travel
along.  
   There is a road that goes from 0 to 7 and takes 665 minutes to travel
along.  
   There is a road that goes from 1 to 2 and takes 998 minutes to travel
along.  
   There is a road that goes from 2 to 9 and takes 475 minutes to travel
along.  
   There is a road that goes from 2 to 5 and takes 260 minutes to travel
along.  
   There is a road that goes from 3 to 8 and takes 966 minutes to travel
along.  
   There is a road that goes from 3 to 6 and takes 871 minutes to travel
along.  
   There is a road that goes from 5 to 6 and takes 83 minutes to travel along.  
   There is a road that goes from 6 to 11 and takes 669 minutes to travel
along.  
   There is a road that goes from 8 to 9 and takes 571 minutes to travel
along.  
   There is a road that goes from 9 to 10 and takes 545 minutes to travel
along.  
   There is a road that goes from 9 to 11 and takes 659 minutes to travel
along.  
   There is a road that goes from 10 to 11 and takes 436 minutes to travel
along.  
   Where should they hold the party, and how long will it take everyone to get
there?

And, while reading this, we also get a very quick timeout (~2 seconds):

   You ran out of time

The "condensed" version for the above would read:

   141  
   12 14 4  
   11  
   2  
   0  
   9  
   10  
   3  
   7  
   2  
   0 1 152  
   0 4 586  
   0 7 665  
   1 2 998  
   2 9 475  
   2 5 260  
   3 8 966  
   3 6 871  
   5 6 83  
   6 11 669  
   8 9 571  
   9 10 545  
   9 11 659  
   10 11 436

Note that each query only sends a count of cities, roads, and people. The
number of foods is the same as the number of people. I thought it wasn't
immediately obvious, but the organisers quickly clarified on IRC and via the
note you see in the descrition. So, each person needs to get one food, then
head to the meeting city.

A nice algorithmic question!

### Algorithm description ###

The cities and roads form a weighted (non-directed) graph. We use Dijkstra's
algorithm to work out the shortest path between each person to each food city.
We also do this for each food. We know that all foods need to be collected, so
part of our answer will be the sum of the journey distances from all food
cities to the meeting point. For this we can simply check each city and sum up
the distances from all the foods and keep track of the best (minimum distance)
city.

The other part of the problem is to work out which person collects which food.
This is more difficult, since the number of assignments for `n` people is `n!`
(factorial). Even with 16 people this is an immense number of permutations to
consider. Serious optimisation is required.

We first start with a trivial assignment of person 1 to food 1, person 2 to
food 2, and so on.

| | F1 | F2 | F3 | F4 |  
| --- | --- | --- | --- | --- |  
| P1 | (4) | 2 | 1 | 3 |  
| P2 | 4 | (4) | 1 | 3 |  
| P3 | 1 | 2 | (5) | 3 |  
| P4 | 8 | 2 | 1 | (1) |

This is obviously rarely the best permutation, but it is only a starting point
for the next step, a greedy algorithm – we swap the assignments of pairs of
people whenever the total distance decreases.

| | F1 | F2 | F3 | F4 |  
| --- | --- | --- | --- | --- |  
| P1 | (4) | -2- | 1 | 3 |  
| P2 | -4- | (4) | 1 | 3 |  
| P3 | 1 | 2 | (5) | 3 |  
| P4 | 8 | 2 | 1 | (1) |

In the above table, swapping P1 and P2 decreases the total distance by 2.
After a couple of steps, there are no more beneficial swaps:

| | F1 | F2 | F3 | F4 |  
| --- | --- | --- | --- | --- |  
| P1 | 4 | (2) | 1 | 3 |  
| P2 | 4 | 4 | (1) | 3 |  
| P3 | (1) | 2 | 5 | 3 |  
| P4 | 8 | 2 | 1 | (1) |

For some time, while working out the solution to this challenge, I thought
this solution would always converge to the optimal solution. Fortunately,
before this greedy algorithm I first implemented an actual bruteforce checker
which simply goes through all the permutations via Heap's algorithm. I say
fortunately because this helped me find out that there are situations in which
the greedy algorithm will not reach the minimum distance. An example from an
actual problem generated by the server:

| | F1 | F2 | F3 | F4 |  
| --- | --- | --- | --- | --- |  
| P1 | 1167 | 1097 | 991  | 1787 |  
| P2 | 1414 | 1489 | 1771 | 1889 |  
| P3 | 1255 | 961  | 1497 | 2001 |  
| P4 | 2054 | 1984 | 1004 | 1800 |

Greedy algorithm solution `[3, 1, 2, 4]`, giving a total distance of `5166`:

| | F1 | F2 | F3 | F4 |  
| --- | --- | --- | --- | --- |  
| P1 | 1167 | 1097 | (991)  | 1787 |  
| P2 | (1414) | 1489 | 1771 | 1889 |  
| P3 | 1255 | (961)  | 1497 | 2001 |  
| P4 | 2054 | 1984 | 1004 | (1800) |

Bruteforce solution `[1, 4, 2, 3]`, giving a total distance of `5021`:

| | F1 | F2 | F3 | F4 |  
| --- | --- | --- | --- | --- |  
| P1 | (1167) | 1097 | 991  | 1787 |  
| P2 | 1414 | 1489 | 1771 | (1889) |  
| P3 | 1255 | (961)  | 1497 | 2001 |  
| P4 | 2054 | 1984 | (1004) | 1800 |

So how come the greedy algorithm could not find this? The swapping algorithm
minimises the total distance, but only ever considers what happens when two
people's foods are swapped. To reach the optimal solution in this case, it
would have to swap people in a cycle of size 3.

This was bad news. I could expand the greedy algorithm to first consider swaps
of two, then of cycles of three, and so on. Unfortunately, this makes it just
as bad in time complexity as the bruteforce algorithm!

So for the actual solution, the greedy swapping algorithm is applied, but only
as a single step before a more thorough check. It is relatively quick
(`O(n^2)` for `n` people) and it produces a reasonable "best guess" value for
the minimum distance.

The next step is to evaluate all permutations! But with a very important
optimisation - pruning. The way people are assigned to food can be modeled as
a tree of choices, at each level choosing one of the remaining foods to the
next person. An example with 3 people:

   P1 -(F1)- P2 -(F2)- P3 -(F3)- [1, 2, 3]  
     |         \  
     |          \(F3)- P3 -(F2)- [1, 3, 2]  
     \           
     |\(F2)- P2 -(F1)- P3 -(F3)- [2, 1, 3]  
     |         \  
     |          \(F3)- P3 -(F1)- [2, 3, 1]  
     \           
      \(F3)- P2 -(F1)- P3 -(F2)- [3, 1, 2]  
               \  
                \(F2)- P3 -(F1)- [3, 2, 1]

The bruteforce algorithm explores each leaf of this tree. But this is often
unnecessary. As we walk down the tree, we add distances one by one to a
running total, so our total distance for a given assignment is the value of
this running total when we reach a leaf of the tree. But suppose we have
already found a solution with a total distance of 200, when exploring a branch
that already has a running total of 250 – clearly we cannot find a better
solution in that branch, since the distances are all positive and the running
total will only ever increase. This is the principle of pruning. Whenever we
actually reach a leaf, we reached it because it is a better solution than the
current best, so we can remember this one instead.

So we set our best minimum to the result of the greedy swapping algorithm and
go through the permutations. How else can we speed the process up?

In the above diagram, the foods are always chosen for each person in the same
order (F1, then F2, then F3) if available. Suppose P1 lives in the same city
as F3, but is far from all other foods - then F3 is clearly the best
assignment for P1, but we first try to give them F1, then F2. If we try to
assign foods with shorter distances to people as we are iterating the tree, we
improve our chances of finding a better minimum sooner, allowing us to prune
away a larger part of the tree. So – we sort each row of the person-food
distance table and assign foods in that order at each level.

Finally, there is one more improvement we can make to the pruning. We can
remember the minimum of each row in the person-food distance table. At each
level of the tree, we can calculate the sum of the row minima of the levels
below. Most likely, it would be impossible to reach this mimimum, because it
can contain conflicting assignments (i.e. two people assigned to the same
food). However, we know we definitely cannot do better than that minimum in
the levels below. So, if our running total + the row minima of the levels
below exceeds the best known solution, we can stop exploring this branch.

### But … ###

There is a problem. All of the above works very quickly and solves the queries
given by the server in fractions of seconds. But sometimes the server rejects
the answer. The best I've seen is 24 / 141 queries answered correctly. I
thought the problem might be that people cannot cross other food cities before
reaching the meeting point, which may be a food city. This required some
annoying changes in the code – i.e. when solving distances from food to
cities, do Dijkstra's algorithm, but never go to a food city. Then for each
food city, look at all of its neighbours and see if each food can reach at
least one.

But then I got this query from the server:

   9 8 9  
   6  
   2  
   7  
   8  
   5  
   3  
   0  
   1  
   4  
   5  
   6  
   2  
   1  
   4  
   7  
   8  
   0  
   3  
   0 6 817  
   0 7 417  
   1 2 118  
   2 8 687  
   2 3 412  
   2 4 78  
   4 7 595  
   5 8 358

In this situation, each city has a food in it, as well as a person. Here is a
graph representation:

                   1  
                   |  
   6 - 0 - 7 - 4 - 2 - 8 - 5  
                   |  
                   3

Clearly there will always be some people who cannot reach the meeting point
without crossing other food cities. E.g. if the meeting point is 2, the person
from city 6 has to cross cities 0, 7, and 4.

So, currently I have no idea what could be wrong with my approach. Perhaps I
made a mistake in my assumptions, or I'll talk to an admin and find out for
sure.  

Original writeup
(https://github.com/Aurel300/empirectf/blob/master/writeups/2018-05-05-PlaidCTF/README.md).