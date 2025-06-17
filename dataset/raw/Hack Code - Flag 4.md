# Hack Code

We get a file with a lot of routes (given as lists of routers), and  
are asked to find a small subset of routers to tap so that we have at  
least one tap on each route. We will ignore the topology of the  
network and the order of routers in the paths, and will treat this as  
a set cover problem: the routes are sets, and we need to pick a small  
set of elements (routers) such that we cover all routes.

We can start with a simple randomised solution: iterate through all  
sets, and if no elements in the set are in the current solution, pick  
one at random and insert it. This will produce solutions with around  
200 elements -- not enough to get any flags, but it is a start.

Next, we can try to improve this (again, at random) with the following  
algorithm:

* pick a random router not yet in the solution  
* insert it in the solution  
* for each other router, see if we can remove it without "breaking"  
 our solution (so all sets are still covered) and remove it if we can  
* if we couldn't remove anything, remove the new router

Sometimes we will add a router and remove multiple old routers, so  
this will slowly improve the solution, and after a minute or two we  
will have one that is good enough to get the first flag.

A small optimisation to the algorithm will make it run significantly  
faster: instead of checking all routers in each iteration, only look  
at those for which we could have made a difference -- those that are  
in one of the sets covered by the new entry. With this optimisation,  
in a few minutes we get a solution with 126 routers, which is enough  
to get all flags (and the best the organisers found).

My code that solves this (note: written in a rush during the CTF and  
presented here without any cleanup) can be found  
[here](https://de298.user.srcf.net/writeups/insa/hackcode.py).  

Original writeup (https://de298.user.srcf.net/writeups/insa/hackcode.html).