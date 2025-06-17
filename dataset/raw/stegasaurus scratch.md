#### Problem description

**Part1:**  
Alice gets the array of 8 random numbers from interval `[0,40000]`, discards
one number and sends the permutation of these numbers to Bob. Bob then have to
figure out the discarded card from the permutation of the numbers he got. The
challenge was to implement functions for Bob and Alice, where Alice and Bob
were supposed to not share any other state between them.

**Part2:**  
Alice gets a random list consisted of exactly 64 1's and 32 2's. She then
chooses exactly 32 positions of 1's and sends them to Bob. Bob by having 32
1's has to figure out the original array consisted of 96 elements. The
challenge was to implement functions for Bob and Alice, where Alice and Bob
were supposed to not share any other state between them.

#### Brief solutions

**Part1:**  
The solution comes from the [paper](https://sci-hub.tw/10.1007/BF03025305)
that I got from p4 team after the CTF and which we failedd to solve during the
CTF, although we were very close and the script only needed brief changes.

TL;DR  
We can represent the discarded element by `discarded = 8*p + reminder`, where
it is known that `p < 40000/8 < 5040 = 7!` and `0 <= reminder < 8`. By
permutation of the 7 cards, Alice can encode `p`. By simplyfing a little bit,
the reminder is the position of the discarded element in the sorted array,
which Alice can smuggle to Bob indirectly and Bob can recover. In the code and
the paper it's a little bit more smart, but this a similar approach. From
that, Bob can easily recover the number.

**Part1:**  
The idea for the solution is the observation that at least one 2 must be
adjacent to one 1. So the Alice wants to choose that 1 because Bob can then
know that there must be 2 next to it.

By induction, that one pair of (1,2) can be "removed" and the process
repeated, which proves solvability of the problem. If we treat the array as a
cycle, then there are exactly two 2 that are adjacent to 1. I chose to always
leave the 1 that is right to 2, e.g. 22221

The commented PoCs for the solutions are
[here](https://gist.github.com/terjanq/a28476359870600c7ad79eb0bbdd9d07)

Original writeup
(https://gist.github.com/terjanq/a28476359870600c7ad79eb0bbdd9d07).