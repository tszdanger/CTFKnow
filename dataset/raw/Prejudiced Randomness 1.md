Prejudiced Randomness 1 (and the idea behind 2)  
===============================================

Category: crypto

Points: 123 (easy) / 338 (hard)

Solves: 39 (easy) / 8 (hard)

Statement  
---------

I found new uber crypto that allows us to securely generate random numbers!
Lets use this to play a very fair game of random chance. Win the game!

```nc hax.allesctf.net 7331```

[challenge.py](https://static.allesctf.net/prejudiced-2d332bfde033d72af2c04293710c90de7da93c1240b9e821810747dc9c195667.py)

Solution  
--------

We are given a strange, random-based game. The server asks us for a number
```n``` equal to a product of two big primes ```p``` and ```q```. Then it
generates ```r```, which is kept secret from us, and then calculates the value
```s = r**2 modulo n``` and gives us the value of ```s```. We are tasked to
find the square root of ```s``` modulo ```n```. Let's denote square root found
by us as ```z```. The server tries to factor ```n``` by taking ```GCD(n, r -
z)```. If server manages to factor ```n``` then we lose and if not then we
win. In order to solve the easier part of the task, we must win at least 90%
of the games and in order to solve the harder part of the task, we must lose
at leat 90% of the games.

Why does this game even works?  
------------------------------

The first step towards solving the problem is to understand how does this game
even works. Why does this method allows the server to factor ```n```? And why
does this method only works 50% of the time?

First of all, it is important to know, that ```s``` will have 4 square roots
modulo ```n```. It can be easily shown that for a prime moduli (eg. ```p```)
there are always 0 or 2 square roots. If one of the square roots modulo
```p``` is ```r```, then the other one will be ```p - r```. Therefore ```s```
have two square roots modulo ```p``` and two square roots modulo ```q``` and
any pair of these residues (one modulo ```p``` and one modulo ```q```) will
result in a different residue modulo ```n``` being a square root of ```s```
(spoiler alert: as long as ```p != q```).

Now let ```r``` be the residue found by a server and ```z``` be the residue
found by us. Their squares have the same residue modulo ```n```, so ```r**2 -
z**2 = 0 modulo n```, so ```(r - z)(r + z) = 0 modulo n```. So ```(r - z)(r +
z)``` is a multiple of ```n = p * q```. Also it's safe to asume, that neither
```p**2``` nor ```q**2``` divides ```(r - z)(r + z)```, because the server
makes sure that our given ```p``` and ```q``` are large enough for this
situation to be highly improbable. Therefore we have four, equiprobable
situations:

* both ```p``` and ```q``` divide ```(r - z)```. Then ```GCD(n, r - z) = n``` and we win.  
* both ```p``` and ```q``` divide ```(r + z)``` and neither divide ```(r - z)```. Then ```GCD(n, r - z) = 1``` and we win.  
* one of the ```p``` and ```q``` divides ```(r - z)``` and the other one divides ```(r + z)```. The we lose, as the server can factor ```n```.

This illustrates, how this game is (seemingly) random and should result in a
win-lose ratio equal to 1:1.

Few words before the actual solution  
------------------------------------

The title and description could make an impression that this task will require
us to perform some rng prediction, but it turns out not to be the case here,
as the rng used is python's SystemRandom, which uses system's urandom.

The challenge also requires us to take square roots of number modulo product
of two primes. As stated earlier, one can find the square roots modulo ```p```
and ```q``` first, then using chinese remainder theorem combine them into a
square root modulo ```n```. There are several methods to find square roots
modulo prime number:

* As we can chose the number ```n```, the first method is to use specially prepared primes, eg. for primes of form ```4k + 3```, the solutions are actualy equal to ```+- s**((p + 1) / 4)```.  
* [Tonelli-Shanks algorithm](https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm) is probably the most popular one.  
* [Cipolla's algorithm](https://en.wikipedia.org/wiki/Cipolla%27s_algorithm) on the other hand is my favourite one. It's so simple and elegant, yet so ingenious. It's also a brilliant example of how thinking outside of the box (or outside of the field in this case :) ) can sometimes solve a problem.

The last algorithm has also another advantage: it's extremely easy to modify
it to find square roots modulo prime powers (spoiler alert: this will be
useful for us).

The easy solution  
-----------------

In the easier part of the task, we want to win as many games as possible. We
must therefore guarantee, that it's not possible to factor our number. The
server performs various checks to see if our input was not too cheesy (ie. if
our n is really a product of two primes that are at least 512 bits large). The
server however doesn't check if our selected primes are different. What would
happen if we were to send an ```n``` equal to ```p * p```? It means that
server will be able to factor our ```n``` iff both ```(r - z)``` and ```(r +
z)``` are divisible by ```p```. This on the other hand means, that both
```r``` and ```z``` must be divisible by ```p```. The ```r``` however is
selected uniformly randomly by the server, which means that with ```p``` 512
bits large, it is extremely improbable to happen. This can guarantee us to win
(almost) 100% of the time!

The biggest problem I had to face was to actually implement the Cipolla's
algorithm, which requires us to perform arithmetic operations in the extended
field. The problem can be solved analogously to implementing complex numbers
however. We can store each field element as pair of numbers ```(a, b)```, so
that our element is equal to ```a + b * sqrt(v)``` where ```v``` is our non-
residue. Now ```(a1, b1) + (a2, b2) = (a1 + a2 modulo n, b1 + b2 modulo n)```
and ```(a1, b1) * (a2, b2) = (a1 * a2 + v * b1 * b2 modulo n, a1 * b2 + b1 *
a2 modulo n)```.

The code for addition and multiplication is below:

```python  
def mul(a, b, v, p):  
	xa, ya = a[0], a[1]  
	xb, yb = b[0], b[1]  
	xr = (xa * xb + v * ya * yb) % p  
	yr = (xa * yb + xb * ya) % p  
	return (xr, yr)

def add(a, b, p):  
	xa, ya = a[0], a[1]  
	xb, yb = b[0], b[1]  
	return ((xa + xb) % p, (ya + yb) % p)  
```

To raise our element to the power I used the exponentiation by squaring
method, which doesn't differ from the one on regular numbers if we have
multiplication implemented.

The square root part is here, although it's just a formula from linked
wikipedia article rewritten as code:

```python  
def sqroot(s, p, k):  
	#finding non-residue  
	a = 1  
	while pow(a * a - s, (p - 1) // 2, p) != p - 1:  
		a += 1  
	#the formula  
	t = (p**k - 2 * p**(k-1) + 1) // 2  
	q = p**(k - 1) * (p + 1) // 2  
	pk = p ** k  
	ld = a * a - s  
	return (invert(2, pk) * pow(s, t, pk) * add(poww((a, 1), q, ld, pk), poww((a, -1), q, ld, pk), pk)[0]) % pk  
```

Full script can be found in ```prejudiced1.py``` file.

Flag: ```ALLES{m4ster_of_r4ndomn3zz_squ4red}```

The hard solution?  
------------------

Unfortunately, I wasn't able to crack this one entirely during the contest,
but I firmly believe I know, what had to be done more or less. This time we
want to lose as many games as possible. Let's think about what would happen if
our given ```n``` could be a product of more than just 2 prime numbers (eg.
```k``` of them). As every prime gives us 2 distinct square roots, this means
that the overall number of square roots modulo ```n``` would be ```2**k```,
but still all of them but two can aid the server in finding a factor of
```n```. Therefore chances of winning drop to ```2**-(k-1)```. Therefore, as
long as we could smuggle ```n``` being a product of, let's say, 7 primes, we
are good.

And there is a good reason to believe that it's possible. The code uses a
[Miller-Rabin primality
test](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test),
which is unbreakable (as long as well implemented :) ). And the last line of
it's implementation looks very fishy:

```python  
def is_prime(n, rounds):  
   if n % 2 == 0:  
       return False  
   d, s = n - 1, 0  
   while not d % 2:  
       d, s = d >> 1, s + 1  
   return not any(test(a, d, n, s) for a in R.sample(range(1,314), rounds))  
```

Basically, they perform the test only using bases less than ```314```. This is
a bad idea, because although there are approximately ```n/4``` witnesses for a
composite ```n```, they are not uniformly distributed amongst numbers ```[0,
n)```. Moreover, there are methods allowing to craft composite numbers that
fail this test for given set of bases. On of the methods is described in [this
article](https://www.sciencedirect.com/science/article/pii/S0747717185710425),
though it's more like a mathematical concept, rather than a step by step
tutorial, so there was still a lot of work to do in order to fully understand
and utilize the idea in order to capture the hard part flag.

Therefore I leave the rest of the problem as an exercise to the reader :). I'm
also not giving up on this problem yet, so maybe in the nearest future if I
manage to crack this Miller-Rabin, you can expect a more detailed write-up for
this part.

Conclusion  
----------

I must admit, from all the CTFs I've played so far, this must be one of my
all-time favourite crypto challenges. The idea behind this random-based game
is very interesting and the idea of exploiting concepts used in this task is
something I haven't seen before in a CTF task. I really frankly wait for the
next year's edition and hope for even more interesting problems to be found
there :)

Cheers!  

Original writeup (https://github.com/wonrzrzeczny/CTF-
writeups/tree/master/Chaos%20Communication%20Camp%202019%20CTF/Prejudiced%20Randomness).