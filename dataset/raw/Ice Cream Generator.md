{{< admonition type=success title="Note" open=true >}}  
This writeup was one of the 5 winners of Amateurs CTF writeups prize  
{{< /admonition >}}

## Overview

This was the first edition of Amateurs CTF and I absolutely loved the
challenges. Managed to solve **[7]/[12]** crypto challenges. They were really
fun and educational.  
But `Ice cream generator` was the most beautiful of them all (also my favorite
problem of this year so far) ?. I plan to make a detailed writeup of it.

## The challenge

{{< admonition note "Challenge Information" >}}  
* **Points:** 495  
* **Description:** Ice cream. Or wait... Ice cream. Same difference.

`nc amt.rs 31310`

[main.py](https://amateurs-
prod.storage.googleapis.com/uploads/fe298c6cc6b64777761d3f0c97a0b5139569e126f5c4660fa16e796376e83509/main.py)

{{< /admonition >}}

Let's take a look at the given code (you can skip it though, looks scary).

```python  
#!/usr/local/bin/python  
from Crypto.Util.number import *  
from os import urandom  
from flag import flag

class lcg:  
   def __init__(self, p):  
       while (a:=bytes_to_long(urandom(16))) > p:  
           pass  
       while (b:=bytes_to_long(urandom(16))) > p:  
           pass  
       self.a, self.b, self.p = a, b, p  
  
   seed = 1337

   def gen_next(self):  
       self.seed = (self.a*self.seed + self.b) % self.p  
       return self.seed

class order:  
   def __init__(self, p):  
       self.p = p

       self.inner_lcg = lcg(p)  
  
       for i in range(1337):  
           self.inner_lcg.gen_next()

       self.flavors = [self.inner_lcg.gen_next() for i in range(1338)]

       self.flavor_map = {i:self.flavors[i] for i in [1,2,3,4,5,6]}  
       self.private = {i:self.flavors[i] for i in [1,2,3,4,5,6,1337]}  
  
   bowls = [0, 0, 0]  
   used = {1:0, 2:0, 3:0, 4:0, 5:0, 6:0}  
   recipe = []

   def make_bowl(self):  
       global flavor_indices  
       self.bowls = [0, 0, 0]  
       self.recipe = []  
       new = {}  
       available = []  
       for i, n in self.used.items():  
           if n == 0:  
               new[i] = 0  
               available += [i]  
       self.used = new  
       print("\nREMAINING FLAVORS: ")  
       for i in available:  
           print(f"Flavor {i} - {flavor_indices[i]}")  
       while True:  
           command = input("\nAdd, combine, or finish? ")  
           if command.lower() == "add":  
               try:  
                   add = input("\nGive a flavor and a bowl: ").rsplit(" ", 1)  
                   self.add(*add)  
               except Exception as e:  
                   print()  
                   print(e)  
           elif command.lower() == "combine":  
               try:  
                   combination = input("\nGive two bowls and an operation: ").split()  
                   assert len(combination) == 3, "Invalid Input Length"  
                   self.combine_bowl(*combination)  
               except Exception as e:  
                   print()  
                   print(e)  
           elif command.lower() == "finish bowl":  
               self.finish_bowl()  
           elif command.lower() == "finish":  
               self.finish()  
               break  
           elif command.lower() == "exit":  
               exit(1)  
           else:  
               print("\nPlease give a valid input.")  

   def mod(self):  
       self.bowls = [i % self.p for i in self.bowls]

   def add(self, flavor, bowl):  
       assert "0" < bowl < "4", "Invalid Bowl"  
       bowl = int(bowl) - 1  
       global flavor_names  
       if flavor not in ["1", "2", "3", "4", "5", "6"]:  
           try:  
               if self.used[flavor_names[flavor]] < 5:  
                   self.bowls[bowl] += self.flavor_map[flavor_names[flavor]]  
                   self.used[flavor_names[flavor]] += 1  
                   self.recipe += [[flavor_names[flavor], bowl]]  
               else:  
                   print(f"\nCannot order {flavor} due to stock issues.")  
           except:  
               print("\nInvalid Flavor")  
       else:  
           try:  
               flavor = int(flavor)  
               if self.used[flavor] < 5:  
                   self.bowls[bowl] += self.flavor_map[flavor]  
                   self.used[flavor] += 1  
                   self.recipe += [[flavor, bowl]]  
               else:  
                   print(f"\nCannot order {flavor} due to stock issues.")  
           except:  
               print("\nInvalid Flavor")  
  
   def combine_bowl(self, a, b, op):  
       assert op in ['add', 'sub', 'mult', 'div'], "Invalid Operation. Please choose either 'add', 'sub', 'mult', or 'div'."  
       assert "0" < a < "4" and "0" < b < "4" and a != b, "Invalid Bowl"  
       a = int(a) - 1  
       b = int(b) - 1  
       if op == 'add':  
           self.bowls[a] += self.bowls[b]  
       elif op == 'sub':  
           self.bowls[a] -= self.bowls[b]  
       elif op == 'mult':  
           self.bowls[a] *= self.bowls[b]  
       elif op == 'div':  
           assert self.bowls[b] != 0, "Empty Bowl for Division"  
           self.bowls[a] *= pow(self.bowls[b], -1, self.p)  
       else:  
           print("\nwtf")  
           exit(1)  
       self.recipe += [[op, a, b]]  
       self.bowls[b] = 0  
       self.mod()  
  
   def finish_bowl(self):  
       unique = 0  
       for i, n in self.used.items():  
           if n and n != 1337:  
               unique += 1  
       if unique < min(3, len(self.used)):  
           print("\nAdd more flavor!")  
           return False  
       recipe = str(self.recipe).replace(' ', '')  
       signature = sum(self.bowls) % self.p  
       self.bowls = [0, 0, 0]  
       self.recipe = []  
       for i in self.used:  
           if self.used[i]:  
               self.used[i] = 1337  
       print(f"\nUser #: {self.p}")  
       print(f"\nRecipe: \n{recipe}")  
       print(f"\n\nSignature: \n{signature}")  
       return True  
  
   def finish(self):  
       if sum(self.bowls):  
           if not self.finish_bowl():  
               print("\nOk the bowls will be dumped.")  
       print("\nOrder done!")  
       return True

   def verify(self, recipe, signature):  
       bowls = [0, 0, 0]  
       for i in recipe:  
           try:  
               if len(i) == 2:  
                   bowls[i[1]] += self.private[i[0]]  
               elif len(i) == 3:  
                   if i[0] == 'add':  
                       bowls[i[1]] += bowls[i[2]]  
                   elif i[0] == 'sub':  
                       bowls[i[1]] -= bowls[i[2]]  
                   elif i[0] == 'mult':  
                       bowls[i[1]] *= bowls[i[2]]  
                   elif i[0] == 'div':  
                       bowls[i[1]] *= pow(bowls[i[2]], -1, self.p)  
                   bowls[i[2]] = 0  
               bowls = [i % self.p for i in bowls]  
           except:  
               exit("\nInvalid Recipe")  
       try:  
           assert sum(bowls) % self.p == signature, "\nInvalid Signature"  
           print("\nYou have successfully redeemed your lce cream!")  
           if signature == self.private[1337]:  
               print(flag)  
       except Exception as e:  
           print(e)  

flavor_names = {"revanilla":1, "cryptolatte":2, "pwnstachio":3,
"strawebrry":4, "miscnt":5, "cookie dalgo":6, "flaudge chocolate":1337}  
flavor_indices = {i:n for n, i in flavor_names.items()}

intro = \  
"""  
----------------------------------------------------  
           WELCOME TO THE LCE CREAM SHOP!            
----------------------------------------------------  
 HERE AT THE LCE CREAM SHOP WE HAVE A FEW BELIEFS  

1. Don't be boring! Choose at least 3 flavors of lce cream. All of it tastes the same anyways...  
2. Don't be repetitive! Well... that and the fact that we have some stock issues. After getting one lce cream with one flavor, you don't get to choose that flavor again.  
3. Since I rolled my own signature system that is extremely secure, if you can manage to forge an arbitrary flavor, I'll give it to you! As long as it exists...  
4. These aren't really beliefs anymore but we only have 6 flavors (available to the customer), and you're only allowed to order once (stock issues again smh). Choose wisely!  
5. To help with the boringness, I will allow you to mix flavors in any way you want. But you can only use up to 5 scoops of each flavor to concoct your lce cream (once again stock issues).  
6. I AM ONLY ACCEPTING ONE RECIEPT. If the first fails, too bad.  
7. I heard there's a special flavor called "flaudge chocolate", it's like the 1337th flavor or something.  
8. Orders can have multiple lce cream mixtures, as long as they follow the rules above.  
9. I am accepting reciepts for TAX PURPOSES only.  
10. Each scoop costs $5 (stock issues AGAIN).  
11. The reciept itself costs $1.  
12. Everything is free. Have fun!  
13. Zero indexing sucks. Here at LCE CREAM SHOP we use one indexing.

Oh yeah here are the options:"""

options = \  
"""  
OPTIONS:  
(1) Generate order  
(2) View flavors  
(3) Redeem a reciept  
(4) Exit  
Choice: """

print(intro)

while True:  
   choice = input(options)  
   if choice == "1":  
       if 'user' in vars():  
           print("\nYou already ordered.")  
           continue  
       user = order(getPrime(128))  
       user.make_bowl()  
       print()  
   elif choice == "2":  
       print("\nThe only valid flavors are: ")  
       [print(f"Flavor {i} - {n}") for i, n in flavor_indices.items() if i != 1337]  
   elif choice == "3":  
       if 'user' not in vars():  
           print("\nNo user.")  
       else:  
           userid = int(input("\nENTER NUMBER: "))  
           assert userid == user.p, "You seem to have lost your reciept."  
           recipe = input("\nENTER RECIPE: ")  
           assert all([i in "[,]01234567abdilmstuv'" for i in recipe]), "\n\nSir, please don't put junk in my lce cream machine!"  
           recipe = eval(recipe, {"__builtins__": {}}, {"__builtins__": {}}) # screw json or ast.literal_eval  
           signature = input("\nENTER SIGNATURE: ")  
           user.verify(recipe, int(signature))  
           exit("\nGoodbye.")  
   elif choice == "4":  
       exit("\nGoodbye.")  
   else:  
       print("\nINVALID CHOICE. Please input '1', '2', '3', or '4'")  
```

At first glance, this seems to be a huge code with over 200 lines ?. I
immediately dropped the problem, thinking it was overcomplicated for my level,
and also because it only had like 2 solves at that moment.  
I returned to this problem almost a day later, when someone on the discord
mentioned that this was much simpler than it looks.

At its core, this is a very simple `LCG` problem. I would explain what it is,
in a short while. What makes this problem special is how we have to crack the
generator without having access to the  
generated random numbers(unlike other easy `LCG` problems, where we can just
spam some template).

## What is LCG?

`LCG` or [`Linear Congruential
Generator`](https://en.wikipedia.org/wiki/Linear_congruential_generator) is an
algorithm to generate `Pseudo Random Numbers` using linear equations.  
The underlying algorithm is very simple to understand. We can represent it
using a recurrence relation like this,  
$$X_{n+1} \ = \ aX_n + c \mod\ m$$

$X_0$ is the seed, used to generate the other random numbers $X_1, X_2, ...,
X_n$

$a$ is the multiplier

$c$ is the increment

$m$ is the modulus (though it's denoted by $p$ in this problem)

Note that all values are bounded by the modulus $m$.

A simple python implementation of LCG follows

```python  
class LCG:  
   def __init__(self, a, c, m, seed):  
       self.a, self.c, self.p, self.seed = a, c, m, seed

   def gen_next(self):  
       self.seed = (self.a*self.seed + self.c) % self.m  
       return self.seed  
```

## How to crack LCG?

There can be different variations to the problems related to cracking `LCG`.
Some give extra information, some go on to even truncate bits from the random
numbers to hide information.

The most common variant is to give some generated numbers (usually 6 numbers
is enough to recover all the parameters), and one has to find the `a, c, m,
seed` from those values. A very beautiful writeup explaining it in detail goes
[here](https://flocto.github.io/writeups/2023/deadsecctf/lcg-writeup/).

In our current problem, `m` and `seed` is already given, making it much easier
to solve. We have to recover `a` and `b`.

Let's say we have 3 generated numbers $X_1, X_2, X_3$.  
$$X_2 \ = \ aX_1 + c\mod\ m$$  
$$X_3 \ = \ aX_2 + c\mod\ m$$

Subtracting the first equation from the second gives us,  
$$X_3 - X_2 \ = \ a(X_2 - X_1) \mod\ m$$  
$$a \equiv\ \frac{X_3 - X_2}{X_2 - X_1} \mod\ m$$

So easy to recover `a` ?. It's trivial to recover `c` now.  
$$X_2 \ = \ aX_1 + c\mod\ m$$  
$$c \equiv\ X_2 - aX_1 \mod\ m$$

## Let's dive into the given code

It was difficult trying to understand the monstrosity of a code. Let us try to
understand the code function by function.

The code starts with the `LCG` class, meaning we have to crack LCG somehow.
But where are the generated random numbers? A quick check reveals that under  
`Order` class, 1337 random numbers are generated through the LCG and dropped.
The later 1338 numbers($X_{1338}$ to $X_{2675}$) are generated and stored in
the `flavors` array. 2 corresponding dictionaries (`flavor_map` and `private`)
are generated using values of the `flavors` array.  
```python  
self.flavors = [self.inner_lcg.gen_next() for i in range(1338)]

self.flavor_map = {i:self.flavors[i] for i in [1,2,3,4,5,6]}  
self.private = {i:self.flavors[i] for i in [1,2,3,4,5,6,1337]}  
```  
Some other variables are also there like,

`bowls`: A list of 3 bowls containing 0.

`used`: A dictionary showing how many times each flavor is used.

`recipe`: A list of what flavors used so far.

When the code is run, the following portion comes first:  
```python  
options = \  
"""  
OPTIONS:  
(1) Generate order  
(2) View flavors  
(3) Redeem a reciept  
(4) Exit  
Choice: """

print(intro)

while True:  
   choice = input(options)  
   if choice == "1":  
       if 'user' in vars():  
           print("\nYou already ordered.")  
           continue  
       user = order(getPrime(128))  
       user.make_bowl()  
       print()  
   elif choice == "2":  
       print("\nThe only valid flavors are: ")  
       [print(f"Flavor {i} - {n}") for i, n in flavor_indices.items() if i != 1337]  
   elif choice == "3":  
       if 'user' not in vars():  
           print("\nNo user.")  
       else:  
           userid = int(input("\nENTER NUMBER: "))  
           assert userid == user.p, "You seem to have lost your reciept."  
           recipe = input("\nENTER RECIPE: ")  
           assert all([i in "[,]01234567abdilmstuv'" for i in recipe]), "\n\nSir, please don't put junk in my lce cream machine!"  
           recipe = eval(recipe, {"__builtins__": {}}, {"__builtins__": {}}) # screw json or ast.literal_eval  
           signature = input("\nENTER SIGNATURE: ")  
           user.verify(recipe, int(signature))  
           exit("\nGoodbye.")  
   elif choice == "4":  
       exit("\nGoodbye.")  
   else:  
       print("\nINVALID CHOICE. Please input '1', '2', '3', or '4'")  
```  
We have to give `1` as our choice since a user must be created first. Let's
see the functionalities of this `make_bowl` function that is called after the
user is created.

### make_bowl  
```python  
while True:  
   command = input("\nAdd, combine, or finish? ")  
   if command.lower() == "add":  
       try:  
           add = input("\nGive a flavor and a bowl: ").rsplit(" ", 1)  
           self.add(*add)  
       except Exception as e:  
           print()  
           print(e)  
   elif command.lower() == "combine":  
       try:  
           combination = input("\nGive two bowls and an operation: ").split()  
           assert len(combination) == 3, "Invalid Input Length"  
           self.combine_bowl(*combination)  
       except Exception as e:  
           print()  
           print(e)  
   elif command.lower() == "finish bowl":  
       self.finish_bowl()  
   elif command.lower() == "finish":  
       self.finish()  
       break  
   elif command.lower() == "exit":  
       exit(1)  
   else:  
       print("\nPlease give a valid input.")  
```  
* We can choose from 4 options: `add`, `combine`, `finish bowl`, and `finish`.   
* Depending on the chosen option, the effect on the `bowl` varies.

### add  
```python  
try:  
   flavor = int(flavor)  
   if self.used[flavor] < 5:  
       self.bowls[bowl] += self.flavor_map[flavor]  
       self.used[flavor] += 1  
       self.recipe += [[flavor, bowl]]  
   else:  
       print(f"\nCannot order {flavor} due to stock issues.")  
except:  
   print("\nInvalid Flavor")  
```  
* We can add any of the 6 flavors to any of the 3 bowls.  
* Adding a flavor means adding a value from the flavor_map dictionary. That's how we can leak values from the flavor list (random numbers generated from the LCG).   
* But we cannot use a flavor more than 4 times.

### combine_bowl  
```python  
a = int(a) - 1  
b = int(b) - 1  
if op == 'add':  
   self.bowls[a] += self.bowls[b]  
elif op == 'sub':  
   self.bowls[a] -= self.bowls[b]  
elif op == 'mult':  
   self.bowls[a] *= self.bowls[b]  
elif op == 'div':  
   assert self.bowls[b] != 0, "Empty Bowl for Division"  
   self.bowls[a] *= pow(self.bowls[b], -1, self.p)  
else:  
   print("\nwtf")  
   exit(1)  
self.recipe += [[op, a, b]]  
self.bowls[b] = 0  
```  
* We can perform `addition`, `subtraction`, `multiplication`, or `division` operation between 2 bowls.  
* The catch is that after an operation is done, the 2nd bowl is set to 0.

### finish_bowl  
```python  
unique = 0  
for i, n in self.used.items():  
   if n and n != 1337:  
       unique += 1  
if unique < min(3, len(self.used)):  
   print("\nAdd more flavor!")  
   return False  
recipe = str(self.recipe).replace(' ', '')  
signature = sum(self.bowls) % self.p  
self.bowls = [0, 0, 0]  
self.recipe = []  
for i in self.used:  
   if self.used[i]:  
       self.used[i] = 1337  
print(f"\nUser #: {self.p}")  
print(f"\nRecipe: \n{recipe}")  
print(f"\n\nSignature: \n{signature}")  
return True  
```  
* Prints `p` which is the modulus of the LCG.  
* Prints recipe, although it has no use.  
* Prints signature. Here signature denotes the sum of 3 bowls.  
* The unique variable ensures we use 3 different flavors that we haven't used before.  
* Once a flavor is used, its use count is set to 1337, so that if we use it again, it won't contribute to uniqueness.

### verify  
```python  
bowls = [0, 0, 0]  
for i in recipe:  
   try:  
       if len(i) == 2:  
           bowls[i[1]] += self.private[i[0]]  
       elif len(i) == 3:  
           if i[0] == 'add':  
               bowls[i[1]] += bowls[i[2]]  
           elif i[0] == 'sub':  
               bowls[i[1]] -= bowls[i[2]]  
           elif i[0] == 'mult':  
               bowls[i[1]] *= bowls[i[2]]  
           elif i[0] == 'div':  
               bowls[i[1]] *= pow(bowls[i[2]], -1, self.p)  
           bowls[i[2]] = 0  
       bowls = [i % self.p for i in bowls]  
   except:  
       exit("\nInvalid Recipe")  
try:  
   assert sum(bowls) % self.p == signature, "\nInvalid Signature"  
   print("\nYou have successfully redeemed your lce cream!")  
   if signature == self.private[1337]:  
       print(flag)  
except Exception as e:  
   print(e)  
```  
* Out given recipe is simulated and stored in the bowls.  
* After the simulation is complete, if the 3 bowls sum to `private[1337]`, we get the flag.  
That means we have to somehow recover the `flavors` list. Only then we can
know what value `private[1337]` contains since `flavors[1337] =
private[1337]`.

## My initial incorrect approach

* `Add` a flavor to a bowl.  
* Print the value on that bowl using `finish bowl`.  
* Repeat the above 2 steps to leak all 6 flavors.  
* Then use those values to crack the LCG.

But the problem with this idea is that we have to use at least 3 flavors to
use `finish bowl`. If we do that, we will get a sum of 3 flavors. This does
not contribute much to leaking the random values.

## Correct approach

We will leak the `p`, `a`, and `c` step-by-step. Let flavor_map = $[X_1, X_2,
X_3, X_4, X_5, X_6]$.

The initial state of the bowls $[b_1, b_2, b_3]$ is:  
$$\underbrace{0} \ \ \underbrace{0}  \ \ \underbrace{0} $$

### Recovering `a`  
* move $X_2$ to $b_1$   
$$\underbrace{X_2} \ \ \underbrace{0} \ \ \underbrace{0} $$  
* move $X_3$ to $b_2$  
$$\underbrace{X_2} \ \ \underbrace{X_3} \ \ \underbrace{0} $$  
* subtract $b_2$ from $b_1$  
$$\underbrace{X_2 - X_3} \ \ \underbrace{0} \ \ \underbrace{0} $$  
* move $X_1$ to $b_2$  
$$\underbrace{X_2 - X_3} \ \ \underbrace{X_1} \ \ \underbrace{0} $$  
* move $X_2$ to $b_3$  
$$\underbrace{X_2 - X_3} \ \ \underbrace{X_1} \ \ \underbrace{X_2} $$  
* subtract $b_3$ from $b_2$  
$$\underbrace{X_2 - X_3} \ \ \underbrace{X_1 - X_2} \ \ \underbrace{0} $$  
* divide $b_1$ by $b_2$  
$$\underbrace{\frac{X_2 - X_3}{X_1 - X_2} \mod\ p} \ \ \underbrace{0} \ \
\underbrace{0} $$

Bowl 1 now contains the value of `a`. Since we have used 3 flavors, this is
unique enough to use `finish bowl`. The signature will be the value of `a`.

### Recovering `c`  
Since we have already used $X_1, X_2, X_3$, using them again won't contribute
anything to uniqueness. So we are going to use $X_4, X_5, X_6$ instead to
recover `c`.  
* move $X_5$ to $b_1$   
$$\underbrace{X_5} \ \ \underbrace{0} \ \ \underbrace{0} $$  
* move $X_6$ to $b_2$  
$$\underbrace{X_5} \ \ \underbrace{X_6} \ \ \underbrace{0} $$  
* subtract $b_2$ from $b_1$  
$$\underbrace{X_5 - X_6} \ \ \underbrace{0} \ \ \underbrace{0} $$  
* move $X_4$ to $b_2$  
$$\underbrace{X_5 - X_6} \ \ \underbrace{X_4} \ \ \underbrace{0} $$  
* move $X_5$ to $b_3$  
$$\underbrace{X_5 - X_6} \ \ \underbrace{X_4} \ \ \underbrace{X_5} $$  
* subtract $b_3$ from $b_2$  
$$\underbrace{X_5 - X_6} \ \ \underbrace{X_4 - X_5} \ \ \underbrace{0} $$  
* divide $b_1$ by $b_2$  
$$\underbrace{\frac{X_5 - X_6}{X_4 - X_5} \mod\ p} \ \ \underbrace{0} \ \
\underbrace{0} $$  
$$\underbrace{a} \ \ \underbrace{0} \ \ \underbrace{0}$$  
* move $X_4$ to $b_2$  
$$\underbrace{a} \ \ \underbrace{X_4} \ \ \underbrace{0}$$  
* multiply $b_2$ with $b_1$  
$$\underbrace{0} \ \ \underbrace{aX_4} \ \ \underbrace{0}$$  
* move $X_5$ to $b_1$  
$$\underbrace{X_5} \ \ \underbrace{aX_4} \ \ \underbrace{0}$$  
* subtract $b_2$ from $b_1$  
$$\underbrace{X_5 - aX_4} \ \ \underbrace{0} \ \ \underbrace{0}$$

So bowl 1 now has `c`. Using `finish bowl` will give `c` as the signature.

### Recovering the `flavors` list  
We can simulate the generation process to get the required sign and the
`flavors` list.  
```python  
lcg = LCG(a, c, p)

for i in range(1337):  
   lcg.gen_next()

flavors = [lcg.gen_next() for i in range(1338)]  
sign = flavors[1337]  
```

## Retrieving the flag

Since we have recovered the target signature, we send it to the verify
function using `Option 3`. As a recipe, we send `[[1337,0]]`. Then after the
simulation is done in the verify function, the state of the 3 bowls will be:  
$$\underbrace{private[1337]} \ \ \underbrace{0} \ \ \underbrace{0}$$  
The sum of the 3 bowls will hence be, `private[1337]` which is what we need to
recover the flag.

> Flag: **amateursCTF{bruh_why_would_you_use_lcg_for_signature}**

What a beautiful problem, innit?

### Solution script  
```python  
from pwn import *

class LCG:  
   def __init__(self, a, c, p):  
       self.a, self.c, self.p = a, c, p  
  
   seed = 1337

   def gen_next(self):  
       self.seed = (self.a*self.seed + self.c) % self.p  
       return self.seed

io = remote('amt.rs', 31310)

def add(a, b):  
   io.recvuntil(b'finish?')  
   io.sendline(b'add')  
   io.recvuntil(b'bowl: ')  
   to_send = ' '.join([str(i) for i in [a, b]])  
   io.sendline(to_send.encode())

def combine_bowl(a, b, op):  
   io.recvuntil(b'finish?')  
   io.sendline(b'combine')  
   io.recvuntil(b'operation: ')  
   to_send = ' '.join([str(i) for i in [a, b, op]])  
   io.sendline(to_send.encode())

def finish_bowl():  
   io.recvuntil(b'finish?')  
   io.sendline(b'finish bowl')  
   io.recvline()  
   p = int(io.recvline().decode().strip().split(': ')[1])  
   io.recvuntil(b'Signature:')  
   io.recvline()  
   sign = int(io.recvline().decode().strip())  
   return p, sign

def finish():  
   io.recvuntil(b'finish?')  
   io.sendline(b'finish')  
   io.recvuntil(b'OPTIONS:')  

io.recvuntil(b'Choice: ')  
io.sendline(b'1')

#recover a, p  
add('2', '1')  
add('3', '2')  
combine_bowl('1', '2', 'sub')  
add('1', '2')  
add('2', '3')  
combine_bowl('2', '3', 'sub')  
combine_bowl('1', '2', 'div')  
p, a = finish_bowl()

print(a, p)

#recover c, p  
add('5', '1')  
add('6', '2')  
combine_bowl('1', '2', 'sub')  
add('4', '2')  
add('5', '3')  
combine_bowl('2', '3', 'sub')  
combine_bowl('1', '2', 'div')  
add('4', '2')  
combine_bowl('2', '1', 'mult')  
add('5', '1')  
combine_bowl('1', '2', 'sub')  
p, c = finish_bowl()  
print(c, p)

finish()

lcg = LCG(a, c, p)

for i in range(1337):  
   lcg.gen_next()

flavors = [lcg.gen_next() for i in range(1338)]  
sign = flavors[1337]

io.recvuntil(b'Choice: ')  
io.sendline(b'3')

io.recvuntil(b'NUMBER: ')  
io.sendline(str(p).encode())

io.recvuntil(b'RECIPE: ')  
io.sendline(b'[[1337,0]]')  
io.recvuntil(b'SIGNATURE: ')  
io.sendline(str(sign).encode())

io.interactive()  
# amateursCTF{bruh_why_would_you_use_lcg_for_signature}

'''  
Algortihm to recover a:  
-------------------------

(x2-x3)/(x1-x2)

1) mov x2 to b1  
2) mov x3 to b2  
3) b1 - b2  
4) mov x1 to b2  
5) mov x2 to b3  
6) b2 - b3  
7) b1 / b2

Algorithm to recover b:  
------------------------

x5 - x4 * a

x5 - x4 * (x5 - x6)/(x4 - x5)

1) mov x5 to b1  
2) mov x6 to b2  
3) b1 - b2  
4) mov x4 to b2  
5) mov x5 to b3  
6) b2 - b3  
7) b1 / b2  
8) mov x4 to b2  
9) b2 * b1  
10) mov x5 to b1  
11) b1 - b2

'''  
```

Original writeup (https://tsumiiiiiiii.github.io/icecream_generator/).