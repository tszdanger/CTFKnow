*For the full experience including images see the original blog post!* 

# Author writeup

## WARNING

If you want to solve the challenge yourself but need a few hints I included [a
file with such help]("/src/lib/assets/2023/02-10_kitctfctf-22-slots/HINTS.md")
for you.  
Also note that I included a fixed version of the binary in case you want to
solve the challenge the way it was initially intended.  
While the binary we deployed was perfectly solvable (with the same key) it
includes two small errors:

- One line of debug output wasn't commented out in the local version (might even help you)  
- I made a mistake integrating a method which renders three checks completely useless and forces you to do more bruteforcing than intended. Big sorry for that!

That things said, let's start with the interesting parts!

## Solution

First of, let's do some basic examinations of the challenge binary with `file`
and `strings`:

From that we can already determine that we are dealing with a stripped C++
binary.  
Additionally, we can assume that we need to find a debug key and that the
binary reads and prints the flag in some special case.

Now, I won't show exactly how to reverse each method since that does not make
much sense as the author.  
I will however show you the important functions and give some hints as to how
you might understand them (using ghidra as an example, as I only use that
decompiler currently).  
Additionally, I will give you some insights on my thought process.

In case your starting out reversing with ghidra, I can recommend
[stacksmashing](https://www.youtube.com/@stacksmashing) for an introduction
and tips and tricks, the docs of ghidra itself on their
[website](https://ghidra.re) or the [GitHub
repo](https://github.com/NationalSecurityAgency/ghidra) and forums for
specific problems.

Another note before we start: please use the provided setup for testing to
avoid problems because of different `rand` implementations!

### Backtracking from "flag.txt"

As always, we could locate the `main` function from the entry point.  
In this case however, we can also quickly localize a `print_flag`-method by
tracing the defined string "flag.txt".  
Going up one function from there, we find a method that is key to the program:
`print_result`.  
It contains the logic for deciding the result of the game.  
I improved the readability a bit here by generating a struct from the
parameter value and by changing some values to named booleans to get this
state:

As you can see we have some boolean in the struct that determines whether the
game is won and some value in the struct (weird getter functions there)
compared with a constant.  
Shortly diving into that comparison function you will find out that it is a
simple string compare.

Now, having found that constant we can trace its references.  
The first occurrece in the binary is an initialization function.  
In case you didn't guess this, note that the four bytes value is simply a
utf8-string:

The other occurrence gives us a bit more intel.  
It enters a branch if a `rand()`-value, actually the first one after
initialization, is a certain constant.  
Since the parameter is used as a pointer with offsets you can try out our
struct for readability:

This method initializes the struct, either randomly or as a flag win state,
for the game.  
I actually generated the final state here as that makes it way easier to
generate the animation states with a controllable outcome.

With that step we finished our backtracking and can try to bruteforce the
value we need to inject to `srand()` (here you will need some time using the
deployed version; the intended one terminates in way under a second as it has
a much smaller key space).

```cpp  
#include <chrono>  
#include <iostream>  
#include <random>

#define MAX_UINT32 4294967295

// the deployed version used the key I commented out  
// const int DEBUG_KEY = 1212832989;  
const int DEBUG_KEY = 292616681;

int main(int argc, char const *argv[])  
{  
   auto t0 = std::chrono::steady_clock::now();  
   for (unsigned int i = 0; i < MAX_UINT32; i++)  
   {  
       srand(i);  
       if (rand() == DEBUG_KEY)  
       {  
           printf("Key: %u\n", i);  
           break;  
       }  
   }  
   auto t1 = std::chrono::steady_clock::now();  
   auto d = (t1 - t0);  
   std::cout << d.count() << "ps\n";  
}  
```

You could now search for `srand()` directly or follow my tour by tracing the
user input.

### Tracing our input

In the `main`-function we can quickly localize our input from the `cin`-pipe.
It is directly used in some function that calls `srand()` (there we are,
already) to set the random seed.

There are three checks you need to pass to be able to set the seed.  
(In the deployed version you can simply ignore those checks, but hey...)  
Additionally, there is some function that converts a uint64 to a string.

The first check tries to find a string from an array of number strings in the
input and returns the remaining string and the position in the input.  
While it mainly uses library functions, ghidra requires some help with
function signatures (often the calling convention and parameters as in the
[docs](https://en.cppreference.com/w/)) and struct definitions to provide a
readable decompilation.

And, by the way, those numbers (you need to trace them to the initialization
function again) are the zipcodes of karlsruhe, since the slot machine was
produced there ?

The second check tests the leetness of the remainder number (checking the
occurrence of all three and the percentage of leet digits in the whole
number).  
You could actually ignore this check since you can reverse the random value to
get the remainder.

The last check ensures that you use the correct zipcode at the correct
position to get the final key.  
Again, it uses a lot of library functions but you have to adjust the
signatures and types to make it readable.

Sadly, the default output of other decompilers can be more readable than
ghidra's.  
Especially Hexrays provides strong defaults in many cases.  
That doesn't need to bother you though, since free tools like ghidra can be
just as strong with a bit of help.  
Again, simply adjusting function signatures and structs produces a perfectly
understandable result.

Now, we can deduce that the third check is actually just implemented as a
string comparison of `input == prefix + KA_PLZS[index] + suffix`  
where the suffix length is `length = (int(remainder) % 53816) %
(len(remainder) -1)`.

Finally, we have to examine one last hurdle: a simple brute force protection.  
We pass a 64-bit integer as input to `initialize_random`, but the checks and
`srand` operate on 32-bit integers.  
I called the conversion-method `custom_to_string` as it converts a 64-bit
integer to a 32-bit number string.  
Looking at its main loop it uses a repeated bitmask of `0b101001001000` where
the marked positions must be zero  
and the other bits are extracted for the actual value with bit-shifting.  
The minimum of `0xffff000000000000` ensures that this value is prefixed with
all ones.

After the CTF, `@lkron` mentioned on Discord that he didn't reverse the method
but used Z3 for solving it (I assume he meant this one).  
Since I couldn't find any writeups of the challenge online, I'll provide an
example implementation of such an approach too:

```py  
#!/ usr/bin/ python  
from z3 import *

def cryptic(input: int) -> int:  
   if input < 0xffff000000000000:  
       return -1

   result = 0  
   current = input  
   for i in range(4):  
       if (current & 0b0000101001001000) != 0:  
           return -1  
       bits = current & 0b00000111 | (current >> 1) & 0b00011000 | (  
           current >> 2) & 0b01100000 | (current >> 3) & 0b10000000  
       result = result | bits << ((i << 3) & 0b00011111)  
       current = current >> 0xc  
   return result

def symbolic(s: Solver, input: BitVec):  
   res = BitVec("res", 64)  
   s.add(input & 0xffff000000000000 == 0xffff000000000000)

   last = input  
   lastRes = BitVec("rIn", 64)  
   s.add(lastRes == 0b0)  
   for i in range(4):  
       s.add((last & 0b0000101001001000) == 0)

       bi = BitVec("b"+str(i), 64)  
       ri = BitVec("r"+str(i), 64)

       s.add(bi == last & 0b00000111 | (last >> 1) & 0b00011000 | (  
           last >> 2) & 0b01100000 | (last >> 3) & 0b10000000)

       s.add(ri == lastRes | bi << ((i << 3) & 0b00011111))  
       lastRes = ri

       lTmp = BitVec("l"+str(i), 64)  
       s.add(lTmp == last >> 0xc)  
       last = lTmp  
   s.add(res == lastRes)  
   return res

print(cryptic(18446490111005696309))

x = BitVec('x', 64)  
s = Solver()

res = symbolic(s, x)  
s.add(res == 1761313373)

if s.check() == z3.sat:  
   print(s.model()[x].as_long())  
else:  
   print("Solver error!")

```

Now, I am no expert with Z3 and there will probably be easier solutions than
this one but it should still work as a valid example.

Finally, once you have the debug key, you can check it with the provided
setup.  
Apart from the described bugs and it using the real flag there are no
differences to the setup we used on our server.  
If you want to explore the code of the challenge I added the source file to
the downloads [up there](#author-writeup).  
Additionally, I added some comments to better explain its functionality and
point out the bugs.  

Original writeup (https://ik0ri4n.de/kitctfctf-22-slots).```  
$ nc web.angstromctf.com 3002  
Welcome to Fruit Slots!  
We've given you $10.00 on the house.  
Once you're a high roller, we'll give you a flag.  
You have $10.00.  
Enter your bet: NaN  
? : ? : ?  
? : ? : ? ◀  
? : ? : ?  
You lost everything.  
Wow, you're a high roller!  
A flag: actf{fruity}  
```