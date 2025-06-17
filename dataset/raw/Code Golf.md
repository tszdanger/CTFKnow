# Code Golf  
## Google CTF 2019

## Index  
* [Acknowledgements](#Acknowledgements)  
* [The problem](#The-problem)  
 * [Problem statement](#Problem-statement)  
 * [Some background](#Some-background)  
 * [Lessons](#Lessons)  
* [The solution](#The-solution)  
 * [A first pass](#A-first-pass)  
 * [The first correct code](#The-first-correct-code)  
 * [More compact code](#More-compact-code)  
 * [The first accepted code](#The-first-accepted-code)  
* [Golfing transformations](#Golf-you-a-Haskell)  
* [NP-Completeness](#NP-Completeness)

## Acknowledgements

This writeup is done by Cole Kurashige.

I'd like to thank Kye Shi for his help designing a faster algorithm,  
and Giselle Serate for algorithm verification and actually running the code.
Also for  
showing me the CTF.

# The problem

As a foreward/warning, this is a lengthy writeup. If you want the TL;DR
highlights ,  
first read the [problem statement](#Problem-statement) if you aren't familiar
with the problem.  
I think the most interesting highlights are the  
[golfing tips](#Golf-you-a-Haskell), specifically [this one](#Finding-the-
possible-shifts), and  
the [NP-Completeness proof](#NP-Completeness).

Or just skim the titles and skim/read what is interesting. A lot of the length
comes from headers,  
newlines, and code blocks - as far as text goes I've tried to edit things so
they're to-the-point.

## Problem statement  
The problem could be found
[here](https://capturetheflag.withgoogle.com/#challenges/)  
as of 6/27/19. In case it gets moved or taken down, I've described it below.

Given a list of strings with gaps in them (denoted by a space), you're asked
to combine them into  
a single string. Imagine all of the strings stacked on top of each other. You
want to shift the strings  
to the so that only one or zero characters are in each position. You also want
to minimize the  
length of the resulting string (ignoring trailing and leading gaps). The tie-
breaker for multiple  
solutions is lexicographic length. Your solution is a function `g :: [String]
-> String`.

An example given is the strings `"ha  m"` and `"ck e"`:

If you overlay them:

   "ha  m"  
   "ck e"

Shift them by an appropriate offset:

   "ha  m"  
     "ck e"

You get the resulting string `"hackme"`.

The catch to all of this is that it must be done in Haskell in 181 bytes or
fewer.

Oh, also, it is [NP-Complete](#NP-Completeness).

## Some background

I spent a _long_ time on this problem. Its theme for me was  
"comfort's a killer." I really like Haskell, and have been using it recently.  
I really like code golf, and have golfed code in the past.  
I probably should've spent more time thinking through an algorithm, but I dove
in  
headfirst. I knew there was a tips for golfing in Haskell on the code golf
stack exchange, but I neglected to use it.

And so, I spent an entire weekend on one problem. Welcome to my hell.

## Lessons

I learned three important lessons from this endeavor.

### Lesson #1

Code golf skills don't just magically manifest themselves in another language.

I primarily code golf in [J](https://www.jsoftware.com/indexno.html) and  
[><>](https://esolangs.org/wiki/Fish). Haskell is neither of these. I used
pretty  
much none of my existing code golf knowledge in golfing this challenge.

### Lesson #2

Imports are useful.

I should've used more imported functions, especially those from `Data.List`
more.  
Our final solution used only two imports: `join` from `Control.Monad` and  
`(\\)` from `Data.List`.  
It can probably be reduced to just using `Prelude`, while still mantaining an
acceptable  
bytecount.

### Lesson #3

Think before you write code.

My first algorithm was far from perfect, and even had a flaw in its logic.
When  
this was fixed and it was golfed, we learned much to my chagrin that it used
too  
much memory and was silently failing. Soooooo ... we had to come up with a new
one  
from scratch. And then golf it again. Did I mention that I spent a lot of time  
on this problem?

# The solution

## A first pass

The first thing I did was write a half-golfed program.

The algorithm was essentially to find every possible way to shift each of the
strings  
and overlay them. Some of these shifts would be invalid, so I discarded those.

I ignored the possibility of strings having trailing spaces, since that would  
just be cruel. Later solutions also ignored the possibility of strings having
leading  
spaces. This turend out to be an OK assumption to make (though I wish it were
told  
to us in the prompt).

There is a mistake in this code: I am only taking the lexicographically
minimal  
solution, not the minimal length solution. This is fixed in the golfed
version,  
at the cost of many bytes.

```haskell  
import Data.List  
import Data.Maybe  
import Control.Monad

-- | the solution function  
g :: [String] -> String  
g xs = minimum . catMaybes $ [sequence . dropWhile (==Nothing)  
                            . map collapseW . transpose $ s | s <- shifts l xs]  
 where  
   l = sum $ map length xs

-- | find all possible ways to shift a string 's' with at most 'l'  
-- characters of padding.  
wordShifts :: Int -> String -> [String]  
wordShifts l s = [space <> s | space <- spaces]  
 where  
   spaces = inits $ replicate l ' '

-- | find every possible way to shift a list of strings, where  
-- each string can be shifted at most 'l' characters to the left  
shifts :: Int -> [String] -> [[String]]  
shifts l [] = [[]]  
shifts l (w:ws) = do  
 shifted <- wordShifts l w  
 rest <- shifts l ws  
 return $ shifted : rest

-- | try to collapse a string into a single character (think of this as
reducing  
-- a column to 1 character, this fails if there are more than 2 non-space
characters  
-- or no non-space characters)  
collapseW :: String -> Maybe Char  
collapseW s = do  
 [y] <- foldMap convert s  
 pure y  
 where  
   convert ' ' = Nothing  
   convert c   = Just [c]  
```

I golfed this down to 178 bytes.

```haskell  
f=foldMap  
h ' '=[]  
h c=[c]  
k l s=[f<>s|f<-inits l]  
z l[]=[[]]  
z l(x:y)=[a:b|a<-k l x,b<-z l y]  
g x=minimum[concat y|s<-transpose<$>z(f(>>" ")x)x,let y=f
h<$>s,all((<=1).length)y]  
```

## The first correct code

At precisely 181 bytes, this was the first code that picked the correct
solution,  
sorting the possible ones by length, then lexicographically.

```haskell  
h=length  
f[]=" "  
f l=l  
z l[]=[[]]  
z l(x:y)=[a:b|a<-[i<>x|i<-inits l],b<-z l y]  
g x=snd$minimum[(h a,a)|s<-z((>>" ")=<<x)x,let y=concat.words<$>transpose
s,all((<=1).h)y,let a=f=<<y]

```

The problem now is that the code was failing silently! Usually the server
would tell  
you if you had an error (compilation, runtime, byte length), but it didn't
respond and  
instead failed after about 25-30 seconds.

We tested with code that ran infinitely, which would get cut off at exactly 1
minute,  
so with some more testing we concluded that the code was using too much memory
and  
getting killed.

(we tested the memory usage with `foldl (+) 0 [1..]`, which timed out after 20
or so  
seconds, and confirmed it was a problem with memory that caused silent failure  
with `foldl' (+) 0 [1..]`, which only timed out after a minute. Ahhh Haskell,
where one  
character makes a huge difference)

## More compact code

I further golfed the first correct solution to 151 bytes.  
I don't remember why I did this.  
It was golfed during the phase where we were trying to figure out why the
server  
wouldn't accept our solution. Maybe I was trying to fit space stripping into
the  
code, but didn't get around to it.

I added some spaces to the last function `g` so it doesn't wrap so hard, but
they  
aren't part of the bytecount.

```haskell  
h=length  
f""=" "  
f l=l  
g x=snd$minimum[(h a,a)|s<-forM[(>>" ")=<<x|_<-x]inits,  
 let y=concat.words<$>transpose(zipWith(<>)s x),all((<=1).h)y,let a=f=<<y]  
```

## The first accepted code

The first correct code took somewhere between 2 to 4 hours of effort to reach.  
By midday Saturday, I had something that was morally right, but didn't pass
the tests.  
That evening, Giselle and I tracked down the root of the problem to space
issues.

I complained to Kye about my solution not being good enough, despite being  
short enough, and he devised an algorithm that was better (at least memory-
wise) than  
my like `O(n^n)` space algorithm. This was maybe around midnight on Saturday
(which  
was 3 AM his time...).

He, however, did not golf it, so I still had to reduce his ~500 bytes to the
below.

I spent an hour or two golfing his solution after I woke up on Sunday  
and brought it down to exactly 181 bytes.

```haskell  
m(a:b)(x:y)=max a x:m b y  
m x y=x<>y  
f s[]=[s]  
f s r=join[f(m s x)$r\\[x]|x<-r,and$zipWith(\x y->x==' '||y==' ')s
x]<>[h:y|(h:t)<-[s],y<-f t r]  
g y=snd$minimum[(length x,x)|x<-f""y]  
```

Yup, this code is _a lot_ different. It ended up being a lot more inefficient
than  
his original code, too, since I cut out all of his optimizations when I golfed
it.

Kye ended up writing an even _more_ efficient version, which thankfully I
didn't need  
to golf.

I just wish that we knew earlier that the "make it snappy" flavortext didn't  
mean to make the code short, but instead meant "efficient enough." I'm used to
seeing  
time/space restrictions given upfront on the Code Golf Stack Exchange, where
there  
can be answers that are right by observation but too inefficient to run
anything but  
the simplest of test cases.

# Golf you a Haskell  
Here were some of the more inventive or useful golfing transformations I used.
Since  
I foolishly neglected to use any resources other than the documentation,  
these were all found by myself.

## Infix your code!  
Haskell has a lot of infix operators (operators like `+` or `-` that go
between  
their arguments). It's made fun of in this  
[article](http://uncyclopedia.wikia.com/wiki/Haskell)  
(warning: somewhat NSFW language), which includes the following code that
produces  
[an infinite list of powers of
2](https://stackoverflow.com/questions/12659951/how-does-this-piece-of-
obfuscated-haskell-code-work/12660526#12660526).

```haskell  
import Data.Function (fix)  
-- [1, 2, 4, 8, 16, ..]  
fix$(<$>)<$>(:)<*>((<$>((:[])<$>))(=<<)<$>(*)<$>(*2))$1  
```

The next few points are on how you can use these operators.

### `$`  
A simple transformation that I often use in code read by people other than
myself  
is `$`. `$` is a function that just applies its left argument to its right
argument.

```haskell  
f $ x = f x  
```

It has really low priority, though, so it can save you parentheses like in

```haskell  
-- these are the same  
gcd (1+2)  (3*4)  
gcd (1+2) $ 3*4  
```

### `map`  
`<$>` and `map` are the same for lists, but the former has lower priority,
which lets  
you reap some of the benefits of `$`, while also not needing a space between
its  
arguments (unlike `map`).

### `concatMap`  
I found myself often using `concatMap`. I first reduced this to `foldMap`,  
and then to the infix `=<<`. All of these have the same definition for lists.

### `return`  
I used `return` to convert an element `x` to a singleton list.  
This becaume `pure` and then finally `[x]` once I realized I was being a
moron.

## Filling holes  
A tricky part of this problem was combining two strings with holes (spaces) in
them  
to produce one where the holes were filled. As it turns out, the only
printable ASCII  
less than space (ASCII 32) is whitespace, so I figured these wouldn't show up
in the  
strings. Thus, given two chars in the same column, we can take their maximum
to find  
the non-space char (if it exists).

## Cheeky pattern matching  
I had code that I wanted to give a list if `x` pattern matched one thing and
the empty  
list if it did not. Something that looked like

```haskell  
case x of  
 (h:t) -> foo h t  
 [] -> []  
```

I converted this to

```haskell  
[foo h t|(h:t)<-[x]]  
```

This abuses the fact that when the pattern match `(h:t)` fails in the context
of a  
list comprehension, an empty list is returned instead of an error. This is a
special  
case of how pattern matching is desugared inside of a `do` block.

N.B. `foo` has a different type between these examples.

## Finding the possible shifts  
Given `strings :: [String]`, I wanted to find all of the ways these strings
could be  
shifted. I eventually boiled this down to finding `paddings ::[[String]]`,
where each  
`padding :: [String]` in the list was the same length as `strings` and had a
varied  
number of spaces in each element. So each `padding`, when combined element-
wise with  
`strings` would give a different shift.

A way of doing this would be

```haskell  
import Data.List (inits)

cartesianProduct :: [[a]] -> [[a]]  
cartesianProduct []       = [[]]  
cartesianProduct (xs:xss) = [x : ys | x <- xs, ys <- cartesianProduct xss]

paddings :: [String] -> [[String]]  
paddings strings = cartesianProduct $ replicate (inits maxPadding) (length
strings)  
 where  
   maxPadding = replicate (sum $ map length strings) ' '  
```

Let's take a look at

```haskell  
maxPadding strings = replicate (sum $ map length strings) ' '  
```

In order to make sure that I was shifting enough, I found a maximum padding
that  
was equal to the sum of the lengths of the strings.

We can reframe this as converting each element in `strings` to a string that
is the same  
length but only consisting of spaces, then concatenating all of these elements
together.

```haskell  
maxPadding strings = concatMap (\str -> replicate (length str) ' ') strings  
```

`replicate . length` is way too long, so let's replace it with `(>> " ")`.

```haskell  
maxPadding strings = concatMap (\str -> str >> " ") strings  
```

Eta reduce and obfuscate `concatMap` to give

```haskell  
maxPadding strings = (>> " ") =<< strings  
```

Much better.

This is only the max padding for a single element though. I wanted to find
`paddings`.  
`inits :: [a] -> [[a]]` will get us part of the way there, since it will give
all  
possible prepended spaces, from 0 to `maxPadding`.

```haskell  
inits [1,2,3] = [[],[1],[1,2],[1,2,3]]  
inits (maxPadding ["a","bc","d"]) = ["", " ", "  ", "   ", "    "]  
```

We then want the cartesian product of `inits maxPadding` repeated `length
strings`  
times. `cartesianProduct` is a long definition, so why don't we  
use the list Monad some more?

```haskell  
paddings strings = sequence (replicate (inits maxPadding) (length strings))  
```

`sequence` is the same as `\x -> forM x id` or `\x -> mapM id x`, so we can
convert to

```haskell  
paddings strings = forM (replicate (inits maxPadding) (length strings)) id  
```

We want to be applying `inits` to every element anyway, so we can pull it out.

```haskell  
paddings strings = forM (replicate maxPadding (length strings)) inits  
```

Then get rid of this `replicate` nonsense by using a list comprehension that
ignores  
all of the values of `strings`.

```haskell  
paddings strings = forM [maxPadding | _ <- strings ] inits  
```

Substitute the definition of `maxPadding` and we're done.

```haskell  
paddings strings = forM[ (>> " ") =<< strings | _ <- strings] inits  
```

354 bytes of (reasonably) readable code down to 67 bytes of nonalphanumeric
soup.

Don't you love code golfing?

# NP Completeness

On Saturday evening, I was banging my head against a wall trying to optimize
the  
space and time complexity of my algorithm. But every time I tried to think
through  
a faster algorithm, something felt wrong. I had a feeling that the problem was  
[NP Complete](https://en.wikipedia.org/wiki/NP-complete), and so the only
thing I could  
get optimal would be space. I eventually sat down and proved it NP-Complete.

## Proof  
The proof is by reduction from the  
[Bin Packing Problem](https://en.wikipedia.org/wiki/Bin_packing_problem)
(BPP). This is  
a pretty rigorous proof, but I tried to make it understandable. I think the  
[Reduction, visualized](#Reduction-visualized)  
section does a pretty good job of building intuition for how the proof works,
but if you  
haven't seen a reduction before this all might seem kind of obtuse.

### Bin Packing Problem (decision version)  
The BPP asks, given `m` bins of size `V` and a set `S` of elements with an
associated  
cost function `f : S -> N` (where `N` is the natural numbers), can `S` be
partitioned  
into at most `m` subsets, each of whose total cost is less than or equal to
`V`? In  
plain English, given `m` bins, each with capacity `V`, can we fill each bin to
at  
most capacity with all of the elements in `S`?

### Crypto Problem (decision version)  
First, I will state the decision variant of the Crypto Problem (CP). Given a
"set" `T`  
of strings that have holes in them represented by spaces and a target length
`l`, the  
Crypto Problem asks whether all elements of `T` can be overlaid such that
there is at  
most one non-hole per column and the length of the overall result (after
removing  
trailing and leading spaces) is `l` or less.

(this "set" may have duplicates - I don't want to be as rigorous as in the
BPP)

### Reduction  
We can construct a CP from an arbitrary BPP as follows.

We first will construct the  
set `T`. Create `m` strings, each of length `3V + 2`. The first and last `V+1`  
characters of these strings are `#`, and the rest (the center) are spaces
(holes).  
Character choice doesn't matter here, so I pick an arbitrary one.  
These strings will represent our bins, and I will refer to them as "bin
strings".

For each element `s` in the set `S` from the BPP, we want to make an analagous
element  
for the CP. This element will be `f(s)` long, and consist only of the
character `*`.  
Again, character choice doesn't matter here. I'll refer to these as "`*`
strings".

Now, we pick a length `l`. This CP will have a maximum length of `(3V + 2) *
m`.

This reduction clearly takes polynomial time as it involves iterating as many
times  
as there elements of `S` and bins.

We claim that the given BPP is solvable if and only if this constructed CP is
solvable.

### Reduction, visualized

Let's consider a BPP with `V = 3`, `m = 3`, and elements of size `1`, `1`,
`2`, and `2`.

The bins:  
```  
# #  # #  # #  
# #  # #  # #  
# #  # #  # #  
###  ###  ###  
```

The elements:  
```  
*  *  *  *  
     *  *  
```

A valid placement of these is putting a `1` in its own bin, a `2` in its own
bin, and  
a `1` and `2` in the last bin. Another valid placement would be to  
fill two bins entirely and leave one empty.

```  
# #  # #  #*#  
# #  #*#  #*#  
#*#  #*#  #*#  
###  ###  ###  
```

The equivalent problem in CP is the following strings:

```  
####   #### (x3)  
* (x2)  
** (x2)  
```

And an equivalent solution is the following:

```  
####   ####  
   *        
          ####   ####  
              **  
                     ####   ####  
                         ***  
```

which, when flattened looks like

```  
####*  ########** ########***####  
```

Note how the length is `(3V + 2) * m` = 33.

### Reduction proof (forward direction)

Given a solution to the BPP, we can make a solution to the CP. Suppose in the
BPP  
solution that some arbitrary bin `B` was filled to a volume `V' <= V` using
the  
elements in the set `S'`. This implies that

```  
sum(f(s') for s' in S') = V' <= V  
```

Since we created a bijection from elements of `S` in the BPP to elements of
`T` in the  
CP, find the corresponding elements from `S'` and put them in the set `T'`. We
claim  
that the elements of the set `T'` can be made to fit into a single bin string.

Why is this? Well, the sum of the lengths of these strings is less than `V`,
which is  
the amount of space in the middle of each "bin" string. Therefore, we can just  
concatenate all of these strings together and place them in the center of the
bin  
string.

Since we can do this for an arbitrary bin, and there is a bijection from `S`
to `T`,  
i.e. all bins in the solution of the BPP span all of `S`, we can fit all of
the elements  
in `T` corresponding to elements in `S` inside of the "bin" strings. This
means that  
there exists a solution where we place all of the `*` strings inside of the
bin  
strings. Therefore, the overall length of this solution is just the length of
all the  
bin strings combined, which is `(3V + 2) * m` as desired.

### Reduction proof (backwards direction)

We'll prove the contrapositve of the backwards direction. If there doesn't
exist  
a solution to the BPP, we cannot make a solution to the CP.

First, it should be reasonably obvious from the previous direction that the
strategy  
of placing the `*` strings in the bin strings won't work, since the BPP is
unsolvable.  
If we could place them in the bins, then that would imply that the BPP was
solvable,  
which contradicts the premise.

So we would have to find a solution to the CP that doesn't involve _just_
putting the  
`*` strings inside of the bin strings. Since our target length is `(3V + 2) *
m`, we  
need to fill all of the holes in the bins. If we aren't _just_ putting `*`
strings  
inside of bin strings, this means we would have to have bin strings intersect.
This is  
impossible, as on either end of the `V` holes in the center there are `V + 1`
holes  
on the side.

Visually, for `V` = 3, we get alignments that look like this.

```  
top bin    | ####   ####  | ####   ####   | ####   ####    | ####   ####     | ...  
bottom bin |  ####   #### |   ####   #### |    ####   #### |     ####   #### | ...  
```

The bins all have to intersect in _some_ column, which is not allowed in an
answer.

Therefore, it is impossible to have a solution to the CP.

### Conclusion

Since we showed a reduction existed from the BPP to the CP that took
polynomial time,  
and that the constructed CP was solvable if and only if the corresponding BPP
was,  
we conclude that the Crypto Problem is NP-Complete.

Original writeup
(https://github.com/doublestandardctf/GoogleCTF2019/blob/master/Code-Golf.md).