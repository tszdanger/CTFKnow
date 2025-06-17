# LessEQualmore

   Sometime, less ~instruction~ equal more ~instruction~ ...  
  
LessEQualmore is a [subleq](https://esolangs.org/wiki/Subleq) virtual machine
running a challenge program.  
The provided program asks for a flag and verifies it.

## Solution

When run the program repeats the input back to you and then verifies it (which
hints at the buffer overflow for the SUBformore pwn challenge).

```  
*** Flag Checker ***  
hitcon{flag}  
You entered:  
hitcon{flag}  
Sorry, wrong flag!  
```

The problem is that the challenge program contains 44197 tokens, has different
alignments in different positions and as subleq programs are is heavily self-
modifying.  
This means that fully understanding the challenge program is a very tedious
task as we need to explore traces and the possible paths the program might
take depending on input.

These types of challenges are possible to solve way faster assuming they
following some common properties / are not hardened:

- There is either no length check or it is early on so we can bruteforce or spot it fast  
- Processed Input is meant to be equal to something (unique flag) which is decided with a branch  
- A trace where part of the flag is correct is very different from a trace that is completely wrong

In practice this means that if the program compares the input in some way and
directly decides if it is correct or not from that, we can focus on finding
these comparisons and derive the correct input from there.

So how do we find these comparisons?

Given that every subleq instruction can be seen as a branch we first to ignore
everything obviously is not a jump (meaning the next address is the same as
the branch address).  
We also only want to focus on branches that depend on the input values, and
filter out everything that always takes the same path for printable input
characters.

We can do this by rewriting the subleq VM and making the input symbolic
variables.  
Through this we can do taint analysis and figure out what the comparisons are
actually doing.  
We can also use a solver to verify whether for any possible input a branch can
be taken or not.  
The nature of subleq leads itself to reusing specific memory regions a lot, so
after a memory cell is zero'd we should also make it concrete / non-symbolic
again as this is important for performance and helps with figuring out better
candidates.

When you do this you will find a lot of possible candidates and it will take
quite a long time to compute.  
To further restrict the space we can also try the assumption (which may not be
true but we can easily test) that the comparison of characters is not just
with each other but contains some constant.

See the [explore.py](explore.py) script for an implementation of this search.

I recommend trying this with a small amount of input characters first (e.g. 8,
which you can see is the block size of comparisons):

```  
PC[ 3314 ]: ( 0 1 3320 ) : 3016 +  
18446744073709551609*input[0] +  
18446744073709551612*input[3] +  
18446744073709551603*input[5] +  
18446744073709551614*input[6] +  
18446744073709551609*input[7] +  
18446744073709551614*input[1] +  
3*input[2] +  
4*input[4] # Possible Solution: b'y~ ~#1A~'  
```

`PC[ 3314 ]` is for completely wrong input (e.g. all A's) the only comparison
that is found.

Note that negative numbers are here shown as unsigned 64-bit numbers, so this
actually means:

```  
PC[ 3314 ]: ( 0 1 3320 ) : 3016 +  
-7*input[0] +  
-4*input[3] +  
-13*input[5] +  
-2*input[6] +  
-7*input[7] +  
-2*input[1] +  
3*input[2] +  
4*input[4] # Possible Solution: b'y~ ~#1A~'  
```

If we now try this as input and explore again:

```  
PC[ 3314 ]: ( 0 1 3320 ) : 3016 +  
18446744073709551609*input[0] +  
18446744073709551612*input[3] +  
18446744073709551603*input[5] +  
18446744073709551614*input[6] +  
18446744073709551609*input[7] +  
18446744073709551614*input[1] +  
3*input[2] +  
4*input[4] # Possible Solution: b'T231Cy8|'

PC[ 3320 ]: ( 1 0 3386 ) : 18446744073709548600 +  
7*input[0] +  
4*input[3] +  
13*input[5] +  
2*input[6] +  
7*input[7] +  
2*input[1] +  
18446744073709551613*input[2] +  
18446744073709551612*input[4] # Possible Solution: b'"*Os%uzz'

PC[ 3314 ]: ( 0 1 3320 ) : 18446744073709550205 +  
5*input[3] +  
18446744073709551606*input[5] +  
11*input[6] +  
18446744073709551613*input[7] +  
6*input[4] +  
3*input[1] +  
2*input[2] +  
18446744073709551614*input[0] # Possible Solution: b'l0

Original writeup
(https://github.com/Pusty/writeups/tree/master/HITCONCTF2023#lessequalmore).