Taxes  
=====

> Active participants of DiceCTF 2022 are required to complete form DG1 "Flag
> Validation." Failure to do so may result in disqualification.  
>  
>    An official message of the DiceGang Revenue Service

In this challenge we're given a pool of forms as PDFs and asked to fill in one
of them (DG1).

In total we're given the following forms:

 * Form DG1: Flag Verification  
 * Form DG4-A: Xenial Obsidian Router  
 * Form DG4-B: Petal Robot Nemo Gladiator  
 * Form DG4-C: Circular Andromeda  
 * Form DG4-D: Visual Motion  
 * Form DG6: [redacted]  
 * Form DG7: [redacted]

Taking a look at DG1, we can see that the forms consist of a set of steps that
when completed would prove we have a valid flag; essentially, an imperative
program.

DG1 reveals the following:  
 * The flag body (between braces) is 64 characters long  
 * ...consisting of printable ASCII characters  
 * ...partitioned into four parts, each of which are 16 characters long  
 * Each part is given by the sub-forms BG4-{A,B,C,D}  
 * The SHA-256 hash of each of the four subparts of the flag so we can verify progress

## DG4-A: Xenial Obsidian Router

Looking at the tasks, it's clear that some automated way of parsing the forms
and executing the programs is needed.  Fortunately, the forms are very
structured, so extracting the text shouldn't be so bad.  From there, we can
loop over the lines and parse/translate it into program
instructions/pseudocode.

First, we need to get usable text from the PDF.  Poppler ships a tool
`pdftotext`; after trying some different options it looked like `pdftotext
-raw` is the best bet.  The output isn't perfect, but adequate enough:

   ...  
   Type  
   or  
   Print  
   1 Field A (internal use only)  
   Part II [redacted]  
   Step 1 Computation Column A  
   2 (do not modify) 2 0  
   3 Copy the ASCII value of the character at index 0 of line 1. 3  
   4 (do not modify) 4 68  
   5 Perform exclusive-or between lines 3 and 4. 5  
   6 (do not modify) 6 255  
   7 Perform logical AND between lines 5 and 6. 7  
   8 (do not modify) 8 45  
   9 Is line 7 equal to line 8?  
   Yes  
   No  
   10 (do not modify) 10 1  
   11  
   If you answered "yes" to line 9, copy the value in line 10. Otherwise, copy
the  
   value in line 2  
   11  
   12 Add line 2 and line 11. 12  
   ...

After some hacky parsing of the text output, I had a tool that would
prettyprint/translate the form program into something more readable:

 ```javascript  
 v3 = input[0]  
 v5 = v3 ^ 68  
 v7 = v5 & 255  
 v9 = (v7 == 45)  
 v11 = v9 ? 1 : 0  
 v12 = 0 + v11  
 v13 = input[1]  
 v15 = v13 ^ 105  
 v16 = v15 & 255  
 v18 = (v16 == 7)  
 v19 = v18 ? 1 : 0  
 v20 = v12 + v19  
 // ...  
 v117 = input[15]  
 v118 = v117 ^ 103  
 v119 = v118 & 255  
 v121 = (v119 == 2)  
 v122 = v121 ? 1 : 0  
 v123 = v116 + v122  
 v125 = (v123 == 16)  
 v126 = (1 if v125 else 0)  
 v127 = v126  
 ```

The only minor "optimisation" done here is tracking lines consisting a direct
constant ("(do not modify)" lines) and inlining the constant when they're
referenced.

We can see that each input character is treated separately in the same way
(with different constants involved), with an equality test performed.  At the
end, we're checking that all the equalities passed (the check against 16), so
we know all those tests must pass, and they uniquely constrain each character.

For each character we end up with a check like `(input[0] ^ 68) & 255 == 45`,
and from there it's easy to find `input[0]`.  In this case we can just find
`input[0]` directly due to the properties of XOR:

 ```javascript  
 (input[0] ^ 68) & 255 == 45  
 (input[0] ^ 68) ^ 45 == 45 ^ 45  
 input[0] ^ (68 ^ 45) == 0  
 input[0] == 68 ^ 45  
 input[0] == 105  
 ```

...but even if we couldn't just directly solve for the input, due to the
independence between the characters we could just as well have bruteforced
each character.

Proceeding this way gives us the first 16-character segment of the flag.

## DG4-B: Petal Robot Nemo Gladiator

One part done, let's continue onwards with the next part!

The previous part could plausibly be solved by hand (without processing the
PDFs), but this is the first task where it wouldn't really be feasible to do
so.

Overall, the approach isn't so different--the characters of the input are
again treated completely independently from each other.  The main difference
is that we can't solve directly for the input in this one--we need to try all
possible characters at each position (independently from each other).

I ended up tweaking my form parser/translator to output a JS function with the
form program in its body and return the count of correct input positions.
Additionally, it'd append a (hardcoded) snippet to bruteforce for each
position in turn:

 ```javascript  
 function foo(input) {  
   // (form program goes here)  
   return v728;  
 }

 const solution = [];  
 for (let i = 0; i < 16; i++) {  
   for (let c = 32; c <= 127; c++) {  
     const input = Array(16).fill(0);  
     input[i] = c;  
     const res = foo(input);  
     if (res[i] == 1) {  
       solution[i] = c;  
     }  
   }  
 }  
 console.log(String.fromCharCode(...solution));  
 ```

Generating and running this searcher script finds our second part of the flag.

Halfway done!

## DG4-C: Circular Andromeda

This next task adds some new tricks to the bag.  The first one: we start with
a call to another function (subform).  Fortunately for us, there's only one
call, with known/static inputs, so we don't really need to implement anything
special for this.

Let's first look at the overall shape of DG4-C itself.

 1. First, we call form DG6 with provided hardcoded inputs  
 2. Next, we build a bytestring from the input string by shifting in each character one at a time  
 3. The input bytestring is bitwise XOR'd with another hardcoded value  
 4. We assert that the DG6 output equals the result of this XOR operation

It's clear what we have to do here: once we know the result of the call to
DG6, we can just XOR it with the provided constant and get the next flag
segment directly.

Let's dig into DG6.  It's immediately clear that we have a very long, tedious
function at our hand.

There's also another curveball here: we get introduced to conditional jumps,
effectively implementing a loop.  fortunately, this is at the very end (in
'Part II Step 2' of DG6), and rather than adding special support in my tool I
found it easier to just manually translate/hardcode the loop and last couple
lines.

Here I decided to switch to generating Python since we're dealing with larger
integers here, and I didn't want any bigint-related headaches.  The DG6 loop
boils down to essentially this:

 ```python  
 def foo(v1, v2):  
   while True:  
     # ...  
     v1925 = v1924  
     v1925 = v2  
     if v1926 == 0:  
       return v1925

     v1929 = v1926 - 1  
     v1, v2 = v1295, v1929  
 ```

I added a print at the loop to keep track of the loop iterations, and ran the
script with the inputs provided form DG4-C.  Unsurprisingly, it immediately
became clear that this program was way too slow.  What were the inputs from
DG4-C again, anyway?

 ```python  
 field_a = 137457122819891222163237234299646470468  
 field_b = 1000000000000  
 ```

...ah.  Yeah, no way we're running ~2⁴⁰ iterations of this monstrosity.

But, we need to compute this number in order to get the next flag part.  So,
what to do?

### Analysis time!

It's clear that interpreted python code and the raw program isn't going to cut
it.  Let's dig in and try to understand the semantics of what the program is
doing.

The program looks something like this:

 ```python  
 while True:  
   v4 = v1  
   v6 = v4 >>  127  
   v8 = v6 &  340282366920938463463374607431768211455  
   v10 = v8 &  1  
   v11 = v10 &  340282366920938463463374607431768211455  
   v12 = (v11 ==  1)

   v13 = v4 >>  0  
   v14 = v13 &  340282366920938463463374607431768211455  
   v15 = v14 &  1  
   v16 = v15 &  340282366920938463463374607431768211455

   v17 = (v16 ==  1)

   v18 = v4 >>  1  
   v19 = v18 &  340282366920938463463374607431768211455  
   v20 = v19 &  1  
   v21 = v20 &  340282366920938463463374607431768211455  
   v22 = (v21 ==  1)  
   v23 = ( 0 if v22 else  1)  
   v24 = ( 0 if v17 else v23)  
   v25 = ( 1 if v22 else  0)  
   v26 = ( 1 if v17 else v25)  
   v27 = (v24 if v12 else v26)  
   v28 = v27 <<  0  
   v29 = v28 &  340282366920938463463374607431768211455  
   v30 =  0 + v29  
   v31 = v30 &  340282366920938463463374607431768211455

   v33 = v4 >>  2  
   v34 = v33 &  340282366920938463463374607431768211455  
   v35 = v34 &  1  
   v36 = v35 &  340282366920938463463374607431768211455  
   v37 = (v36 ==  1)  
   v38 = ( 0 if v37 else  1)  
   v39 = ( 0 if v22 else v38)  
   v40 = ( 1 if v37 else  0)  
   v41 = ( 1 if v22 else v40)  
   v42 = (v39 if v17 else v41)  
   v43 = v42 <<  1  
   v44 = v43 &  340282366920938463463374607431768211455  
   v45 = v31 + v44  
   v46 = v45 &  340282366920938463463374607431768211455

   # ...

   v1925 = v1924  
   v1926 = v2  
   if v1926 == 0:  
     return v1925

   v1929 = v1926 - 1  
   v1, v2 = v1295, v1929  
 ```

First, an observation: we keep masking with this big hardcoded constant,
340282366920938463463374607431768211455, all over the place.  Looking at it in
hex makes it clear that it's a power-of-two minus one; checking reveals it's
indeed 2¹²⁸ - 1.  It's good to keep the bitmasks in mind, but we can largely
ignore them anytime it's clear that the output doesn't need to be masked.
This also tells us we're dealing with 128-bit integers this time around.

It's clear that the program has some kind of unrolled loop.  I already did
some grouping in the snippet above, but looking carefully at the start and end
of the function makes it clear where the regular pattern starts/ends.

So, I started annotating the program (back to C-style conditionals; sorry, I
have snippets from different iterations of my tool, and the code is too much
of a mess to fix up now).  Here's a first look at the start:

   v4 = x  
   v6 = x >> 127                # highest bit of x  
   v8 = v6                      # highest bit of x  
   v10 = v8 & 1                 # highest bit of x  
   v11 = v10                    # highest bit of x  
   v12 = (v11 == 1)             # highest bit of x is 1

   v13 = x >> 0                 # x  
   v15 = (x >> 0) & 1           # lowest bit of x  
   v17 = (v15 == 1)             # lowest bit of x is 1

   v22 = (x >> 1) & 1           # bit 1 of x is set  
   v23 = !v22  
   v24 = v17 ? 0 : v23          # bit0 == 1 ? 0 : !bit1  
   v25 = v22  
   v26 = v17 ? 1 : v22          # bit0 == 1 ? 1 :  bit1  
   v27 = bit128 ? v24 : v26     # if signbit then v24 else v26  
   v28 = v27 << 0  
   v30 = 0 + v29                # shift bit into new place and add to tally

It's clear that we're looking at individual bits of x, performing some
operations/arithmetic on them and building up a new number from individual
resulting bits for the next loop iteration.  There's some logic involving
neighbouring bits as well.

At this point, I was thinking in the direction of ripple-carry adders (since
we also extract the highest bit, i.e. sign bit, which might make sense for
signed integers).  This turned out to not quite be right, but that's why my
annotations are like that...

Anyway, let's go over this bit of code again, now that we have a bit of a
better idea of what's going on... we can abstract and simplify some more.

   v4 = x  
   v12 = (x >> 127) & 1         # highest bit (sign bit)

   v17 = (x >> 0) & 1           # bit0

   v22 = (x >> 1) & 1           # bit1  
   v23 = !bit1  
   v24 = bit0 ? 0 : !bit1       # !(bit0 | bit1)  
   v25 = bit1  
   v26 = bit0 ? 1 : bit1        # bit0 | bit1  
   v27 = sign ? v24 : v26       # sign ? !(bit0 | bit1) : (bit0 | bit1)  
   v30 = 0 + (v27 << 0)         # shift bit into place and add to tally

   v37 = (x >> 2) & 1           # bit2  
   v38 = !bit2  
   v39 = bit1 ? 0 : !bit2       # !(bit1 | bit2)  
   v40 = bit2  
   v41 = bit1 ? 1 : bit2        # bit1 | bit2  
   v42 = bit0 ? !(bit1 | bit2) : (bit1 | bit2)  
   v46 = v30 + (v42 << 1)       # shift bit into place and add to tally

Once we look past the first part of the unrolled loop, we can see that it's
not using the sign bit in the second part.. instead, it looks like we're
always using neighbouring bits, and the use of the highest bit in the first
iteration of the unrolled loop might point at bit rotations... wrapping around
the integer.

I started to get a feel for the conditionals as well.  It's clear that `v26 =
bit0 ? 1 : bit1` behaves as a logical OR (if bit0, then 1; else if bit1, then
1; else, 0), but that `bit0 ? 0 : !bit1` is the negation of the same is a bit
less obvious.  Nothing that can't be solved with a quick truth-table and
trying all possible values, though:

   a b │ v24  v26  
   ────┼──────────  
   0 0 │  1    0  
   0 1 │  0    1  
   1 0 │  0    1  
   1 1 │  0    1

Treating them as `(a | b)` and `!(a | b)` helps with figuring out the final conditional in each unrolled iteration as well, which selects between them.  It looks like `c ? !(a | b) : (a | b)`, or essentially a kind of conditional negation (negate if `c`, otherwise pass through as is).

This perfectly describes a XOR operation.  So, we can simplify further:

   v37 = (x >> 2) & 1           # bit2  
   v39 = !(bit1 | bit2)  
   v41 = bit1 | bit2  
   v42 = bit0 ^ (bit1 | bit2)  
   v46 = v30 + (v42 << 1)       # shift bit into place and add to tally

Let's also look at the last couple iterations, to see exactly what the
behaviour is with these bit indices.

   # ...

   v1897 = (x >> 126) & 1          # bit126  
   v1899 = !(bit125 | bit126)  
   v1901 = bit125 | bit126  
   v1902 = bit124 ^ (bit125 | bit126)  
   v1906 = v1891 + (v1902 << 125)  # shift into place and add to tally

   v1908 = !(bit126 | bit127)  
   v1910 = bit126 | bit127  
   v1911 = bit125 ^ (bit126 | bit127)  
   v1915 = v1906 + (v1911 << 126)

   v1917 = !(bit127 | bit0)  
   v1919 = bit127 | bit0  
   v1920 = bit126 ^ (bit127 | bit0)  
   v1924 = v1915 + (v1920 << 127)

Ah, we loop back over to bit0 again.

Since for each bit, we perform operations with its left and right neighbour
(from the state before, and wrapping around), rather than performing these
operations individually we could just bitrotate the big number and use bitwise
operations.  Let's whip up a Python implementation quickly:

 ```python  
 x = 137457122819891222163237234299646470468  
 y = 1000000000000

 def rol1(x, N = 128):  
   return ((x << 1) | (x >> (N - 1))) & ((1 << N) - 1)

 def ror1(x, N = 128):  
   return ((x & 1) << (N - 1)) | (x >> 1)

 while y > 0:  
   x = rol1(x) ^ (x | ror1(x))  
   y -= 1  
   print(y, '{:032x}'.format(x))  
 ```

Still wayyy too slow, but implementing it this way let me verify that my
implementation/reasoning was sound by comparing iterations against the naive
(direct-from-the-form) implementation.

We need a faster implementation for this to be feasible, but now we know what
operations to perform.  Let's write a searcher in C and make use of
`__uint128_t`; hopefully that's fast enough.

 ```c  
 #include <stdio.h>  
 #include <stdint.h>

 typedef uint64_t u64;  
 typedef __uint128_t u128;

 int main(void) {  
   u128 hi = 7451565559246643524;  
   u128 lo = 7453001392616335684;

   u128 x = hi << 64 | lo;  
   size_t y = 1000000000000;  
 //size_t y = 1UL << 32;

   for (size_t i = 0; i <= y; i++) {  
     u128 x_rol1 = (x << 1) | (x >> 127);  
     u128 x_ror1 = (x & 1) << 127 | (x >> 1);  
     x = x_rol1 ^ (x | x_ror1);

     if ((i & ((1 << 30) - 1)) == 0 || (i > y-5)) {  
       printf("%13zu/%zu  %016jx%016jx\n", i, y, (u64)(x >> 64), (u64)x);  
     }  
   }  
 }  
 ```

Running the searcher with `y = 1 << 32` took ~8 seconds on my laptop, a
massive improvement.  A quick calculation says this should be feasible, so I
kicked the searcher off after double-checking the logic is sound.  30 minutes
later, I had the last couple iterations, and could XOR them with the constant
from DG4-C.

The one after precisely 1000000000000 iterations indeed gave me printable
ASCII after the XOR, and that's our third flag segment down.

Phew!

(If you're wondering why I print several loop iterations toward the end and
loop until `<= y`: at this point I was too tired to think straight, and the
last thing I wanted was to waste 30 minutes because I iterate a loop iteration
too far.  Better safe than sorry.)

One more to go.

## DG4-D: Visual Motion

At this point [leah] had pointed out the pattern in the form names to me.  A
was Xenial Obsidian Router, XOR; B was PRNG; C was Circular due to the loops.
This one is Visual Motion, so presumably it implements some kind of VM?

[leah]: https://leahneukirchen.org/

Looking at DG4-D, the initial general vibes are similar to the previous task,
except the order is inverted.  The steps are something like:

 1. Build up a big number  
 2. Build up a bitstring by shifting subsequent characters from the input into place (shifting by 7 bits at a time)  
 3. Call DG7 with these two numbers as arguments  
 4. Return the result of call to DG7

So it's clear that whatever DG7 does, it needs to help us in determining the
characters making up the input that we feed into it.  I started off by
computing the big number, just to have it around already...

Let's dig into DG7 to see what it does, keeping VMs in the back of our head.

Again we encounter a program with a similar loop/tail-recursion structure as
DG6, but once again I chose to just handle that part manually by hand instead
of letting my tool translate it.  Here's what DG7 looks like, in Python form:

 ```python  
 def foo(v1, v2):  
   # Part II Step 1  
   v3 = v1  
   v5 = v3 &  3  
   v6 = (v5 ==  3)  
   v8 = (v5 ==  2)  
   v10 = (v5 ==  1)  
   v11 = v2  
   v13 = v11 <<  7  
   v15 = (v5 ==  0)  
   v16 = v3 >>  2  
   v17 = ( 0 if v15 else v16)  
   v19 = v17 &  127  
   v20 = v13 + v19  
   v21 = (v20 if v10 else v11)  
   v22 = v21 &  127  
   v23 = (v22 ==  0)  
   v24 = v17 >>  7  
   v25 = (v24 if v10 else v17)  
   v26 = (v25 if v23 else  0)  
   v27 = (v26 if v8 else v25)  
   v28 = v27 >>  2  
   v29 = (v28 if v6 else v27)

   # Part II Step 2  
   v30 = v1  
   v32 = v30 &  3  
   v33 = (v32 ==  3)  
   v35 = (v32 ==  2)  
   v37 = (v32 ==  1)  
   v38 = v2  
   v40 = v38 <<  7  
   v42 = (v32 ==  0)  
   v43 = v30 >>  2  
   v44 = ( 0 if v42 else v43)  
   v46 = v44 &  127  
   v47 = v40 + v46  
   v48 = (v47 if v37 else v38)  
   v49 = v48 &  127  
   v50 = (v49 ==  0)  
   v51 = v44 >>  7  
   v52 = (v51 if v37 else v44)  
   v53 = (v52 if v50 else  0)  
   v54 = (v53 if v35 else v52)  
   v55 = v54 &  3  
   v56 = (v55 ==  0)  
   v57 = (v48 if v50 else  0)  
   v58 = (v57 if v35 else v48)  
   v60 = v58 >>  14  
   v61 = v60 <<  7  
   v62 = v58 &  127  
   v63 = v58 >>  7  
   v64 = v63 &  127  
   v65 = v62 + v64  
   v66 = v65 &  127  
   v67 = v61 + v66  
   v68 = (v55 ==  1)  
   v69 = v64 - v62  
   v70 = v69 &  127  
   v71 = v61 + v70  
   v72 = (v55 ==  2)  
   v73 = v62 * v64  
   v74 = v73 &  127  
   v75 = v61 + v74  
   v76 = v62 ^ v64  
   v77 = v76 &  127  
   v78 = v61 + v77  
   v79 = (v75 if v72 else v78)  
   v80 = (v71 if v68 else v79)  
   v81 = (v67 if v56 else v80)  
   v82 = (v81 if v33 else v58)

   # Part III  
   v83 = v29  
   v84 = v82  
   v86 = v84 & 127

   if v83 == 0:  
     return v86

   return foo(v83, v84)  
 ```

I kept it tail-recursive since at this point I wasn't too worried about
running the code; I mostly wanted to analyse it.

### Analysis

Part II is split into two steps, which is probably semantically meaningful to
the program.  Let's keep that in mind.

Also, in Part III we can see that the final lines from Part II Step 1 and Step
2 are used as the new values for the function arguments.  Let's also keep that
in mind.

#### Part II Step 1

Part II Step 1 begins:

 ```python  
 v3 = v1  
 v5 = v3 &  3                         # v5  = x & 3         (= op?)  
 v6 = (v5 ==  3)                      # v6  = (x & 3) == 3  
 v8 = (v5 ==  2)                      # v8  = (x & 3) == 2  
 v10 = (v5 ==  1)                     # v10 = (x & 3) == 1  
 ```

and right away it looks like we're extracting the low 2 bits of our first
argument (that I've decided to call x), and performing some checks to see if
it's 1, 2, or 3.  Later, we see a similar check for 0 as well.  Given we have
"virtual machine" in the back of our head, I labelled this as 'op' right away
since it could plasibly be an opcode.

Part II Step 1 continues:

 ```python  
 v11 = y  
 v13 = v11 <<  7                      # v13 = y << 7  
 v15 = (v5 ==  0)                     # v15 = (x & 3) == 0  
 v16 = v3 >>  2                       # v16 = x >> 2  
 v17 = ( 0 if v15 else v16)           # v17 = op == 0 ? 0 : v16
# op0?  
 v19 = v17 &  127                     #  
 v20 = v13 + v19                      # v20 = v13 | (v17 & 127)  
 v21 = (v20 if v10 else v11)          # v21 = op == 1 ? (y << 7) | (v17 & 127) : y        # op1 = shift 7 bits into y         op1 = copy?  
 v22 = v21 &  127  
 v23 = (v22 ==  0)                    # v23 = (v21 & 127) == 0
# is low7 of y' == 0?  
 v24 = v17 >>  7                      # shift out 7 bits from x'  
 v25 = (v24 if v10 else v17)          # v25 = op == 1 ? v17 >> 7 : v17
# if op1, shift out 7 bits of x  
 v26 = (v25 if v23 else  0)           # v26 = low7 of y' == 0 ? v25 : 0  
 v27 = (v26 if v8 else v25)           # v27 = op == 2 ? v26 : v25
# op2 = low  
 v28 = v27 >>  2                      # v28 = v27 >> 2  
 v29 = (v28 if v6 else v27)           # v29 = op == 3 ? v28 : v27
# op3 = shift out two bits          op3 = nop?  
 ```

...with some notes of mine annotated on the side.  I had a hard time following
the logic for the different cases though, and keeping track of which
instructions/cases were relevant as I considered the different "opcodes".

Let's try case analysis instead.

Let's copy Step 1 and assume `op` is 0, see what that gets us, and then the
same for 1, 2, 3.  For each case, we start from `v29` and work our way
backwards to see what value it has when the booleans are fixed in a way.

For instance, for op=0:

 ```python  
 v6  = False  
 v8  = False  
 v10 = False  
 v15 = True

 v13 = y <<  7  
 v16 = x >>  2  
 v17 = ( 0 if True else v16)  
 v19 = v17 &  127  
 v20 = v13 + v19  
 v21 = (v20 if False else y)  
 v22 = v21 &  127  
 v23 = (v22 ==  0)  
 v24 = v17 >>  7  
 v25 = (v24 if False else v17)  
 v26 = (v25 if v23 else  0)  
 v27 = (v26 if False else v25)  
 v28 = v27 >>  2  
 v29 = (v28 if False else v27)  
 ```

...simplifies to

 ```python  
 v29 = 0  
 ```

Proceeding similarly, for op=1:

 ```python  
 v17 = x >> 2                   # x with op shifted out  
 v24 = v17 >> 7                 # shift out the bits copied from x  
 v29 = v24  
 ```

(or just `v29 = x >> 2` if you prefer), and for op=2:

 ```python  
 v29 = 0  
 ```

and finally op=3:

 ```python  
 v29 = x >> 4  
 ```

We now know how to compute the next value of `x` for all 4 cases of `op` (= `x
& 3`).  But, how do these operations affect `y`?

#### Part II Step 2

Here I proceeded with similar case analysis as to Step 1.  Skipping over the
details, there's only really one case that gets a bit complicated.

For op=0:

 ```python  
 v82 = y  
 ```

It seems all this operation does is set `x = 0`, so it seems my "exit" or
"done" intuition was correct here.

For op=1:

 ```python  
 v82 = (y << 7) + ((x >> 2) & 127)  
 ```

Shift 7 bits from x onto y (ignoring the low 2 bits making up `op` in `x`).

For op=2, I ended up with this:

 ```python  
 v82 = (y & 127) == 0 ? y : 0  
 ```

If the low 7 bits of `y` are `0`, we keep `y` intact.  Otherwise, we clear it.

For op=3, things are a bit more complicated; here's what we get:

 ```python  
 v55 = (x >> 2) & 3   # read another op from x

 v56 = (v55 == 0)     # subop 0  
 v68 = (v55 == 1)     # subop 1  
 v72 = (v55 == 2)     # subop 2

 v61 = (y >> 14) << 7  
 v62 = y & 127        # lowest operand  
 v64 = (y >> 7) & 127 # second operand  
 v65 = v62 + v64  
 v66 = v65 & 127      # add operands (mod 128)  
 v67 = v61 + v66      # subop 0 result

 v69 = v64 - v62  
 v70 = v69 &  127     # subtract operands  
 v71 = v61 + v70      # subop 1 result

 v73 = v62 * v64  
 v74 = v73 &  127     # multiply operands  
 v75 = v61 + v74      # subop 2 result

 v76 = v62 ^ v64  
 v77 = v76 &  127     # XOR operands  
 v78 = v61 + v77      # subop 3 result  
 v79 = (v75 if v72 else v78)  
 v80 = (v71 if v68 else v79)  
 v81 = (v67 if v56 else v80)  
 v82 = v81  
 ```

Remember in Step 1 that for `op=3` we shifted out 4 bits.  I already guessed
this meant we might have several sub-operations here, and indeed it turned out
to be an "arithmetic operation" opcode.  Looking at how `y` is used here is
also interesting; it looks like we effectively pop two values, perform an
operation, and push the result.  This makes sense: stack-based VMs are very
simple.

#### Python implementation

At this point I felt I understood the opcodes well enough to at least try to
write a python "disassembler".  The program code is the big number we computed
earlier and fed as the first argument (my `x`), and the initial stack is `y`,
which we're meant to pre-populate with our flag characters.  We don't know the
initial stack, but even without that we should be able to disassemble the
program and verify our understanding seems sound.

I'll omit the code for the "disassembler", but here's the start of the output
running it on the program we computed.

   push 93  
   push 42  
   mul  
   push 98  
   push 92  
   mul  
   xor  
   push 52  
   push 93  
   add  
   push 108  
   push 102  
   add  
   mul  
   xor  
   # ...

This looked pretty promising: the pattern pushes and operations look like
you'd expect.  Great!

The op=2 opcode was still a bit of a mystery, but I gathered it was
essentially an "assert", peeking at the top of the stack and making sure it's
0, so that's how I implemented it.

At this point I tweaked my disassembler to also run the instructions, and
tried running it with an empty stack.  This gave me a stack underflow,
although right before the op=2 "assertion".  Trying it with a stack
prepopulated with [0] gave me this trace:

   # ...  
   mul          [0, 107, 96]  
   add          [0, 75]  
   push 20      [0, 75, 20]  
   xor          [0, 95]  
   xor          [95]  
   assert       [95]  
   # ...

Looks like we're essentially back to DG4-A, where each character is revealed
in turn.

At this point I ended up just manually building up the stack one number at a
time, giving us the final stack fragment.

Here's the source code of my python implementation of the VM:

 ```python  
 def execute(code, stack):  
   count = 0

   while code > 0:  
     op = code & 3  
     code >>= 2

     mnemonic = None  
     ret = False

     if op == 0:  
       mnemonic = "exit"

     elif op == 1:  
       x = code & 127  
       code >>= 7  
       mnemonic = f"push {x}"  
       stack.append(x)

     elif op == 2:  
       mnemonic = "assert"  
       if stack[-1] == 0:  
         stack.pop()  
         print("===ok")  
         count += 1  
       else:  
         ret = True

     elif op == 3:  
       subop = code & 3  
       code >>= 2  
       x = stack.pop()  
       y = stack.pop()

       if subop == 0:  
         mnemonic = "add"  
         stack.append((x + y) & 127)  
       elif subop == 1:  
         mnemonic = "sub"  
         stack.append((y - x) & 127)  
       elif subop == 2:  
         mnemonic = "mul"  
         stack.append((x * y) & 127)  
       elif subop == 3:  
         mnemonic = "xor"  
         stack.append((x ^ y) & 127)

     print("{:12} {}".format(mnemonic, stack))

   return count

 code = # ... (computed number)

 execute(code, [0])  # gives us first char of flag  
 ```

And that's it, now we have all four flag fragments and can assemble the flag.

Phew!