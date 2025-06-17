# Writeup of circuitry-magic challenge from M0leCon CTF 2022

TLDR: Extract logic from binary, create symbolic constraints, then guess the
correct flag.

Writeup author: [adamd](https://adamdoupe.com)

Solve Script: [solve.py](./solve.py)

The challenge description given is the following:

```  
VHDL is for noobs, I implement all my tests in C, it is faster, easier, and
more resistant to attacks!

Note: flag needs to be wrapped in ptm{}, it is all printable ascii and it
makes sense in English.

Author: @Alberto247  
```

We are given [encoder](./encoder) and [output.txt](./output.txt).

First we should look at `output.txt`, what we see is a simple json file with a
list of dictionaries of inputs and outputs:

```json  
[{"input": 0, "output": 1}, {"input": 1, "output": 0}, {"input": 2, "output":
0}, {"input": 3, "output": 0}, {"input": 4, "output": 0}, {"input": 5,
"output": 0}, {"input": 6, "output": 0}, {"input": 7, "output": 1}, {"input":
8, "output": 0}, {"input": 9, "output": 0}, {"input": 10, "output": 0},
{"input": 11, "output": 1}, {"input": 12, "output": 0}, {"input": 13,
"output": 0}, {"input": 14, "output": 1}, {"input": 15, "output": 0},
{"input": 16, "output": 0}, {"input": 17, "output": 0}, {"input": 18,
"output": 0}, {"input": 19, "output": 1}, {"input": 20, "output": 1},
{"input": 21, "output": 1}, {"input": 22, "output": 0}, {"input": 23,
"output": 0}, {"input": 24, "output": 0}, {"input": 25, "output": 1},
{"input": 26, "output": 1}, {"input": 27, "output": 0}, {"input": 28,
"output": 0}, {"input": 29, "output": 0}, {"input": 30, "output": 0},
{"input": 31, "output": 0}, {"input": 32, "output": 1}, {"input": 33,
"output": 1}, {"input": 34, "output": 0}, {"input": 35, "output": 0},
{"input": 36, "output": 1}, {"input": 37, "output": 1}, {"input": 38,
"output": 0}, {"input": 39, "output": 0}, {"input": 40, "output": 0},
{"input": 41, "output": 0}, {"input": 42, "output": 1}, {"input": 43,
"output": 1}, {"input": 44, "output": 0}, {"input": 45, "output": 0},
{"input": 46, "output": 0}, {"input": 47, "output": 1}, {"input": 48,
"output": 1}, {"input": 49, "output": 1}, {"input": 50, "output": 1},
{"input": 51, "output": 0}, {"input": 52, "output": 0}, {"input": 53,
"output": 0}, {"input": 54, "output": 0}, {"input": 55, "output": 0},
{"input": 56, "output": 1}, {"input": 57, "output": 0}, {"input": 58,
"output": 0}, {"input": 59, "output": 0}, {"input": 60, "output": 0},
{"input": 61, "output": 0}, {"input": 62, "output": 0}, {"input": 63,
"output": 0}]  
```

So what do we do with this?

Well, we start to reverse the binary, which is just a x86-64 binary.

Luckily the `main` function is not so complicated:

```C  
int __cdecl main(int argc, const char **argv, const char **envp)  
{  
 unsigned int v4; // [rsp+0h] [rbp-60h] BYREF  
 int i; // [rsp+4h] [rbp-5Ch]  
 char input_bits[6]; // [rsp+Ah] [rbp-56h] BYREF  
 char buf[72]; // [rsp+10h] [rbp-50h] BYREF  
 unsigned __int64 v8; // [rsp+58h] [rbp-8h]

 v8 = __readfsqword(0x28u);  
 v4 = 0;  
 __isoc99_scanf("%d", &v4;;  
 if ( v4 < 0x40 )  
 {  
   for ( i = 0; i <= 5; ++i )  
   {  
     input_bits[5 - i] = v4 & 1;  
     v4 = (int)v4 >> 1;  
   }  
   first_step(input_bits, buf);  
   second_step(buf);  
   third_step((__int64)buf, &v4;;  
   printf("%d", v4);  
   return 0;  
 }  
 else  
 {  
   puts("Please provide an input on 6 bits");  
   return -1;  
 }  
}  
```

Essentially what this does it read in a number from us, and if that number is
less than 0x40 (only 6 bits of a number), then it will do stuff with it.

Also important to note here that this corresponds to `output.txt` which has
`input` numbers from 0--63 (0x40 is 64).

Also note that what I called `input_bits` is actually filled in backwards from
what you'd expect (the bit order).  
It's a good idea to note these things so that when you try to implement/solve
it, you match the logic exactly.

The first goal that I have when approaching a reversing challenge (which I
don't often do) is to understand what the challenge is asking of us.

So, I try to go through the code at a high-level to understand where/what the
flag is, or what the challenge wants us to discover as the flag.

The `first_step` calls a bunch of function calls based on our input and fills
a buffer (the second argument):

```C  
void __fastcall first_step(char *input_bits, char *buf)  
{  
 char v2; // [rsp+12h] [rbp-Eh]  
 char v3; // [rsp+13h] [rbp-Dh]  
 int i; // [rsp+14h] [rbp-Ch]  
 int j; // [rsp+18h] [rbp-8h]  
 int k; // [rsp+1Ch] [rbp-4h]

 for ( i = 0; i <= 63; ++i )  
 {  
   v2 = 0;  
   for ( j = 0; j <= 1; ++j )  
   {  
     v3 = 1;  
     for ( k = 0; k <= 5; ++k )  
       v3 &= ((__int64 (__fastcall *)(_QWORD))*(&first_step_array[12 * i] + 6 * j + k))((unsigned int)input_bits[k]);  
     v2 |= v3;  
   }  
   buf[i] = v2;  
 }  
}  
```

These function calls in `first_step_array` are either `neg` (negation) or
`identity` (return the same thing).

The result of `first_step_array` is passed into `second_step`, where the
buffer is mixed with a global called, nice enough `flag`:

```C  
void __fastcall second_step(char *a1)  
{  
 int i; // [rsp+14h] [rbp-4h]

 for ( i = 0; i <= 63; ++i )  
   a1[i] &= flag[i];  
}  
```

Looking at `flag` we see that it's 64 bytes, where each byte is 0 or 1 (this
matches the challenge description mentioning VHDL, which is a hardware
description language).

Concatenating all the bits together, we get an 8-character ASCII string of
`notflag!`.

So, it's important to now step back and think about what the challenge wants
us to do.

Based on the content, we can assume that `notflag!` is _not_ the flag.

This is in contrast to the general flow of reversing challenges where the flag
is somehow embedded in the binary.

However, we're not just given the binary (always important to remember that),
we're also given `output.txt`.

So, presumably the author has generated `output.txt` on a binary where `flag`
is the _real_ flag, and therefore we need to use the `input/output` to figure
out what `flag` must be (since it's used to calculate the output.

Now that we have our goal in mind, we can go back to the third (and final)
step.

This function essentially mixes a bunch of the 1 and 0 from the prior steps
based on this `chains` global variable.

```C  
void __fastcall third_step(char *buf, _DWORD *output)  
{  
 int i; // [rsp+18h] [rbp-18h]  
 int j; // [rsp+1Ch] [rbp-14h]  
 char v4[8]; // [rsp+20h] [rbp-10h]  
 unsigned __int64 v5; // [rsp+28h] [rbp-8h]

 v5 = __readfsqword(0x28u);  
 *output = 0;  
 for ( i = 0; i <= 7; ++i )  
 {  
   for ( j = 0; j <= 7; ++j )  
     v4[j] = buf[chains[8 * i + (j + 1) % 8]] & buf[chains[8 * i + j]];  
   *output |= (char)(v4[6] | v4[5] | v4[4] | v4[3] | v4[2] | v4[1] | v4[0] | v4[7]);  
 }  
}  
```

So now that we understand the logic, how to go about solving the challenge?

## Approach

My plan was to essentially re-implement the logic using symbolic equations,
and use `Z3`, a constraint solver, to solve.

Luckily, angr has a nice abstraction layer on top of `Z3` called
[`claripy`](https://github.com/angr/claripy).

So the first step was to translate the logic of the program into a Python
program.

```python  
def first_step(input_bits):  
   to_return = []  
   for i in range(64):  
       val = 0  
       for j in range(2):  
           cur = 1  
           for k in range(6):  
               func = first_step_array[12*i + 6*j + k]  
               cur &= func(input_bits[k])  
           val |= cur  
       to_return.append(val)  
   return to_return  
```

```python  
def second_step(buf, flag):  
   to_return = []  
   for i in range(64):  
       to_return.append(buf[i] & flag[i])  
   return to_return  
```

```python  
def third_step(buf):  
   output = 0  
   for i in range(8):  
       tmp = [0]*8  
       for j in range(8):  
           tmp[j] = buf[chains[8*i + ((j+1) % 8)]] & buf[chains[8*i + j]]  
       output |= tmp[0] | tmp[1] | tmp[2] | tmp[3] | tmp[4] | tmp[5] | tmp[6] | tmp[7]

   return output  
```

One problem here is how to precisely extract the values from IDA for the
globals `first_step_array` and `chains`.

`first_step_array` I couldn't figure out a nice way to do it, so I just copy-
pasted from IDA into emacs, then used emacs macros to clean everything up into
a Python array of just `neg` and `identity` (which I then wrote functions
for).

For `chains`, after some googling I learned that IDA has a nice feature `Edit
-> Export Data`, which allows you to export the select data as many different
options.

Of course, I made a mistake here and exported the raw char array, not
realizing that these were `int`s (which caused my implementation to not match.

## Verification

After this was done, I set the flag to be the same as the binary that I had,
then I ran all 64 inputs to see if they matched.

They did not, and I had to debug to figure out the problem was (it was the
chains issue).

## Symbolic Victory

After understanding that my implementation was correct, then I switched to
building symbolic constraints based on this logic for all the input/output
pairs in `output.txt`.

This was a bit slow going, as I needed to look up the documentation for how to
do a lot of things with claripy.

I rewrote the encoder function (although looking back, so that the input could
be a python int, and it would create the `input_bits` as claripy variables
(concrete variables, as we know their value).

```python  
def encoder_symbolic(input, flag):  
   assert(input < 0x40)

   input_bits = [0]*6  
   for i in range(6):  
       input_bits[5-i] = claripy.BVV(input & 1, size=1)  
       input >>= 1

   first_output = first_step_symbolic(input_bits)  
   second_output = second_step(first_output, flag)  
   third_output = third_step(second_output)

   return third_output  
```

The only function that I needed to change (or at least thought that I needed
to change) was the `first_step`, so I changed this to just figure out what the
function was (`identity` vs. `neg`), and just emulate that behavior. Note that
I used XOR in place of negation, as this is equivalent and worked with claripy
symbolic variables.

```python  
def first_step_symbolic(input_bits):  
   to_return = []  
   for i in range(64):  
       val = claripy.BVV(0, size=1)  
       for j in range(2):  
           cur = claripy.BVV(1, size=1)  
           for k in range(6):  
               func = first_step_array[12*i + 6*j + k]  
               this_val = input_bits[k]  
               if func == neg:  
                   this_val = this_val ^ 1  
               cur &= this_val  
           val |= cur  
       to_return.append(val)  
   return to_return  
```

Once I verified that the symbolic version was working, I could then try to
read all the required input/output samples, run them through
`encoder_symbolic` to get a claripy formula, then add a constraint that this
output is equal to the output given in `output.txt`.

The basic logic is:

```python

   with open("./output.txt") as f:  
       required = json.load(f)

   equations = []  
   for r in required:  
       equation = encoder_symbolic(r["input"], flag_array)  
       equations.append(equation == r["output"])

```

Now `equations` is a list of all the equations that must be true, and they
should be composed of the symbolic variable of our `flag`.

At this point, I made some mistakes about understand the bit order of the
flag, which led to strange output.

So I dove back into the claripy documentation and examples, as well as playing
around with it, until I was able to make it be how I wanted (the bits needed
to be in reverse order, as `flag[0]` is the lowest bit in claripy):

```python

   s = claripy.Solver()  
   flag = claripy.BVS(f"flag", 64)  
  
   flag_array = []  
   for i in range(63, -1, -1):  
        flag_array.append(flag[i])  
  
```

The final step was, at the end, to `and` all the equations together and then
solve!

```python  
   final = claripy.And(*equations)  
   s.add(final)

   solve_flag = s.eval(flag, 1)

```

After parsing out `solve_flag`, the first character was an I, and the rest was
gibberish.

I went back to the drawing board, and revisited the challenge.  
I don't know for certain, but I think that's when the following was added to
the challenge description: `it is all printable ascii and it makes sense in
English` about the flag.

Based on this, I added constraints to the flag symbolic variable so that each
byte was ASCII:

```python  
   # Add constraints regarding the flag  
   for i in range(0, 64, 8):  
       flag_byte = flag[i+7:i]  
       s.add(flag_byte >= 0x20)  
       s.add(flag_byte <= 0x7E)  
```

I also then needed to change the flag output script, as it's possible for
there to be _multiple_ solutions to a symbolic equation (think `x < y` has an
infinite number of values of `x` and `y` where the equation is true).

So I changed the printing of the flag to output 100 solutions:

```python  
   flags = s.eval(flag, 100)  
   print(len(flags))  
   for possible_flag in flags:

       candidate_flag = ""  
       for i in range(8):  
           candidate_flag += chr(possible_flag & 0xFF)  
           possible_flag >>= 8  
  
       print(candidate_flag[::-1])  
```

I got the following list (important note, there's no rhyme or reason to why
the output is in this order, Z3 has its own internal logic for doing that):

```  
)t3m~gic  
)t3lngkc  
)t;lngkc  
)tslngkc  
)t{lngkc  
)t3mNgic  
)t3m~gkc  
)t;m~gkc  
)t;mNgic  
it3lngic  
)t3l^gik  
)t;mNgkc  
)t3mNgkc  
it3lngkc  
it;lngkc  
itslngkc  
it{lngkc  
)t3mngik  
)t3logkc  
)t;logkc  
)tslogkc  
)t{logkc  
it{logkc  
itslogkc  
It3lNgkc  
it3logkc  
it;logkc  
)t;lngic  
)t3lNgic  
)t;lNgic  
)t3m^gic  
It{lNgkc  
)t3lNgkc  
)t;lNgkc  
)tslNgkc  
)t{lNgkc  
)t3m^gkc  
)t;m^gkc  
it{lNgkc  
it3lNgkc  
it;lNgkc  
itslNgkc  
)t3mNgik  
)t3lOgkc  
)t;lOgkc  
)tslOgkc  
)t{lOgkc  
)t3m_gkc  
)t;m_gkc  
)t3l~gic  
it3lOgkc  
it;lOgkc  
itslOgkc  
it{lOgkc  
)t{l~gkc  
)tsl~gkc  
)t3l~gkc  
)t;l~gkc  
Itslogkc  
It;logkc  
It3logkc  
It{logkc  
)t3lngik  
)t;lngik  
it3lNgic  
)t3m~gik  
)tsl_gkc  
)t{l_gkc  
)t3l_gkc  
)t;l_gkc  
it3lngik  
)t3mogkc  
)t;mogkc  
It3lngkc  
It;lngkc  
Itslngkc  
It{lngkc  
)t3l^gic  
)t3mngic  
)t;mngic  
It;lNgkc  
)tsl^gkc  
)t{l^gkc  
)t3l^gkc  
)t;l^gkc  
)t3l~gik  
)t;mngkc  
It;lOgkc  
It3lOgkc  
)t3mngkc  
ItslOgkc  
It{lOgkc  
)t3lNgik  
)t;lNgik  
)t3m^gik  
it3lNgik  
)t;mOgkc  
)t3mOgkc  
ItslNgkc  
)t3lngic  
```

None of these look useful!

But, while looking at these, I kinda had an idea, it seemed like some form of
`its` (unsure capitalization) at the beginning.

For the end, my mind first went to `magic`, which would actually fit based on
the length: `itsmagic`.

But that didn't quite feel right to me, so I scrolled through the list of
`100` possible flags and saw this chunk:

```  
it3lOgkc  
it;lOgkc  
itslOgkc  
it{lOgkc  
)t{l~gkc  
)tsl~gkc  
)t3l~gkc  
)t;l~gkc  
Itslogkc  
It;logkc  
It3logkc  
It{logkc  
```

These look to be saying that the second half is `logic`!

Putting that together you get `itslogic`, which is eight characters, and, most
importantly, it fits with the theme of the challenge (implementing hardware
logic in C).

I didn't know the capitalization, so first guess I just tried `ptm{itslogic}`,
and to my surprise it was correct.

My full solve script is here: [solve.py](./solve.py).

Overall, it was fun for me to try a reversing challenge, and I got to use
angr/claripy which was quite fun.

However, it's very annoying when they are multiple possible solves for a
reversing challenge, as there's no way to know except to guess.

Although that's not entirely true, as you could generate a ton of solutions
and sort by those that have english words in them perhaps.

But hey, mistakes happen (and I've been on the hosting side of things), so I
still had a fun time solving the challenge.  

Original writeup
(https://github.com/shellphish/writeups/tree/main/challenges/rev/c/m0lecon-
circuitry-magic-2022).