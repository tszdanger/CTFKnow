# Summary

In this challenge we are given some obfuscated Python code that ultimately
emulates a custom machine with memory encoded in base 3. The flag can be found
in memory. Note: To find the files referred to here, please see [this
repository](https://gitlab.com/shalaamum/ctf-writeups/-/blob/master/FE-
CTF%202022/snake-jazz/).

# Obfuscation layer

We are given two Python files, `runme.py` and `magic.py`. Running the former
we are prompted to enter a key, and after inputting a teststring the program
responds with `sadpanda.jpg`.  
```  
$ ./runme.py  
                     .  
                       `:.  
                         `:.  
                 .:'     ,::  
                .:'      ;:'  
                ::      ;:'  
                 :    .:'  
                  `.  :.  
         _________________________  
        : _ _ _ _ _ _ _ _ _ _ _ _ :  
    ,---:".".".".".".".".".".".".":  
   : ,'"`::.:.:.:.:.:.:.:.:.:.:.::'  
   `.`.  `:-===-===-===-===-===-:'  
     `.`-._:                   :  
       `-.__`.               ,'  
   ,--------`"`-------------'--------.  
    `"--.__                   __.--"'  
           `""-------------""'

Please enter key: testkey  
sadpanda.jpg

```  
Presumably the program checks whether we have input the correct flag.

So let us now look at `runme.py`. The only content of this file after `import
magic` is a very long expression that begins with
`_+___+---+---+-__+++-+_-_+_++_++++-+-_+_++_-__-_-+++-++---`, continuing on in
the same fashion. While `+` and `-` are unary and binary arithmetic operations
in Python, `_`, as well as `__` and `___` etc. are usually not defined, so
this must come from the `magic` module, so let us have a look at that now.
`magic.py` contains first the definition of a `class X`, which we will turn to
later, followed by the following code that gets executed on import.  
```python  
for i in range(1, 100):  
   setattr(sys.modules['__main__'],'_'*i,X(3**i))  
```  
We can thus see that e.g. `_` used in `runme.py` refers to an object of type
`X` that was initialized as `X(3**1)`, and `__` is `X(3**2)`, etc.  
Let us now look at the definition of `X`. Looking at the `__init__` function
we see that an object of `X` holds as data three integers, with member names
`a`, `b`, and `c`:  
```python  
class X(object):  
   def __init__(x,a=0,b=0,c=0):  
       x.a=a  
       x.b=b or ~-a  
       x.c=c  
```  
Apart from the `__init__` function we find definitions for various unary and
binary arithmetic or boolean operations, as an example we have here the
`__invert__` function (which gets called for an expression of the form `~x`,
if the type of `x` is `X`):  
```python  
   def __invert__(x):  
       x.c-=x.c  
       return X(x.a,x.b,x.c)  
```  
Just like this one also the other ones return a new object of type `X` with
`a`, `b`, and `c` depending on the arguments, but with no side effects.  
The last member function of `class X` is `__del__`, which makes up the bulk of
`magic.py`, and which gets called on deletion of the object. Only in `__del__`
input is taken in from the user, but looking through the function we can see
that no new object of type `X` gets constructed in it, and neither does
anything else happen (such as changing global variables) that would lead to
code running after termination of a call to `__del__` to depend on what
happens during the call. This implies that input from the user can only ever
impact what happens in the one call to `__del__` in which that input was read
in. While evaluating the long expression from `runme.py`, many objects of `X`
will be created and deleted, however as `__del__` begins with  
```python  
   def __del__(x):  
       if not x.c: return  
```  
some of those calls will have no effect. So let us see what calls with which
arguments actually pass this test, by adding something like the following on
the very next line.  
```python  
       print(f'Call to __del__, object to reproduce:\nX(a=0x{x.a:x}, b=0x{x.b:x}, c=0x{x.c:x})')  
```  
The reason we print out `a`, `b`, and `c` in hexadecimal is that the numbers
are quite large, and Python would complain when trying to parse them later if
we used a decimal representation.

The files `magic2.py` and `runme2.py` are obtained by making the change above.
Executing `runme2.py` we obtain only a single printout announcing a call to
`__del__` that passed the `x.c` condition:  
```  
Call to __del__, object to reproduce:  
X(a=0xf5252907aa10ab6b52973f93fed61d01e6971a55867bd6951a6ed5648135e04d7e273fee7c571d49ea0bbd16990761aa51cb33051a16ecf621b04a666ffb0f898a02a6909d475d40504d5eb1724f519f3657dbec9c52e765bdb9c999945c4e45ddcbbfa7823f90901c884697f2d4be68ec1002a304446ba391cc6f4c1440ec86d927b41196005422de0800c89b35076b2783f261406cf7e31c58ac64d7e87b14a7ab5898b258179bdfd50cf75962f47d6302f9b58e501a78bcfcda3e9bed740c72be0306c62da2a6f7451a4bf94b8b5d276984ebe8a41356097dee1e2efd3f334b76bb3e688072d8ea2cb6a4bc729759ef7183de43a58c99bba04110220d3f30365185419d85adab0330fc64563e33632b03ac396024417bb7d34f17341daa528ea42b0f9d2e3aa3f01da0ce89c5a6b33472bf304621675fea0b049ff995bb5047f2bdde4a3e4139c00768eb1f1cd560def7956e46b94d3280772dfd86d0af33b485dccbffd7a931e85b422166dda0eb2cbd08ab956da9132823acc6e4cd23376118fe5e0906f758d37a1c6c77525f45c4028371cf42fb2e9f3cb8e2d979d84400b6605aef8bf8dd123fc8f1006d222ec7063214d655f6037d3373422df5d4b37c5dd31feb7bbf6f8aaa870e23220979be5dc5ccde592cff25e03fe5f35e31b1504f5baac5b8c5f1203e252d677e85dd10a39c65872124dabf57132001f78d8f4f8fdf10721b408d33a784a7fdf4b13be594ef48483b68b46ac893187bb27a0ac1aa55462cccf6f916fa52fd19372a24090218a43c8f4e8a4860792806dc968f1bc21b5c8ce417a24932079d536d811433e45e0db40cc0af718eeb08a17f25e0fb5227223c4577b9e7fb377340da03f30904585e404e1c54d5d7a48a0f457f2a339b9dbc2bf5f5a6d096bd0719e8e58b62d6cb1bd5668037cdca13605a3ef2b4ac0a48554fe7fa3a5481c3bdfb897ea3bbf45b8be86a06dbeb100cf7d922d3a00e5d8408d72ecb1414f3fa3e7699e02bade1a086385d862ca587ec92840e6df1f306bcf31aa721d8aaa84d41c1e102665ba735450abdfb7c584aaf452a103877054d50607824f157b813821afcaf341e1262d4228039deccd9c1bb8f4db72bdcf57a68543c9257959bd6e72371469c804b1df2c96d7c9ed65cd59391855df0318a6180967a40df1556e09246e7139537d2d02b8cb90c8e73f3a2176186aca1a38ce0d2635b6bf20725d09ac719521ac157fb8800511744ffb3d24daee3973da0da8edba159d9e3e4d1b178075eb6947f07fdc3d4888c1058d588dd5d468d21875557fe8ad65abd10c9e1852f9324302f9bbc8783f303be0eabca1549dfc2286d4bce502b9f3b8cd7f02f1b8ef16b8aaded71a18a3bb28dd437cf5b68ab49cbe55d996b115a54eddd8f1291b98d1cd277640824d476d384eb1d8a2c03746a685821c11f8d77ce45f721be893bcc4b7494b56391a97c6883d05e5e2cb2049fbea98cc2d228955a513faa00e0d0fcb034ee2f2b6248992d2e9d853621793000b5719c9166e71d222650dcba1442ba3808da13df5f7547b1a94bfa2abafbe682a3216e038f1091eda9c2877e9bc0a46bb2c06877bc40620da516e00c38142d45eb69d07235477cef8aef038f1570fbd638d17a851c63e81ff34f6b8b2238d3329de77fa77a2aa37fd78732aca902be47f8524c97a7132476cf94482c1052127711928f3c7a04a0ede860b06338c219c8e6406b7215a351baa8ed664bd5be785245ffb57bf45b72e4177c834084c9182ded559fc4930035d1ebe39d6d05ef138a2a763c2b41601120f676a4e3e26a9af94cba7280580633661c7e7222067f84df7b8ddade5f5a19f2d15509ba4469e44261e268e0d9e850b99758296fbea7bdd6522e715d42c258a6d878691994a86a35ad8db,
b=0xa738fbf877afd0ba31d02a27bc32ade21db41e0c2dddd279e7046f8ab2850129842b55704bdc96fd8fc5b00503cded660076ca97af0870f3999a34a5776a84318bb349c6508a32ebb806bc7ad6ea251733349a6c81eebf874fa647f77c0bf882d4aec2fc71d6f17b261ae4c4caf80606296e6681ed2dd964289a862423db6617f60b87b5b3d3d62dd700544fe5b3e2515382f74cbba936c5fba8ff816221d3175e1b616637d8d72f43091593c82fd87932b0da6aa3199eca65e91896c29e3cb49ac86aa31f98273b05f19fce26deca7c7bb786048256903ae1b5a2f9b7c389a4acb14f349798d3aafcfd59dc8502a9aad21cb69d5122141a88ff8e213d064f7e56f23afc51627555bfd26cd544c653554ae51aaeec39398d0c3a2585d1aaa1caf26c51dec1cb5f7464fe870553cc455316f6bd51abe6e31c566f97922ea3e4072c76aab3811db49d5ef38b8c525429c19b86d71f8258919736b85cb6bfa8bb89a6687fd38c95395de0f2fc5f1c199b0ab0e8dd20e1ba178be7449b7ca72186cc1a91408942e7d44ebdca3657d71cb196830ed4ba8b7295eade9b5c28a4e7e3878ffaf95e489429ec328109f6a1985a8697c2433ed811001344c6ef6eb693f644b051adaa363e5b3026723325c44ddee6a5ce3736bfaddaeafcfe9f0cccf9bf34450ee273bb056821e65c30d2fcff1c4ad3a10c29986931d218fed36be54fdd8415902447045475de5c1597b813caebf63c51ef265f387a31662f6e3f56fe8d632d2842aa1619e2f26973cee12cf1a62af52b632112c08d349effe78d96a4fef7960c7a5b6966cff1aaf3ea3f837f327f43d619e377e7494b6eefc119c8f86ea9507af6ebbf4eb4c37428223ef67afda9b633568928783d6e57a4d498cd8835032c873fe942b5144cb1d40d1b955d1c72817dc8a4de65348a7dcd5682636b3478b3cc0f98d2cc83e8e93ec0e0462c5350dfb1839cc9f96f239b33fc698e72aa3b1571458b15538b37eb15a1775813bc18635a912f9bf124ad9c428c88747fe59eff7e7ec4b50db42196351b86cb45ff838982f56b5bc60d5afba65b2df159b1c61499413ea9bc8937d2a7f8e48f003abafdf01e55f5cabc73b761ece120ac06dc2a1d2eb1aad14757e56cdaf17baad6a2c9d07e10c9f939cc20af7d72fcb257cc65ec8252b1b666fd514b8e746adccba16784d817bf014a9f9c81d2a02ba2695fc7efe5bcea6081ef8fd28d0b29d10b72531f0715439677b6f045c363fab66dcfe0a562e19d91cbfd208ccce7f264913b1b1beeb6e41a3c96396db110fb6a6a295a60341276f2caeb955124b4a4b4e87d6ec692bc18d28563ad62d0ef0187663ebd1cb7cf30eb13f960939c14c17d17bd9f4f3602c34f52243653519c8393704506465d7e9163412059245a2db9b418556164c19287b461ee4d58f5b722df4adc1b1365f79f57d5a16cdeacac35fc46c8ccc45fd2f04d13e3f79f7f16ac5d1ba915c4ad16fa1ee69a3ff86d4e0e745531e9339db60f253c3462bf326ebb989e46a10358f8648cf0e928bdc5a4ccb352daf93d0bb9ca973a579069ec8df57cbf28ad62b47b5642194e43955184caa278b0595a2252f6c0d53f92a16697f8a167ac62cedcb848fc82eb18f562767b9d31b9d477174f8b1fd03c1182a0577265a1db83abd5f7b4472a353e2b1fd3e81563b76d0be67e73cb9fb72150532c1d1f2dad3fe16b42dc842f0051bb70c7a7ee3a869aae7135dc5100a179776572eb088f84f37073159c85c37ca7add3be1f511674502924930406991c0262e3cae062589eced1e6073fcb9173bc1d348b004cd8e31959fca97b7053f47c6e331120fa2f572a217e55461a7d7e13f75b0eff7e74fa4ae3204e8445e046aadc3f382b698aa8d5e4b275676b3ab7cd45bdfd42e799033,
c=0x3)  
```

Instead of the long expression in `runme2.py` we could instead just construct
and delete the object indicated above. If we do this, then all the arithmetic
and boolean unary and binary operations for `X` are not going to be used
anymore, so they have become irrelevant and can be discarded. Similarly for
the definition of `_` and so on. We thus arrive at `magic3.py` and
`runme3.py`, where we additionally renamed `__del__` to `run`.

# Analysis of the emulator

The following is the beginning of the `run` function in `magic3.py` we now
have to analyze.  
```python  
   def run(x):  
       if not x.c: return  
       y=[0]*9  
       while 3**y[8]<x.a:  
           z=x.b//3**y[8]%3**7  
           y[8]+=7  
           a=z//3**4  
           b=z//9%9  
           c=z%9  
           d=c+x.b//3**y[8]%3**7*3*3  
           if   a==0:  
               os._exit(0)  
           elif a==1:  
               y[8]+=7  
               y[b]=d  
```  
After that there are a bunch more elif branches depending on the value of `a`.
So we initialize 9 integer variables in the list `y` to `0`, and then there is
a loop where we first calculate some values for `z`, `a`, `b`, `c`, and `d`,
and then there is a big case distinction based on what the value of `a` is.
Searching through the code we can quickly see that `x.a` and `x.c` are only
used in the first couple of lines; `x.c` is only used in the `if not x.c:
return` check at the start and `x.a` only in the exit condition of the loop.
So the behavior of this function must mostly be encoded in the value of `x.b`.
The following are the lines in the `run` function in which `x.b` is accessed
or changed:  
```python  
z=x.b//3**y[8]%3**7  
d=c+x.b//3**y[8]%3**7*3*3  
y[b]=x.b//3**y[c]%3**(3*3)  
x.b+=y[b]*3**y[c]-x.b//3**y[c]%3**9*3**y[c]  
```  
We can make those lines a little more readable (perhaps after looking up
[order of precedence for Python
operations](https://docs.python.org/3/reference/expressions.html#operator-
precedence)):  
```python  
z = ( x.b // (3**y[8]) ) % (3**7)  
d = c + ( ( x.b // 3**y[8] ) % ((3**7)) ) * 3 * 3  
y[b] = ( x.b // (3**y[c]) ) % (3**(3*3))  
x.b += ( y[b] * (3**y[c]) )  -  ( ( x.b // (3**y[c]) ) % 3**9 ) * (3**y[c])  
```  
We see that on the right hand side `x.b` is always first divided by a power of
3 that depends on some other variable, and then the result is taken modulo a
fixed power of 3. This has a very natural interpretation if we think of `x.b`
as a number in base 3.  If we index the trits (like bits, but in ternary, i.e.
base 3) of `x.b` starting with 0 for the least significant one, then the first
line can be interpreted as extracting trits `y[8]` through `y[8] + 6` from
`x.b`, in the sense that the resulting value has as least significant trit the
one that occurs at index `y[8]` in `x.b`.  Similarly for the third line,
though in this case rather than 7 trits we extract 9 trits. In the second line
7 trits are extracted, and the result is shifted up by two trits. Finally, the
last line changes the value of `x.b`. With the interpretation so far in mind
we can rewrite this line as follows.  
```python  
x.b = ( x.b  -  ( ( x.b // (3**y[c]) ) % 3**9 ) * (3**y[c]) ) \  
     + ( y[b] * (3**y[c]) )  
```  
What happens is that with `( x.b // (3**y[c]) ) % 3**9` we first extract 9
trits beginning from the one indexed by `y[c]`. The multiplication by
`3**y[c]` shifts that number up so that the we now obtain a copy of `x.b` in
which all trits except the 9 ones starting from the one indexed by `y[c]` have
been set to 0. Subtracting this from `x.b` thus results in a copy of `x.b` in
which the 9 trits starting with the one indexed by `y[c]` have been cleared.
Finally, as long as `y[b]` is a nonnegative integer smaller than `3**9`,
adding `y[b] * (3**y[c])` sets those 9 trits to be the least significant 9
trits of `y[b]`.

We can thus conclude that `x.b` acts as the memory of the emulated ternary
machine. The smallest units that are read or written seem to be both 7 and 9
trits long, which is a bit unusual. Accordingly, memory is addressed at the
lowest level, the trit (i.e. in the first line above we have `3**y[8]` rather
than `3**(y[8]*7)`).

# Getting the flag

If the program encoded in `x.b` checks whether our input is the flag, then the
easiest way this might happen would be to just compare with the correct flag
that is stored in memory (perhaps after decryption). In that case we can find
it just by printing out the content of the memory (perhaps at the right
moment). But it could also be that the correct flag in memory is encrypted or
hashed in some way and our input will be compared after being encrypted or
hashed as well. In the latter case we might have to identify what the
individual instructions do and disassemble/debug the program. But as a first
check we can try to print out memory access by replacing the four lines that
use `x.b` above with a new function that also prints out the memory accessed.

We thus add the following to the definition of `class X`:  
```python  
   def mem_get(self, index, width):  
       value = (self.b // (3**index)) % (3**width)  
       output = f'Memory at {index} of width {width} accessed, value is 0x{value:02x}'  
       if value < 127:  
           output += f'="{chr(value)}"'  
       print(output)  
       return value

   def mem_set(self, index, width, value):  
       if value >= 3**width:  
           print(f'Trying to write {value} at {index} with only width {width}')  
           raise Exception  
       self.b = (self.b - ((self.b // (3**index)) % (3**width))*(3**index)) + value*(3**index)  
       output = f'Memory at {index} of width {width} set to 0x{value:02x}'  
       if value < 127:  
           output += f'="{chr(value)}"'  
       print(output)  
```  
and replace e.g. `z=x.b//3**y[8]%3**7` with `z = x.mem_get(y[8], 7)`. This
change is implemented in `magic4.py` and `runme4.py`.

The output has very many lines. Perhaps we should reduce this a bit to see
something. The case distinction being made in the loop depends on `a` . The
first three lines at the top of the loop are as follows.  
```python  
           z = x.mem_get(y[8], 7)  
           y[8]+=7  
           a=z//3**4  
```  
Thus `a` is given by the lowest 4 trits of `z`, which is given by 7 trits of
memory indexed by `y[8]`. Furthermore, `y[8]` is increased by 7. This suggests
that `z` encodes a instruction and `y[8]` is the instruction pointer. We are
thus not really interested in memory access at the instruction pointer, so
lets us make the printout of memory access optional and let us filter out
these accesses. Furthermore, let us filter out memory access before input is
first taken from the user. This is done in `magic5.py` and `runme5.py`.

Going through the output, we can actually see characters `f`, `l`, `a`, `g`,
`{` occurring in that order, the first one being the following line.  
```  
Memory at 6333 of width 9 accessed, value is 0x66="f"  
```  
Thus it looks like we might be able to extract the flag from memory directly.
So let us now print out memory starting at `6333` with width `9`.

We add the following function to `class X`:  
```python  
   def print_memory_string(self, index, width):  
       while True:  
           value = self.mem_get(index, width, debug=False)  
           if value < 127:  
               print(chr(value), end='')  
           else:  
               break  
           index += width  
       print()  
```  
and call this with `x.print_memory_string(6333, 9)`. This is implemented in
`magic6.py` and `runme6.py`.  
If we directly call this, we unfortunately do not obtain the flag, initially
the value at address `6333` is `0x1411` rather than `0x66`. So perhaps the
flag is first decrypted in memory. To circumvent this problem we print the
memory *after* having run the program. In order to do this we need to make one
more change: when `a == 0`, execution of the emulated program halts, by
calling `os._exit(0)`. We change this to `break` to end the loop instead.

With these changes we now obtain the following output:  
```  
$ ./runme6.py  
                     .  
                       `:.  
                         `:.  
                 .:'     ,::  
                .:'      ;:'  
                ::      ;:'  
                 :    .:'  
                  `.  :.  
         _________________________  
        : _ _ _ _ _ _ _ _ _ _ _ _ :  
    ,---:".".".".".".".".".".".".":  
   : ,'"`::.:.:.:.:.:.:.:.:.:.:.::'  
   `.`.  `:-===-===-===-===-===-:'  
     `.`-._:                   :  
       `-.__`.               ,'  
   ,--------`"`-------------'--------.  
    `"--.__                   __.--"'  
           `""-------------""'

Please enter key: testkey  
sadpanda.jpg  
flag{it's, it's a device Morty!}testkey  
```

The correct flag is indeed `flag{it's, it's a device Morty!}`.

# False paths taken during the CTF

During the CTF competition I did not consider just trying if the flag can be
read off from memory and was assuming that I would have to reverse some
crypto-operations on the input or something like that. I thus wasted some time
understanding the different instructions and disassembling the program before
I realized that this was unnecessary and the flag could be read off from
memory.

Original writeup (https://gitlab.com/shalaamum/ctf-writeups/-/blob/master/FE-
CTF%202022/snake-jazz/writeup.md).