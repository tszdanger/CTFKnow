## Alice & Bob (FE-CTF 2023)

(This write-up is also available [as a
gist](https://gist.github.com/TethysSvensson/51c7325808619a08c2ea353300588d72))

This challenge consists of three parts. In each part participants are tasked
with creating two python functions, `alice()` and `bob()`, which will be sent
to the server. These functions are executed multiple times on the server in a
sandbox and are used to encode and decode messages generated by the server
code.

### Detailed challenge overview

We did not find the sandbox particularly interesting. We assumed it was safe
and focused our attention elsewhere. A simplified version of the runner code
without the sandbox is this:

```python  
def run_single_check():  
   token = list(os.urandom(N))  
   msg = alice(token)  
   assert type(msg) == list and len(msg) <= 64 * 8 and all(x is True or x is
False for x in msg)  
   if msg: msg[random.randrange(0, len(msg))] ^= True  
   assert bob(msg) == token

for _ in range(1000):  
   run_single_check()

send_flag()  
```

The above code gives some random data to your `alice()` function, which will
then encode it as a list of up to `64*8 = 512` bits. After encoding it will
flip exactly one random bit in your message and give it to your `bob()`
function. Your `bob()` function should then recover the original message
despite the single bit flip.

Solving the challenge requires writing `alice()` and `bob()` functions that
consistently produce the correct results in all 1000 executions. Moreover, for
each part of the challenge will increase by adjusting the value of `N`.

The simplified code above also leaves out the part of how to communicate your
functions to the server, but that part is trivial as you just need to hex-
encode the functions and send a string for both `alice()` and `bob()`.

### Part 1 (N=21)

The first part requires transmitting `21*8 = 168` data bits using up to `64*8
= 512` encoding bits. This is really easy, since we can just triplicate each
bit and take the majority when decoding.

```python  
def alice(args):  
   o = []  
   for b in args:  
       for c in f'{b:08b}':  
           o += [bool(int(c))] * 3  
   return o

def bob(args):  
   o = []  
   for i in range(0, len(args), 8*3):  
       c = 0  
       for i in range(i, i+8*3, 3):  
           cur = (args[i] + args[i+1] + args[i+2]) // 2  
           c = (c << 1) | cur  
       o.append(c)  
   return o  
```

After doing the proper hex encoding and connecting to the server we get the
flag:

`flag{m4j0rity-vot3-s1mple,-f4ir-&-effect1ve}`

### Part 2 (N=62)

For this part we have to transmit `62*8 = 496` data bits using the same `512`
encoding bits. The intended solution for this challenge was probably to use
[`Hamming(511, 502)`](https://en.wikipedia.org/wiki/Hamming_code), which can
encode up to `502` data bits using `511` encoding bits.

While we considered using this approach, we decided to skip it and instead
write a solution that also works for both part 2 and 3 with minimal changes.

### Part 3 (N=63)

For this part we have to transmit `63*8 = 504` data bits using the same `512`
data bits. For a while, we were somewhat stuck trying to make this work.

Isn't the hamming code supposed to be optimal?? We only get one more encoding
bit than needed for `Hamming(511, 502)`, and yet we are supposed to cram two
more data bits?? What gives???

It turns out that we made two flawed assumptions.

#### Flawed assumption 1: One more bit!

The realization that the code doesn't demand lists of precisely 512-bits opens
up the possibility of utilizing shorter lists, nearly providing an extra bit
by converting between representations of up-to-512-bits and exactly-513-bits.

```python  
# This function takes a list in the exactly-513 representation and encodes it
as a list in the  
# up-to-512 representation  
# There is only one 513-bit list that cannot be encoded like this, and it is  
# the list that does not have any True values  
def to_512(l):  
   while l[-1] == False:  
       l.pop()  
   l.pop()  
   return l

# This function is the inverse of the function above. It takes a list of up-
to-512 bits and encodes it as a list  
# with exactly 513 bits  
def to_513(l):  
   l.append(True)  
   while len(l) < 513:  
       l.append(False)  
   return l  
```

#### Flawed assumption 2: Hamming is not optimal?!?

It turns out that the hamming code is only optimal if you need to protect
against **up to 1** bit flip. In our case we have additional information,
since we know that **exactly 1 bit** will be flipped. This means that the
hamming bound no longer applies and we are free to try and find smarter ways.

#### Our solution

Our solution was strongly inspired by [an interesting puzzle using a chess
board](http://datagenetics.com/blog/december12014/index.html).

We chose to implement a very special hash function, which maps the `513` bits
to a single `9`-bit number. This hash function works by associating each
position in the array with a 9 bit number and `xor`ing the number of the
position that has `True` values.

Since we are free to which number to associate with each position, we choose
the last 9 positions of the our 513 bit number with the 9 different powers of
two. This means that by manipulating those last 9 junk bits, we can arrive at
any hash value we want.

We pick those 9 bits, so that the hash becomes zero. After a single bit gets
flipped, this will change the corresponding hash value. By seeing how the hash
value was changed, we can figure out which position of the data was flipped
and revert the change.

There is only one small gotcha: There are only 513 unique 9-bit values! We got
around this problem by having a single repeated occurrence of `0x100`. By
putting this repeated value at the last place, we know are guaranteed that
this bit will not be flipped, since this place is artificially reconstructed
by our `to_513()` code.

#### Code

```python  
def alice(args):  
   powers_of_two = [1, 2, 4, 8, 16, 32, 64, 128, 256]  
   hash_values = [i for i in range(512) if i == 0 or ((i - 1) & i) != 0 or i
== 256] + powers_of_two

   def checksum(args):  
       r = 0  
       for (h, b) in zip(hash_values, args):  
           r ^= b * h  
       return r

   def to_512(l):  
       while l[-1] == False:  
           l.pop()  
       l.pop()  
       return l

   def to_bits(args):  
       o = []  
       for b in args:  
           for c in f'{b:08b}':  
               o.append(bool(int(c)))  
       return o

   args = args + [0] * (63 - len(args)) # fixup for part 2  
   args = to_bits(args)  
   c = checksum(args)  
   for b in powers_of_two:  
       args.append((c & b) != 0)

   # debug check  
   assert checksum(args) == 0

   # trim down to 512 bits  
   return to_512(args)

def bob(args):  
   powers_of_two = [1, 2, 4, 8, 16, 32, 64, 128, 256]  
   hash_values = [i for i in range(512) if i == 0 or ((i - 1) & i) != 0 or i
== 256] + powers_of_two

   def checksum(args):  
       r = 0  
       for (h, b) in zip(hash_values, args):  
           r ^= b * h  
       return r

   def to_513(l):  
       l.append(True)  
       while len(l) < 513:  
           l.append(False)  
       return l

   def from_bits(args):  
       o = []  
       for i in range(0, len(args), 8):  
           c = 0  
           for i in range(i, i+8):  
               c = (c << 1) | args[i]  
           o.append(c)  
       return o

   args = to_513(args)

   c = checksum(args)  
   args[hash_values.index(c)] ^= True

   return from_bits(args[:504])  
```

Flag for part 2: `flag{textb00k-h4mming-c0d3s? no more!}`

Flag for part 3: `flag{v3ry-cl0se-to-the-th30retical-limit}`

#### Addendum 1: Alternative solution using `Hamming(511, 502)`

After the CTF ended, I was made by aware of a different solution by some other
players from Kalmarunionen (thanks Killerdog and eskildsen!).

To understand this solution, first recall that a decoder for `Hamming(M, N)`
messages actually returns two values:

- A corrected message with the following behavior:  
 - For messages with 0-1 bitflips: Guaranteed to equal the original message  
 - For messages with 2-∞ bitflips: Guaranteed to be different from the original message  
- A boolean indicating if message was already valid or if it had to be corrected  
 - For messages with 0 bitflips: Guaranteed to be `True`  
 - For messages with 1-2 bitflips: Guaranteed to be `False`  
 - For messages with 3-∞ bitflips: Both behaviours possible depending on which bits were flipped

We can use this extra boolean to figure out if the bit flip happened outside
of the hamming protected area and flip it accordingly.

A sketch of this solution looks like this:

```python  
def alice(msg):  
   msg = to_bits(msg)  
   msg = hamming_encode(msg[:502]) + msg[502:504]  
   msg = to_512(msg)

   return msg

def bob(msg):  
   msg = to_513(msg)  
   hamming_msg, hamming_was_valid = hamming_decode(msg[:511])

   if hamming_was_valid:  
       # The flip must be in bit 511, since bits 0-510 were part of the hamming  
       # encoding and bit 512 was artificially reconstructed by the to_513 function.  
       msg[511] ^= True

   msg = to_bytes(hamming_msg + msg[511:513])

   return msg  
```

#### Addendum 2: Suggestion for challenge improvements

It was possible to solve the challenge using the `Hamming(511, 502)` exactly
as outlined above, but without realizing that you get an extra boolean out of
the decoder. Instead you would simply apply a bit of wishful thinking and
return the wrong message if the bitflip hit outside the protected area. Over
1000 rounds, the probability of being lucky every time is `(511/512) ** 1000`
or roughly 14%.

In my opinion, this means that the challenge should have run for more than
1000 rounds, or alternatively tested every bitflip position at least once.  

Original writeup
(https://gist.github.com/TethysSvensson/51c7325808619a08c2ea353300588d72).