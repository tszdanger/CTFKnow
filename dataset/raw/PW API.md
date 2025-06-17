# PW API (worth 400+392 points)  
Part of the P.W.N. University CTF 2018 (https://uni.hctf.fun/pages/home/)

```  
Prof. Hackevoll always forgets his passwords.  
Thats why he wrote himself a password storage API...  
[...]  
Hint: What you found out in PW API Stage 1 might come in handy here!  
```

The description included a download link to the server application and a link
running a hosted instance as well as a link to an example script using the
API.

The App is a Java Web Service which allows storing passwords using a simple
API. To get an API key you need a static password which is set on application
startup. Using this API key you can add and retrieve all passwords
corresponding to this API key.

Stage 1 was a database dump where the first flag was included in a Screenshot.
Revisiting this screenshot after reading the hint we notice that the
screenshot includes the address bar showing
`http://pwapi.uni.hctf.fun:909/get?apikey=QC3qp3UgMUoWjSKgOt`. It also
contained another attachment showing a picture from Spongebob with the text `3
days later`.

Naturally the first idea is to just use that key to retrieve the flag but that
obviously fails.

## Application Source Code  
The application is a standard jar file which we can `unzip` and decompile
using any Java decompiler (e.g. `jad`). This gives us four files containing
the application logic, the most interesting of which is PasswordController
with the following lines:

```  
import org.apache.commons.lang3.RandomStringUtils;

[...]

public ApiKey createKey(String pw)  
{  
 String apiKey = "";  
 boolean activated = false;  
 if(pw.equals(instancePw))  
 {  
     apiKey = RandomStringUtils.random(100, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");  
     activated = true;  
     pws.put(apiKey, new ArrayList());  
 }  
 return new ApiKey(apiKey, activated);  
}  
```

Note that the API key must have the length of 100 characters, since the key
from the screenshot is only 18 characters in length this is either not the
correct or an incomplete key.

Looking into the source code of `RandomStringUtils` we notice that this does
not use a cryptographically secure PRNG, so our first idea is to break this by
abusing the predictable nature to recover the full api key which will
(hopefully) yield the flag when used on the hosted instance of the service.

## Attempt 1: System.nanoTime() and 3 days later  
`RandomStringUtils` is based on the standard `java.util.Random` generator, for
which the source code is available online. When it is not seeded with any
particular seed it will use `System.nanoTime()` xor'ed with a
`seedUniquifier`. This `seedUniquifier` is predictable and depends on the
number of instances created of `Random()`  so far. It is initialized with
`8682522807148012L` and then multiplied with `181783497276652981L` each time
it is used (truncated to 64bit due to being a `long`).

`System.nanoTime()` refers to the amount of nano seconds which have elapsed
since some specific but unspecified point in time. Remembering the attachment
from the first stage, which read `3 days later`, this sounds a lot like the
correct seed. `3 days` in nano seconds is `3*24*60*60*1E9`, so now we can just
xor this with the first `seedUniquifier` (or rather the first 10 just to be
sure) and use that as the `Random` instance used by `RandomStringUtils`
instead.

This, however, does not lead to the correct result.

## Attempt 2: Using the 18 character substring to reverse the RNG seed  
The second idea was to use what we know about the key from the screenshot,
namely the first 18 characters, to reconstruct the seed. However, since each
random value generated is taken modulo 62 inside the
`RandomStringUtils.random()` function it did not seem to be feasible at first.
Out of ideas, we abandonded this challenge for now.

Then the second hint was released, which was:  
```  
Hint 2: Sometimes the simple, linear truth is hidden behind a lot of bloat,
but can still be met in the middle.  
```

Having solved the `LCG and the X` challenge of the same CTF before, we assumed
that `linear truth` referred to the "linear congruential generator" used by
the Java Random generator (more details on how this type of RNG works follow).

"be met in the middle" most likely refers to a "meet-in-the-middle attack"
which, roughly speaking, is based on breaking the problem into two simpler
problems, solving those and combining the solutions to solve the initial
problem.

Now it sounds like this attempt was not that wrong after all.

### `RandomStringUtils` internals  
First lets take a look at how the `RandomStringUtils` library works. The
binary shipped version commons-lang 3.7 for which the relevant source code can
be found here: https://commons.apache.org/proper/commons-lang/apidocs/src-
html/org/apache/commons/lang3/RandomStringUtils.html#line.56

Internally, `random(...)` is overloaded and the actual function doing the work
has the following signature:  
```  
public static String random(int count, int start, int end, final boolean
letters, final boolean numbers,  
                           final char[] chars, final Random random) {  
```

In our case this function is called as `random(100, 0, 62, false, false,
"abc...789", RANDOM)` where `62` is the length of the charset and `RANDOM` is
the static instance of `java.util.Random`.

Stripping away handling for special cases, which are irrelevant in this case,
the function basically works as follows:  
```  
final StringBuilder builder = new StringBuilder(count);  
final int gap = end - start;

while (count-- != 0) {  
   int codePoint = chars[random.nextInt(gap) + start];  
   builder.appendCodePoint(codePoint);  
}  
return builder.toString();  
```

Seems pretty straight forward, so let's dive into the `random.nextInt(int)`
function.

### `java.util.Random` internals  
The Random generator has apparently changed a bit over the time but the
functionality remained the same since at least JDK8 (which is the earliest we
looked at).

The `nextInt()` function basically works as follows:

```  
public int nextInt(int bound) {  
   [handling of special cases omitted]

   int bits, val;  
   do {  
       bits = next(31);  
       val = bits % bound;  
   } while (bits - val + (bound-1) < 0);  
   return val;  
}  
```

The `while (bits - val + (bound-1) < 0)` check is used to assure a uniform
distribution over all values between 0 and the bound. However, in this case
the likelihood for this to happen is `(2^31 % 62) / 2^31` which is extremely
unlikely. Later we figured out that this is indeed irrelevant in this case
since this special case is never hit, which is why we will omit it in the rest
of the writeup. However, this is just an additional random number being
generated with the previous one being discarded.

Basically we return the result of `next(31)` modulo 62, so let's look at
```int next(int bits)``` next, again omitting the code which makes this
function thread-safe.

```  
protected int next(int bits) {  
   long oldseed = seed.get();  
   long nextseed = (oldseed * multiplier + addend) & mask;  
   seed.set(nextseed);  
   return (int)(nextseed >>> (48 - bits));  
}  
```

In this funciton, `seed` is the internal state of the `Random` instance which
consists only of this 64-bit `long`. `multiplier`, `addend` and `mask` are
fixed constants which thus can be considered public knowledge.

`multiplier = 0x5DEECE66DL` and `addend = 0xBL` are just "good" constants
taken from some paper, which are not really interesting. `mask = (1L << 48) -
1` is taken from this paper as well but is simply truncating the result to
make it only 48 bits in length. This is equivalent to modulo `2^48`.

For outputting this, the new seed is then shifted to the right leaving us with
exactly as many bits as we requested. In our case this shifts the output by
`17`. Note that only the output is shifted, not the internal state of the RNG.

These three constants together with the seed define how the Linear
Congruential Generator behaves. And at this point, during our research, we
have come across quite a lot of StackOverflow posts telling us that we should
definitely not use this for cryptographical purposes, since the seed can
easily be recovered from the output.

However, a lot of the replies on these posts assume that you get the complete
output of the RNG, but we just get the output modulo 62. Some other assume
that we can get some bits from the output, but again, since we take the output
modulo 62 we lose all of the bits of the output. Actually not all of them,
since the parity, i.e. the least significant bit, remains the same, since our
modulo is even. But surely this one bit can't be enough to recover the seed,
or can it?

### The attack  
(Disclaimer: the following chapter is based on this reply on StackExchange:
https://crypto.stackexchange.com/questions/2086/predicting-values-from-a-
linear-congruential-generator/2087#2087)

The linked post addresses the case where we have the modulo 6, but it works
the same in our case. The two important things about this are that a) we have
an even modulo on the output and b) we have a power of 2 as the modulo in our
RNG (reminder: the modulo was 2^48).

As mentioned before, a) gives us the benefit that we obtain one unaltered bit
of the generator's output (and thus the state). In our case, since the state
is shifted by `17` to the right to obtain the output, this bit is the 18th bit
of the RNG's state (when ordered ascending from LSB to MSB where the least
significant bit is the first bit).

The second property b) is what enables the meet-in-the-middle attack. Since we
are doing a modulo with a power of two, this is equal to simply cutting of the
leftmost bits of the output and not altering the rest of the state. This means
that when we are only interested in the 18th bit, we do not care about
anything left of it when doing additions or multiplications. When doing
additions, the 18 least significant bits may overflow and affect the more
significant bits, but never the other way around. The same thing holds for
multiplications.

The key benefit is that when we are only interested in the 18 least
significant bits, we can ignore all more significant bits. Thus, when
reversing the seed of the RNG, we no longer have to look at all `2^48`
possible states but only at `2^18` which is easily bruteforceable.

Now, how do we recognize the correct seed? We are interested in only the
parity of the outputs, so for each character in our known API key
(`"QC3qp3UgMUoWjSKgOt"`), we look whether it is at an even or odd position in
the String used to generate it, where the first index is 0 and thus even.

We can then simply try all `2^18` possible seeds and see which yields the same
sequence of even/odd in the 18th bit which is equal to the first output bit.
This can be achieved with the following code, where `vals` denotes the indices
of the char's of the API key in the String used to generate it.  
```  
LinkedList<Long> candidates = new LinkedList<Long>();

outer:  
for(long seed = 0; seed < (1L<<18); seed++) {  
 long newSeed = seed;  
 for(int i = 0; i < numChars; i++) {  
   int bits, val;  
   do {  
     newSeed = (newSeed * multiplier + addend) & mask;  
     bits = (int)(newSeed >>> (48 - 31));  
     val = bits % 62;  
   } while(bits - val + (62-1) < 0);  
   if((val % 2) != (vals[i] % 2)) {  
     continue outer;  
   }  
 }

 candidates.add(seed);  
}  
```  
Now we have a list with potential candidates for the 18 least significant
bits. Since the seed is 48 bits in length, we have `2^30` possibilities for
the remaining 30 bits. This is more than before, but even though bruteforcing
now takes a few seconds, this is absolutely feasible.

Now we no longer care only about the least significant bit of the output of
`nextInt(int bound)` but instead all of them, so we simply check whether the
output modulo 62 would yield the same character as we have in our known API
key.  
```  
LinkedList<Long> solutions = new LinkedList<Long>();

for(long c : candidates) {  
 System.out.println("Checking: " + c);  
 outer2:  
 for(long l = 0; l < (1L << 30); l++) {  
   long newSeed = (l << 18) | c;  
   long theSeed = newSeed;

   for(int i = 0; i < numChars; i++) {  
     int bits, val;  
     do {  
       newSeed = (newSeed * multiplier + addend) & mask;  
       bits = (int)(newSeed >>> (48 - 31));  
       val = bits % 62;  
     } while(bits - val + (62-1) < 0);  
     if(val != vals[i]) {  
       continue outer2;  
     }  
   }

   System.out.println("Found: " + theSeed);  
   solutions.add(theSeed);  
 }  
}  
```  
This allows us to recover the full seed. Having this seed, we can simply use
it to generate the whole 100 character key as follows, where `baseString` is
`"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"`  
```  
for(long s : solutions) {  
 System.out.println("Verifying: " + s);

 long newSeed = s;

 for(int i = 0; i < 100; i++) {  
   int bits, val;  
   do {  
     newSeed = (newSeed * multiplier + addend) & mask;  
     bits = (int)(newSeed >>> (48 - 31));  
     val = bits % 62;  
   } while(bits - val + (62-1) < 0);  
   System.out.print(baseString.charAt(val));  
 }  
 System.out.println();  
}  
```  
This solution works perfectly for all test values generated using:  
```  
RandomStringUtils.random(100,
"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");  
```  
Now there is just one problem: It does not work with the actual apikey in the
challenge.  
### The Unsolvable Challenge  
"Does not work" in this case means the solution above found no seed. Now this
can either mean two things: a) the theory or implementation is wrong or b) the
known API key can not have been generated with the
`RandomStringUtils.random(...)` call from above.

While a) seems absolutely possible and we actually spent quite a lot of time
on debugging, we will skip forward to the part where we contacted the
organizers. It is, however, noteworthy that we played around with the input
and, upon reversing it, we were able to recover a seed generating
`"tOgKSjWoUMgU3pq3CQ"`, but stretching the key to 100 characters using the
code above and submitting this to the service did not yield the flag.

Upon realizing that we apparently seemed to be doing the correct thing and
after confirming that the key was indeed generated with the same application
we have, they added the following hint:

```  
Hint 3: OpenJDK Runtime Environment (build 10.0.2+13-Debian-1), or in Docker
terms FROM openjdk  
```

Since we looked at the code of OpenJDK8 so far and only tested the solution
with values generated by an application being run using the JRE8, we also
looked at OpenJDK10 and OpenJDK11 but the result remained the same: We could
recover the seeds from all generated Strings except the one from the
challenge.

So we contacted the organizers again, and it turned out they indeed made a
mistake. While they initially uploaded a .jar-file using `commons-lang-3.7`,
the actual service used `commons-lang-3.5`. After they uploaded the fixed
application, we actually had to look quite hard to spot the differences
between the two.

As mentioned before the `RandomStringUtils.random()` in Version 3.7 works as
follows:  
```  
final StringBuilder builder = new StringBuilder(count);  
final int gap = end - start;

while (count-- != 0) {  
   int codePoint = chars[random.nextInt(gap) + start];  
   builder.appendCodePoint(codePoint);  
}  
return builder.toString();  
```  
While Version 3.5 used the following code (again omitting special case
handling):  
```  
final char[] buffer = new char[count];  
final int gap = end - start;

while (count-- != 0) {  
   char ch = chars[random.nextInt(gap) + start];  
   buffer[count] = ch;  
}  
return builder.toString();  
```  
While at first glance it appears that they just switched from a `char` buffer
to a `StringBuilder`, they actually reversed the order in which the String is
built. (A very minor detail which will most likely never affect anyone except
those solving this challenge.)

This also explains why we found a seed for generating the reverted String,
because that is what was actually used. But instead of generating the 82
following characters as we did, we now need the preceeding 82 characters.

### Reversing the LCG  
The only thing left for us to do is to invert the LCG so that it outputs the
82 preceeding characters. StackOverflow to the rescue again!
(https://stackoverflow.com/questions/2911432/reversible-pseudo-random-
sequence-generator/16630535#16630535)

The answer explains that if we have a generator of the form `x = (a * prevx +
c) mod m` (which we have), the previous step can be calculated as `prevx =
ainverse * (x - c) mod m` where `ainverse = extEuclid(a, m).x`.

The `ainverse` is independent of the seed and for the Java RNG it is
`-35320271006875L`.

We just have to adapt the output as follows:  
```  
for(long s : solutions) {  
 long newSeed = s;

 for(int i = 0; i < 80; i++) {  
   newSeed = (reverseMultiplier * (newSeed - addend)) & mask;  
 }

 for(int i = 0; i < 100; i++) {  
   int bits, val;  
   do {  
     newSeed = (newSeed * multiplier + addend) & mask;  
     bits = (int)(newSeed >>> (48 - 31));  
     val = bits % choice;  
   } while(bits - val + (choice-1) < 0);  
   System.out.print(baseString.charAt(val));  
 }  
 System.out.println();  
}  
```

The generator first moves 80 steps back and then outputs 100 characters
including the 20 chars we already have. We also have to reverse the input
String and the output String.

Note that we no longer have 18 known and 82 unknown but now 20 known and 80
unknown characters. That is because the organizers accidentally shipped the
actual flag with the fixed application which another team used to get first
blood (although there was no bonus for first blood).

They changed the flag and generated a new API key now giving us those 20
characters: `"mRGB1yvTOpi8WGiDqIeb"`

For this our program yields
`"sEbRER9aii7xLBwJGRo6ilxe0ssAAmnVYZNQF8j7ITb6ndf1AMhOyTv380dwRaJajlOc4pzkNNuEui9RbeIqDiGW8ipOTvy1BGRm"`
which, when reverted, yields
`"mRGB1yvTOpi8WGiDqIebR9iuEuNNkzp4cOljaJaRwd083vTyOhMA1fdn6bTI7j8FQNZYVnmAAss0exli6oRGJwBLx7iia9RERbEs"`
as the API Key.

After submitting this to the service we got  
```  
[{'website': 'hctf.fun', 'password': 'flag{I_guess_ME_STUPID_ME_STUPID}'}]  
```  
which this time was the actual first blood and the only solve until the end of
the CTF. This flag is a reference to their mistake, the original flag was
`flag{I_guess_random_is_not_that_random}`.

Even with the mistake this was still a super fun (and informative) challenge.  

Original writeup (https://github.com/ldruschk/ctf-
writeups/blob/master/2018_pwnctf_pw-api.md).