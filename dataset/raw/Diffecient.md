# [SekaiCTF 2022] Diffecient

## tl;dr

Find a hash collision for a bloom filter using
[MurmurHash3](https://en.wikipedia.org/wiki/MurmurHash) aka mmh3.  
I got first blood on the challenge by being too lazy to do cryptanalysis and
instead using the powers of OSINT to find an existing solutions coded by real
cryptographers.

## Description

crypto/Diffecient; 7 solves, 498 points

Challenge author: `deut-erium`

Welcome to the Diffecient Security Key Database API, for securely and
efficiently saving tons of long security keys! Feel free to query your
security keys, and pay a little to add your own to our state-of-the-art
database.

We trust our product so much that we even save our own keys here!

Source code:

```python  
import math  
import random  
import re  
import mmh3

def randbytes(n): return bytes ([random.randint(0,255) for i in range(n)])

class BloomFilter:  
   def __init__(self, m, k, hash_func=mmh3.hash):  
       self.__m = m  
       self.__k = k  
       self.__i = 0  
       self.__digests = set()  
       self.hash = hash_func

   def security(self):  
       false_positive = pow(  
           1 - pow(math.e, -self.__k * self.__i / self.__m), self.__k)  
       try:  
           return int(1 / false_positive).bit_length()  
       except (ZeroDivisionError, OverflowError):  
           return float('inf')

   def _add(self, item):  
       self.__i += 1  
       for i in range(self.__k):  
           self.__digests.add(self.hash(item, i) % self.__m)

   def check(self, item):  
       return all(self.hash(item, i) % self.__m in self.__digests  
                  for i in range(self.__k))

   def num_passwords(self):  
       return self.__i

   def memory_consumption(self):  
       return 4*len(self.__digests)

class PasswordDB(BloomFilter):  
   def __init__(self, m, k, security, hash_func=mmh3.hash):  
       super().__init__(m, k, hash_func)  
       self.add_keys(security)  
       self.addition_quota = 1  
       self.added_keys = set()

   def add_keys(self, thresh_security):  
       while self.security() > thresh_security:  
           self._add(randbytes(256))  
       print("Added {} security keys to DB".format(self.num_passwords()))  
       print("Original size of keys {} KB vs {} KB in DB".format(  
           self.num_passwords()//4, self.memory_consumption()//1024))

   def check_admin(self, key):  
       if not re.match(b".{32,}", key):  
           print("Admin key should be atleast 32 characters long")  
           return False  
       if not re.match(b"(?=.*[a-z])", key):  
           print("Admin key should contain atleast 1 lowercase character")  
           return False  
       if not re.match(b"(?=.*[A-Z])", key):  
           print("Admin key should contain atleast 1 uppercase character")  
           return False  
       if not re.match(br"(?=.*\d)", key):  
           print("Admin key should contain atleast 1 digit character")  
           return False  
       if not re.match(br"(?=.*\W)", key):  
           print("Admin key should contain atleast 1 special character")  
           return False  
       if key in self.added_keys:  
           print("Admin account restricted for free tier")  
           return False  
       return self.check(key)

   def query_db(self, key):  
       if self.check(key):  
           print("Key present in DB")  
       else:  
           print("Key not present in DB")

   def add_sample(self, key):  
       if self.addition_quota > 0:  
           self._add(key)  
           self.added_keys.add(key)  
           self.addition_quota -= 1  
           print("key added successfully to DB")  
       else:  
           print("API quota exceeded")

BANNER = r"""  
____  ____  ____  ____  ____  ___  ____  ____  _  _  ____  
(  _ \(_  _)( ___)( ___)( ___)/ __)(_  _)( ___)( \( )(_  _)  
)(_) )_)(_  )__)  )__)  )__)( (__  _)(_  )__)  )  (   )(  
(____/(____)(__)  (__)  (____)\___)(____)(____)(_)\_) (__)

Welcome to diffecient security key database API for securely  
and efficiently saving tonnes of long security keys!  
Feel FREE to query your security keys and pay a little to  
add your own security keys to our state of the art DB!  
We trust our product so much that we even save our own keys here  
"""  
print(BANNER)  
PASSWORD_DB = PasswordDB(2**32 - 5, 47, 768, mmh3.hash)  
while True:  
   try:  
       option = int(input("Enter API option:\n"))  
       if option == 1:  
           key = bytes.fromhex(input("Enter key in hex\n"))  
           PASSWORD_DB.query_db(key)  
       elif option == 2:  
           key = bytes.fromhex(input("Enter key in hex\n"))  
           PASSWORD_DB.add_sample(key)  
       elif option == 3:  
           key = bytes.fromhex(input("Enter key in hex\n"))  
           if PASSWORD_DB.check_admin(key):  
               from flag import flag  
               print(flag)  
           else:  
               print("No Admin no flag")  
       elif option == 4:  
           exit(0)  
   except:  
       print("Something wrong happened")  
       exit(1)  
```

## First impressions of the problem

We're given a bunch of code that implements a password database that stores
passwords  
using [MurmurHash3](https://en.wikipedia.org/wiki/MurmurHash) in a [bloom
filter](https://en.wikipedia.org/wiki/Bloom_filter).  
The exact way insertions into the bloom filter is done is with:  
```python  
   def _add(self, item):  
       self.__i += 1  
       for i in range(self.__k):  
           self.__digests.add(self.hash(item, i) % self.__m)  
```  
The bloom filter calls MurmurHash3 47 times with the second parameter being
the seed (in this case the seeds are 0 to 46).

We're allowed to add exactly one thing to the bloom filter.  
We can also check if a password is in the bloom filter, if it is, we get the
flag!  
However, we need to make sure we pass the `check_admin` function to do so:  
```python  
   def check_admin(self, key):  
       if not re.match(b".{32,}", key):  
           print("Admin key should be atleast 32 characters long")  
           return False  
       if not re.match(b"(?=.*[a-z])", key):  
           print("Admin key should contain atleast 1 lowercase character")  
           return False  
       if not re.match(b"(?=.*[A-Z])", key):  
           print("Admin key should contain atleast 1 uppercase character")  
           return False  
       if not re.match(br"(?=.*\d)", key):  
           print("Admin key should contain atleast 1 digit character")  
           return False  
       if not re.match(br"(?=.*\W)", key):  
           print("Admin key should contain atleast 1 special character")  
           return False  
       if key in self.added_keys:  
           print("Admin account restricted for free tier")  
           return False  
       return self.check(key)  
```

The `check_admin` function ensures the password is 32 characters long, and
contains some characters, and  
that we didn't add the key ourself.  
Due to the nature of the hashing usages,  
if we add a password and find another password hashing to the same value (aka
a hash collision),  
we wouldn't have added the key ourselves, and it would be "in the database"
according to the  
bloom filter. So our goal from now is to just find a hash collisions for the
first 47 hashes in the bloom filter.

## Playing with hash collisions

The first thing we can do is play around with hashes to see if we can find a
simple hash collision in the bloom filter.

Very quickly, after playing around with some zero bytes, I find one:

```python  
import mmh3  
import re

def check_admin(key):  
   if not re.match(b".{32,}", key):  
       print("Admin key should be atleast 32 characters long")  
       return False  
   if not re.match(b"(?=.*[a-z])", key):  
       print("Admin key should contain atleast 1 lowercase character")  
       return False  
   if not re.match(b"(?=.*[A-Z])", key):  
       print("Admin key should contain atleast 1 uppercase character")  
       return False  
   if not re.match(br"(?=.*\d)", key):  
       print("Admin key should contain atleast 1 digit character")  
       return False  
   if not re.match(br"(?=.*\W)", key):  
       print("Admin key should contain atleast 1 special character")  
       return False  
   return True

S = set()  
a = '0000'  
b = '000000'  
print(a, b)  
for i in range(47):  
   S.add(mmh3.hash(bytes.fromhex(a),i))

for i in range(47):  
   S.add(mmh3.hash(bytes.fromhex(b),i))  
print(len(S))  
print(check_admin(bytes.fromhex(a)))  
print(check_admin(bytes.fromhex(b)))  
```

The hashes aren't actually colliding for the same seeds, but are colliding at
different seeds in a way that somehow works.  
Unfortunately, this doesn't really help, both passwords clearly fails
`check_admin`  for obvious reasons.  
Furthermore, it isn't clear how we can extend this collision into a longer and
fulfil all the conditions of length and character content.

Back to the drawing board, I decided to do some OSINT.

## OSINT about hash collisions

The best place to start any search is on Wikipedia,  
so I begin with the [Wikipedia page on
MurmurHash](https://en.wikipedia.org/wiki/MurmurHash).  
Reading through, I notice a section on [Vulnerabilities of
MurmurHash](https://en.wikipedia.org/wiki/MurmurHash#Vulnerabilities).  
The page mentions a collision attack found by two cryptographers Jean-Philippe
Aumasson and Daniel J. Bernstein  
where even randomized seeds were vulnerable. This is great, since if it works
for random seeds, it basically means that it would work for "most" seeds,
including the seeds from 0 to 46.

The wikipedia lists a single citation to [a blog by Martin Boßlet from
2012](https://emboss.github.io/blog/2012/12/14/breaking-murmur-hash-flooding-
dos-reloaded/)  
where he provides a ruby script, and lists some hash collisions.  
Unfortunately, its for MurmurHash2, which is different, and his collisions
don't work for MurmurHash3.  
The blog said similar techniques are possible, but I don't feel like (or
really know how to) perform cryptanalysis to do something similar.

We're not completely out of luck as the blog mentions results Aumasson and
Bernstein "completely breaking" MurmurHash3 by finding multicollision hashes
and providing implementations of it at the following URL:
[https://131002.net/siphash/#at](https://131002.net/siphash/#at). Following
the URL unfortuantely redirects to the [homepage of JP
Aumasson](https://www.aumasson.jp/#at), and clicking the SipHash link on his
homepage just goes to the Wikipedia page for SipHash.  
It seemed like Aumasson must have reorganized his web pages, so we're out of
luck here.

Or are we? Good thing the [Internet Archive](https://archive.org/web/) exists,
we'll just use the Wayback Machine to travel back in time before he
reorganized his web page (assuming the page at some point got a lot of
traffic).  
Fortunately for us it got [lots of traffic in
2018](https://web.archive.org/web/20180401000000*/131002.net/siphash) and
sporadically in other years. On the website he provides some [C++ code to find
universal (key-independent) hash
collisions](https://web.archive.org/web/20180901061338/https://131002.net/siphash/murmur3collisions-20120827.tar.gz),
which is exactly what I want.

After downloading and untarring, I inspected the source code and am greeted
with the following comment:  
```c++  
/*  
* multicollisions for MurmurHash3  
*  
* MurmurHash3 C++ implementation is available at   
* http://code.google.com/p/smhasher/wiki/MurmurHash3  
*  
* the function Murmur3Multicollisions finds many different inputs  
* hashing to the same 32-bit value (multicollision)  
*   
* example output:  
* 32-bit seed 7a0e823a  
* 4-multicollision  
* 16-byte inputs  
* MurmurHash3_x86_32( bdd0c04b5c3995827482773b12acab35 ) = 94d7cf1b  
* MurmurHash3_x86_32( 652fa0565c3946be7482773b12acab35 ) = 94d7cf1b  
* MurmurHash3_x86_32( bdd0c04b5c399582cc23983012ac5c71 ) = 94d7cf1b  
* MurmurHash3_x86_32( 652fa0565c3946becc23983012ac5c71 ) = 94d7cf1b  
*  
* the multicollisions found are "universal": they work for any seed/key  
*  
* authors:  
* Jean-Philippe Aumasson, Daniel J. Bernstein  
*/  
```

Huh, so they provide some example 16-byte input that cause hash collisions.
However we need 32-byte collisions.  
The natural next step was to look through the code to try to see if I can
easily change some parameter in their code to change it to 32-byte collisions
(it looks like it would be trivial to, but I never even bothered running their
code).  
Instead I figure I'd try to see if the 16-byte collisions they found extended
to 32-byte ones, by just doubling them (adding a copy of themselves to the
end).  
This might be a strange thing to try, but these sorts of hashes that shift
bits around are usually very amenable to  
length extension type attacks, so it seemed to be a reasonable thing to try.  
```python  
S = set()  
a = 'bdd0c04b5c3995827482773b12acab35'  
b = '652fa0565c3946be7482773b12acab35'  
a = a+a  
b = b+b  
print(a)  
print(b)  
for i in range(47):  
   S.add(mmh3.hash(bytes.fromhex(a),i))

for i in range(47):  
   S.add(mmh3.hash(bytes.fromhex(b),i))  
print(len(S))  
print(check_admin(bytes.fromhex(a)))  
print(check_admin(bytes.fromhex(b)))  
```

The output was:  
```  
bdd0c04b5c3995827482773b12acab35bdd0c04b5c3995827482773b12acab35  
652fa0565c3946be7482773b12acab35652fa0565c3946be7482773b12acab35  
47  
True  
True  
```

Wow, it just worked somehow!  
It consisted of some random bytes, so it's not surprising it passed all the
other checks,  
but the fact that it hashes to the same values is surprising.  
So I just plugged it into the program and out popped the flag:

```

____  ____  ____  ____  ____  ___  ____  ____  _  _  ____  
(  _ \(_  _)( ___)( ___)( ___)/ __)(_  _)( ___)( \( )(_  _)  
)(_) )_)(_  )__)  )__)  )__)( (__  _)(_  )__)  )  (   )(  
(____/(____)(__)  (__)  (____)\___)(____)(____)(_)\_) (__)

Welcome to diffecient security key database API for securely  
and efficiently saving tonnes of long security keys!  
Feel FREE to query your security keys and pay a little to  
add your own security keys to our state of the art DB!  
We trust our product so much that we even save our own keys here

Added 1102 security keys to DB  
Original size of keys 275 KB vs 202 KB in DB  
Enter API option:  
2  
Enter key in hex  
bdd0c04b5c3995827482773b12acab35bdd0c04b5c3995827482773b12acab35  
key added successfully to DB  
Enter API option:  
3  
Enter key in hex  
652fa0565c3946be7482773b12acab35652fa0565c3946be7482773b12acab35  
b'SEKAI{56f066a1b13fd350ac4a4889efe22cb1825651843e9d0ccae0f87844d1d65190}'  
```

Neato, I solved (and in fact got first blood) on a cryptography challenge
without doing any of my own cryptanalysis, writing any real code, or even
running any real code.  

Original writeup (https://davidzheng.web.illinois.edu/2022/10/03/sekaictf-
diffecient.html).