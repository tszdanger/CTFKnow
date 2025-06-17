# string.equals(integer) (misc, 475p)

Pretty simple and stupid challenge - pure brute-force task.

We get
[code](https://raw.githubusercontent.com/TFNS/writeups/master/2020-04-12-ByteBanditsCTF/string_equals/chall.py)
and
[hashes.txt](https://raw.githubusercontent.com/TFNS/writeups/master/2020-04-12-ByteBanditsCTF/string_equals/hashes.txt),
and also [directory with random
data](https://github.com/TFNS/writeups/tree/master/2020-04-12-ByteBanditsCTF/string_equals/a).

The idea is pretty simple:

1. Everything is repeated 10000 times  
2. Random file is selected from the supplied data  
3. Random start and end index are selected in the file, with difference of at most 100  
4. Data from selected file with given range are extracted  
5. Two hash functions are calculated over the data  
6. Results are stored in the hashes file

Our goal is to calculate the two hash functions on the concatenation of all
the extracted data.  
So we need to use the hashes to figure our which data were used to calculate
them.  
There is nothing special, there are only 20 files, start index is between 1
and 1000 and end index is between 101 and 1100.  
We can just calculate all possible hash values for all possible data extracts.

One thing to consider is the hash functions:

```python  
def func1(s):  
   h = 0  
   for i in range(len(s)):  
       h += (ord(s[i]) - 96) * pow(31, i, mod)  
       h %= mod  
   return h

def func2(s):  
   h = 0  
   for i in range(len(s)):  
       h += (ord(s[i]) - 96) * pow(31, i, mod2)  
       h %= mod2  
   return h  
```

Both functions use `pow(31, i, mod)`, and we know that `i` has some very
limited range of 100, so we can calcualte this just once, to speed things up:

```python  
pows1 = [pow(31, i, mod) for i in range(105)]  
pows2 = [pow(31, i, mod2) for i in range(105)]

def func1(s):  
   h = 0  
   for i in range(len(s)):  
       h += (ord(s[i]) - 96) * pows1[i]  
       h %= mod  
   return h

def func2(s):  
   h = 0  
   for i in range(len(s)):  
       h += (ord(s[i]) - 96) * pows2[i]  
       h %= mod2  
   return h  
```

Now for each file we do:

```python  
def worker(x):  
   print(x)  
   file_data = open("a/" + str(x)).read()  
   memorized_hashes = {}  
   for a in range(1, 1001):  
       for b in range(a - 1, a + 101):  
           s1 = file_data[a - 1: b]  
           ha1 = func1(s1)  
           ha2 = func2(s1)  
           h = str(ha1) + " " + str(ha2)  
           memorized_hashes[h] = s1  
   return memorized_hashes  
```

We run this in parallel:

```python  
from crypto_commons.brute.brute import brute  
   maps = brute(worker, range(20), processes=6)  
   memorized_hashes = {}  
   for m in maps:  
       memorized_hashes.update(m)  
```

Now we can just go over the hashes.txt and get all the inputs from the map:

```python  
   expected_hashes = open("hashes.txt", 'r').readlines()  
   s = ""  
   for h in expected_hashes:  
       s1 = memorized_hashes[h.strip()]  
       s += s1  
```

Now the last thing to do is to calculate hash functions over this `s`.  
Here we need to use the original hash functions, because our memorized `pow`
values are only for short strings, but we finally get:
`flag{82806233047447860}`

[complete solver
here](https://raw.githubusercontent.com/TFNS/writeups/master/2020-04-12-ByteBanditsCTF/string_equals/solver.py)

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-04-12-ByteBanditsCTF/string_equals/README.md).