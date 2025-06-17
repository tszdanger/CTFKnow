# Challenge Description  
Baby MD5  
Your mission is to find weird hash collision!

nc 66.172.10.203 2570

# Solution  
The challenge is split into two parts, the first is a proof-of-worth (PoW) and
the second is the actual challenge  
Booth parts are about getting partial hash collisions and by that I mean (4-6)
hex digits of the hash are the same

## PoW  
You are asked to provide a printable string with a defined length that when
hashed with a hash function (that is defined in the question); will have the
requested 6 hex digits at the end of the hash

Example: Please submit a printable string X, such that sha1(X)[-6:] = 5f4774
and len(X) = 32

options for hash functions are SHA1, SHA224, SHA256, SHA384, SHA512, MD5 and
may be others that I didn't see

### How to solve?  
Generating random strings(or a padded counter string) with the requested
length and testing if thier hash matches the required digits is actually
possible since the search space is only 6 hex digits  
Something like this in a loop could work  
```python  
  new_str = ''.join(random.choice(string.ascii_letters) for _ in
range(length)) # f'{counter}'.rjust(length, '0')  
  new_hash_seg = f(new_str) # f is your hash function  
```

Another faster solution is to use existing rainbow tables for hash functions
that are pre-computed to get a string that matches the request but we didn't
end up going for this solution

You get something like this (using a counter and padding it with zeros as this
turned out faster than random strings):  
string = 00000000000000000000000000350390  
hash = 1807a375245bada596041dea0851b0260d5f4774

## Actual challenge  
You are asked to provide a pair of strings that will result True in a given
function (babymd5) which just checks the two strings to make sure they meet
certain conditions.  
The conditions are that they have a pre-defined prefixes (one of them is the
word 'dead'), and also that after repeatedly hashing them using MD5 they will
provide the same hash

```python  
def babymd5(m, n, x_head, y_head, x, y):  
 if x.startswith(x_head) and y.startswith(y_head):  
   for _ in range(m):  
     xhash = md5(x.encode('utf-8')).hexdigest()  
     x = xhash  
   for _ in range(n):  
     yhash = md5(y.encode('utf-8')).hexdigest()  
     y = yhash  
   if xhash == yhash:  
     return True  
return False  
```  
Where you are given m, n, x_head and y_head = 'dead' and you are asked to
produce x and y  
Example: (m, n, x_head, y_head) = (195, 5, 'HLX', 'dead')

### How to solve? (We actually didn't solve this part during the competition)  
The solution depends on the fact that the word 'dead' is a valid start of a
hex digest and m > n, and since the babymd5 function repetadly performs the
hash on x;  
then all what we need is a string x that starts with the given x_head and that
hashes to a hash that starts with the digits 'dead' after the right amount of
times and then we use the resulting hash as our string y

Something like this in a loop will work:

```python  
  possible_x = x_head + ''.join(random.choice(string.ascii_letters) for _ in
range(length)) # f'{x_head}{counter}'.ljust(length, '0')  
  x_hash = possible_x  
  for _ in range(m-n):  
      x_hash = md5(x_hash.encode('utf-8')).hexdigest()  
  if x_hash.startswith('dead')  
   y = x_hash  
   x = possible_x  
   break  
```  
the length should be a valid length for md5 hash for the y string, but isn't
restricted for the x string but a good strategy since it isn't restricted is
to just use the same length

You actually need to be lucky for the PoW since the server can disconnect and
you will need to start over(or you can get a slow hashing function like
sha512), but for the actual challenge you can hold the connection by
periodically asking for the conditions

x = HLX52570000000000000000000000000 , y = dead8ff641a3d0853e9753ca3f98fb55

Flag: ASIS{MD5_c0L1iD!N9_iZ_4pProX1mA73lY_1.47*10^-29}

For a sample of the actual exploit code: check the original writeup

Original writeup (https://github.com/TalaatHarb/ctf-
writeups/tree/main/asisctf2020/babymd5).