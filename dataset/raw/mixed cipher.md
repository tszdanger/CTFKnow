# mixed cipher (233 points/ 39 solves)  
## Problem statement:  
>I heard bulldozer is on this channel, be careful!  
  
>nc crypto.chal.ctf.westerns.tokyo 5643  
  
>[server.py](https://github.com/GabiTulba/Tokyo-Westerns-2018-Mixed-Cipher-
Crypto-Write-up/blob/master/server.py)  
  
  

## My opinion:  
This problem is at the moment my favourite RSA problem, I had a lot of fun
solving it and I learned a new RSA attack and found a tool for breaking
python's random.  
  

## The problem:  
We are given a python script and a port where it runs:  
  
```python  
from Crypto.PublicKey import RSA  
from Crypto.Cipher import AES  
from Crypto.Util.number import long_to_bytes

import random  
import signal  
import os  
import sys

sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)  
privkey = RSA.generate(1024)  
pubkey = privkey.publickey()  
flag = open('./flag').read().strip()  
aeskey = os.urandom(16)  
BLOCK_SIZE = 16

def pad(s):  
   n = 16 - len(s)%16  
   return s + chr(n)*n

def unpad(s):  
   n = ord(s[-1])  
   return s[:-n]

def aes_encrypt(s):  
   iv = long_to_bytes(random.getrandbits(BLOCK_SIZE*8), 16)  
   aes = AES.new(aeskey, AES.MODE_CBC, iv)  
   return iv + aes.encrypt(pad(s))

def aes_decrypt(s):  
   iv = s[:BLOCK_SIZE]  
   aes = AES.new(aeskey, AES.MODE_CBC, iv)  
   return unpad(aes.decrypt(s[BLOCK_SIZE:]))

def bulldozer(s):  
   s = bytearray(s)  
   print('Bulldozer is coming!')  
   for idx in range(len(s) - 1):  
       s[idx] = '#'  
   return str(s)

def encrypt():  
   p = raw_input('input plain text: ').strip()  
   print('RSA: {}'.format(pubkey.encrypt(p, 0)[0].encode('hex')))  
   print('AES: {}'.format(aes_encrypt(p).encode('hex')))

def decrypt():  
   c = raw_input('input hexencoded cipher text: ').strip().decode('hex')  
   print('RSA: {}'.format(bulldozer(privkey.decrypt(c)).encode('hex')))

def print_flag():  
   print('here is encrypted flag :)')  
   p = flag  
   print('another bulldozer is coming!')  
   print(('#'*BLOCK_SIZE+aes_encrypt(p)[BLOCK_SIZE:]).encode('hex'))

def print_key():  
   print('here is encrypted key :)')  
   p = aeskey  
   c = pubkey.encrypt(p, 0)[0]  
   print(c.encode('hex'))

signal.alarm(300)  
while True:  
   print("""Welcome to mixed cipher :)  
I heard bulldozer is on this channel, be careful!  
1: encrypt  
2: decrypt  
3: get encrypted flag  
4: get encrypted key""")  
   n = int(raw_input())

   menu = {  
       1: encrypt,  
       2: decrypt,  
       3: print_flag,  
       4: print_key,  
   }

   if n not in menu:  
       print('bye :)')  
       exit()  
   menu[n]()  
```  
  
  
It's a lot of code to digest so let's start:

We have 4 options, `encrypt` which is an encryption oracle for both
[RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) and
[AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard), `decrypt`
which is a decryption oracle for RSA, but we only get the last byte, `get
encrypted flag` which returns the flag encrypted with AES but we won't get the
IV and finally `get encrypted key` which returns the AES key, encrypted with
RSA.  
  
  
  
Now let's analyse the 2 enryptions. Both of them are done using python's
Crypto library, and both are generated each time we connect to the netcat so
we have to solve everything in one go.  
  
For RSA we know `e=65537` since it is the standard value when using
`RSA.generate()` and we know that `n` has `1024` bits. For AES we know that
the `key` is generated using `os.urandom(16)` so that's cryptographically
secure, and the encryption uses CBC mode with random IV. The IV is generated
using `random.getrandbits(128)`. Python's random library is an implementation
of a [Marsenne Twister](https://en.wikipedia.org/wiki/Mersenne_Twister), so we
can get the internal state of the PRNG using this tool
[randcrack](https://github.com/tna0y/Python-random-module-cracker), you'll see
in my code that we need only 156 (624/4) queries to get the internal state. Ok
so we can get the `IV` for `get encrypted flag` let's see how to get the
`key`.  
  

After a bit of googleing I found an article about [RSA LSB decryption
oracle](https://crypto.stackexchange.com/questions/11053/rsa-least-
significant-bit-oracle-attack). Long story short, we can do a binary search in
order to get the `key` (for more details read the article it's pretty easy to
understand). So after 1024 queries we can get the `key`, but that would cause
a timeout because the connection is closed after 300 seconds
(`signal.alarm(300)`). but we can optimise our attack, we know that the `key`
is 128 bits so the first 896 iterations of the search will always return an
even bit and therefore we can simulate it without needing to communicate with
the server, also another optimization is that when the interval left is
smaller that 256 we can get the `key` because we know the last byte of the
`key`. So in total there are about 120 queries that have to be done.  
  
  
  
Next, In order to do the LSB attack we need to know `n` for the RSA, this
isn't too hard to do. We know that `m^e = c mod n` which is equivalent to `m^e
-c = n*k` so by geting a few values using the RSA encryption oracle we get
different values of `k` let's call them `k_i`, if we do `gcd(n*k_i)` until we
are left with a 1024 bit number we retrieve `n`. `n` is found after 2-4 such
queries.  
  
  
  
So to solve the problem step by step:  
 1. Get `n` using the RSA encryption oracle and gcd. (2-4 queries)  
 2. Get the AES `key` using the RSA LSB decryption oracle. (120 queries)  
 3. Get the `IV` by exploiting random's Marsenne Twister. (156 queries)  
 4. decrypt the AES encrypted **flag**.  
  
  
  
Total number of queries: ~280 which suffices the time constraint.  
  
## The code:

The following code is the exploit described above:  
  
```python  
from Crypto.Cipher import AES  
from Crypto.Util.number import long_to_bytes  
from randcrack import RandCrack  
from libnum.ranges import Ranges  
from Crypto.Util.number import inverse  
from pwn import *  
rem = remote('crypto.chal.ctf.westerns.tokyo', 5643)  
e = 65537  
rng=Ranges()  
key=0

def pad(x):  
	if(len(x)%2):  
		return '0'+x  
	else: return x

def oracle(CT):  
	rem.sendline('2')  
	rem.sendlineafter('input hexencoded cipher text:',pad(hex(CT)[2:].strip('L')))  
	rem.recvuntil('RSA: ')  
	PT=int(rem.recvline().strip('\n'),16)  
	#print PT	  
	return PT%2

def spec_oracle(CT):  
	rem.sendline('2')  
	rem.sendlineafter('input hexencoded cipher text:',pad(hex(CT)[2:].strip('L')))  
	rem.recvuntil('RSA: ')  
	PT=int(rem.recvline().strip('\n'),16)  
	#print PT	  
	return PT%256

def get_aeskey():  
	rng=Ranges((0,n-1))  
	rem.sendline('4')  
	rem.recvuntil('here is encrypted key :)\n')  
	C= int(rem.recvline().strip('\n'),16)  
	C2=C  
	end=spec_oracle(C)  
	p2=pow(2,e,n)  
	C=p2*C%n  
	a,b=(0,n-1)  
	for i in range(1024-128):  
		b=(a+b)/2  
		C=p2*C%n  
	rng=Ranges((a,b))  
	while(rng.len>256):  
		a,b=rng.segments[0]  
		c=(a+b)/2  
		if(oracle(C)):  
			rng=Ranges((c,b))  
		else: rng=Ranges((a,c))		  
		C=C*p2%n  
  
	for x in rng:  
		if(x%256==end):  
			key=x  
	return key

def get_IV():  
	rem.sendline('1')  
	rem.sendlineafter('input plain text: ','')  
	rem.recvuntil('AES: ')  
	x=int(rem.recvline().strip('\n')[:32],16)  
	return x

def get_encflag():  
	rem.sendline('3')  
	rem.recvuntil('another bulldozer is coming!\n')  
	x=int(rem.recvline().strip('\n')[32:],16)  
	return x

def get_aesIV():  
	rc=RandCrack()  
	for i in range(156):  
		x=get_IV()  
		for j in range(4):  
			rc.submit(x%(2**32))  
			x=x>>32  
	return rc

def gcd(a,b):  
   while b!=0:  
       r=a%b  
       a=b  
       b=r  
   return  a

def unpad(s):  
   n = ord(s[-1])  
   return s[:-n]

def decrypt(key,iv,ct):  
   iv = long_to_bytes(iv)  
   key = long_to_bytes(key)  
   ct = long_to_bytes(ct)  
   aes = AES.new(key, AES.MODE_CBC, iv)  
   return unpad(aes.decrypt(ct))

def testn():  
	x=pow(2,e,n)  
	rem.sendline('1')  
	rem.sendlineafter('input plain text: ','\x02')  
	d=int(rem.recvline().strip().split()[-1],16)  
	if(d==x):  
		print "Hah! I got your N.\n\nN =",n,'\n\n'

def testkey():  
	rem.sendline('4')  
	rem.recvuntil('here is encrypted key :)\n')  
	x= int(rem.recvline().strip('\n'),16)

	rem.sendline('1')  
	rem.sendlineafter('input plain text: ',pad(hex(key)[2:]).decode('hex'))  
	d=int(rem.recvline().strip().split()[-1],16)  
	if(d==x):  
		print "Hah! I got your key.\n\nkey =",key,'\n\n'

def testIV():  
	x=get_IV()  
	if(R.predict_getrandbits(128)==x):  
		print 'Hah! I got your IV.\n\n'

rem.sendline('1')  
rem.sendlineafter('input plain text: ','\x02')  
d=rem.recvline().strip().split()[-1]  
n=2**e-int(d,16)  
i=3  
while(len(bin(n)[2:])>1024):  
	rem.sendline('1')  
	rem.sendlineafter('input plain text: ',chr(i))  
	d=rem.recvline().strip().split()[-1]  
	n=gcd(n,i**e-int(d,16))  
	i+=1

print "They see me rollin\'...\n"

testn()

key=get_aeskey()

testkey()

R=get_aesIV()

testIV()  
IV=R.predict_getrandbits(128)

enc=get_encflag()  
x=decrypt(key,IV,enc)  
print "Hah! I got your flag!!\n\n",x[x.find("TWCTF{"):],"\n\nThey hatin\'\n"  
```

## Finding the flag:  
  
  
After waiting a few minutes we get the flag:  
  

```

They see me rollin'...

Hah! I got your N.

N =
97296189225320520759310958901821318292941159071085302914570733037137301719802813543486312696205327547219060061779826729810679035724168274702856628147899971638856634150039817679793101473904012675800251390984372484702190944861703601376318295830231309442524950273952340675847708845952520591445075232356247060953

Hah! I got your key.

key = 74841390274395365187087351403508275949

Hah! I got your IV.

Hah! I got your flag!!

TWCTF{L#B_de#r#pti#n_ora#le_c9630b129769330c9498858830f306d9}

They hatin'

```

  
  
  
Flag: **TWCTF{L#B_de#r#pti#n_ora#le_c9630b129769330c9498858830f306d9}**  

Original writeup (https://github.com/GabiTulba/Tokyo-Westerns-2018-Mixed-
Cipher-Crypto-Write-up/blob/master/README.md).