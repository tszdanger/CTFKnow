# Follow the Currents - angstromCTF 2021

- Category: Crypto  
- Points: 70  
- Solves: 271

## Description

go with the flow...

Author: lamchcl

## Solution

We are given an encrypted string and the script used to encrypt it.

As we can see from the source, it uses a keystream-like cipher which at the
beginning generates two random bytes and creates the following ones with a
deterministic function that takes the previous bytes of the key as input. This
keystream is xored with the key.

```python  
def keystream():  
	key = os.urandom(2)  
	index = 0  
	while 1:  
		index+=1  
		if index >= len(key):  
			key += zlib.crc32(key).to_bytes(4,'big')  
		yield key[index]  
```

The real problem is to find the first two bytes, after that we can deduce the
following ones. Since it is only two bytes, we can brute-force them and
generate the keystream for every possible combination. With one of them we
obtained the string `Flag: there are like 30 minutes left before the ctf
starts so i have no idea what to put here other than the flag which is
actf{low_entropy_keystream}`

```python  
for p in product(range(256), repeat=2):  
   key = bytearray(p)

   k = keystream(key)  
   plain = decrypt(k)

   plaintext = [chr(c) for c in plain]  
   if "actf{" in "".join(plaintext):  
       print("".join(plaintext))  
```

**Full script in
https://github.com/r00tstici/writeups/blob/master/angstromCTF_2021/follow_the_currents/exploit.py**  

Original writeup
(https://github.com/r00tstici/writeups/tree/master/angstromCTF_2021/follow_the_currents).