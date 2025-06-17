#### Description:  
Shoutout to those people who think that base64 is proper encryption

#### main.py  
```python  
from Crypto.Util.number import long_to_bytes, bytes_to_long  
from gmpy2 import mpz, to_binary  
#from secret import flag, key

ALPHABET = bytearray(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ#")

def base_n_encode(bytes_in, base):  
	return mpz(bytes_to_long(bytes_in)).digits(base).upper().encode()

def base_n_decode(bytes_in, base):  
	bytes_out = to_binary(mpz(bytes_in, base=base))[:1:-1]  
	return bytes_out

def encrypt(bytes_in, key):  
	out = bytes_in  
	for i in key:  
		print(i)  
		out = base_n_encode(out, ALPHABET.index(i))  
	return out

def decrypt(bytes_in, key):  
	out = bytes_in  
	for i in key:  
		out = base_n_decode(out, ALPHABET.index(i))  
	return out

"""  
flag_enc = encrypt(flag, key)  
f = open("flag_enc", "wb")  
f.write(flag_enc)  
f.close()  
"""  
```

#### flag_enc  
The file can be found in the authors' repository:
[`flag_enc`](https://github.com/sigpwny/UIUCTF-2021-Public/blob/master/crypto/back_to_basics/public/flag_enc)

----

Let's look at the provided script:

As first step the alphabet of the key is defined:  
```python  
ALPHABET = bytearray(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ#")  
```

`base_n_encode` reads the bytes of the given string as one big integer and
expresses it in the given base.  
```python  
def base_n_encode(bytes_in, base):  
	return mpz(bytes_to_long(bytes_in)).digits(base).upper().encode()  
```

`base_n_decode` reads the string as string-representation of a big integer in
the given base and returns the binary representation of this integer.  
```python  
def base_n_decode(bytes_in, base):  
	bytes_out = to_binary(mpz(bytes_in, base=base))[:1:-1]  
	return bytes_out  
```

`encrypt` takes each char of the key and uses it as base for `base_n_encode`.
For getting an integer base, the char is searched in the above alphabet and
the position is used as base.  
```python  
def encrypt(bytes_in, key):  
	out = bytes_in  
	for i in key:  
		print(i)  
		out = base_n_encode(out, ALPHABET.index(i))  
	return out  
```

`decrypt` takes each char of the key and uses in the same way as in `encode`
for decoding the string with `base_n_decode`.  
```python  
def decrypt(bytes_in, key):  
	out = bytes_in  
	for i in key:  
		out = base_n_decode(out, ALPHABET.index(i))  
	return out  
```

Finally, there is a comment, which explains, how `flag_enc` was created:  
```python  
flag_enc = encrypt(flag, key)  
f = open("flag_enc", "wb")  
f.write(flag_enc)  
f.close()  
```

----

At the start some considerations:  
- `0` and `1` cannot be part of the string, as their indices in the alphabet (`0` & `1`) are no bases  
- The base of the encrypted text will always be greater than each char in the text, as all characters in a string with base `b` are from interval `[0, b-1]`

With this knowledge, we can start the decryption. First we need to load the
encrypted flag:  
```python  
with open("flag_enc", "rb") as f:  
	out = f.read()  
```

For debug purposes we initialize some variables:  
```python  
round = 0  
key = ""  
```

As we don't know when we are done, we first loop infinitely. Furthermore we
want to keep our debug variable up to date.  
```python  
while True:  
	round += 1  
```

First we determine the alphabet of the current string:  
```python  
	alphabet = set(out)  
```

We only need the maximum for determining the smallest possible base. And again
some debug printing.  
```python  
	m = max(alphabet)  
	print("{}: used {}, {}".format(round, m, alphabet))  
```

Let's get the smallest base. If the char is not found, the script will fail at
this point with an error.  
```python  
	b = ALPHABET.index(m) + 1  
```

Now we can determine whether the calculated base is in range.  
```python  
	if b >= len(ALPHABET):  
		print("no")  
		exit(1)  
```

Now we can test for all possible bases and collect possible indices  
```python  
	indices = list()  
	for i in range(b, len(ALPHABET)):  
```

As the decryption can fail, and we don't want the script to be aborted, we
have to wrap it in `try`. And again some debug printing.  
```python  
		try:  
			new_out = base_n_decode(out, i)  
			print(max(new_out), min(new_out))  
```

As `#` cannot be in the string and as the chars build a continues block in
ASCII, we can simply check the boundaries to determine whether the decrypted
string matches our requirements and the index is a candidate:  
```python  
			if max(new_out) <= 90 and min(new_out) >= 48:  
				indices.append(i)  
```

Because the flag will have some additional chars outside this range, we also
check if the decrypted string is a potential flag. For preventing spam, we
also check the length and hope, that the flag is shorter than 100 chars. If
not, we have to adjust the length.  
```python  
			if max(new_out) <= 125 and min(new_out) >= 48 and len(out) < 100:  
				print(f"key: {key + chr(ALPHABET[i])}, possible flag: {new_out}")  
```

If the decryption fails, we don't want to do something. As python requires a
statement in except, we do some useless assignment.  
```python  
		except:  
			log = 1  
```

For proceeding, we need an index. Let's exit, if we haven't found one.  
```python  
	if len(indices) < 1:  
		print("no")  
		exit(1)  
```

Now we must select the index for the next round. As it is unlikely that the
base is much higher than the maximum char in the string, we use the smallest
working base. As we haven't stored the decrypted string, we have to decrypt it
again. Furthermore we append the used character from the alphabet to the key.
And again some debug printing.  
```python  
	out = base_n_decode(out, indices[0])  
	key += chr(ALPHABET[indices[0]])  
	print(key)  
	print(indices)  
	print(f"{round}: used {chr(ALPHABET[b])}, len: {len(out)}")  
```

The whole script looks as following:  
```python  
from Crypto.Util.number import long_to_bytes, bytes_to_long  
from gmpy2 import mpz, to_binary  
#from secret import flag, key

ALPHABET = bytearray(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ#")

def base_n_encode(bytes_in, base):  
	return mpz(bytes_to_long(bytes_in)).digits(base).upper().encode()

def base_n_decode(bytes_in, base):  
	bytes_out = to_binary(mpz(bytes_in, base=base))[:1:-1]  
	return bytes_out

def encrypt(bytes_in, key):  
	out = bytes_in  
	for i in key:  
		print(i)  
		out = base_n_encode(out, ALPHABET.index(i))  
	return out

def decrypt(bytes_in, key):  
	out = bytes_in  
	for i in key:  
		out = base_n_decode(out, ALPHABET.index(i))  
	return out

with open("flag_enc", "rb") as f:  
	out = f.read()

round = 0  
key = ""  
while True:  
	round += 1  
	alphabet = set(out)  
	m = max(alphabet)  
	print("{}: used {}, {}".format(round, m, alphabet))  
	b = ALPHABET.index(m) + 1  
	if b >= len(ALPHABET):  
		print("no")  
		exit(1)  
	indices = list()  
	for i in range(b, len(ALPHABET)):  
		try:  
			new_out = base_n_decode(out, i)  
			print(max(new_out), min(new_out))  
			if max(new_out) <= 90 and min(new_out) >= 48:  
				indices.append(i)  
			if max(new_out) <= 125 and min(new_out) >= 48 and len(new_out) < 100:  
				print(f"key: {key + chr(ALPHABET[i])}, possible flag: {new_out}")  
		except:  
			log = 1  
	if len(indices) < 1:  
		print("no")  
		exit(1)  
	out = base_n_decode(out, indices[0])  
	key += chr(ALPHABET[indices[0]])  
	print(key)  
	print(indices)  
	print(f"{round}: used {chr(ALPHABET[b])}, len: {len(out)}")  
```

In the output we find the flag (`b'uiuctf{r4DixAL}'`) and the corresponding
key (`WM5Z8CRJABXJDJ5W`).

Original writeup (https://ctf0.de/posts/uiuctf2021-back-to-basics/).