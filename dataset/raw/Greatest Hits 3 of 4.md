This is what we're given:

```  
flaglink="REDACTED"

def xor(msg, key):  
   o = ''  
   for i in range(len(msg)):  
       o += chr(ord(msg[i]) ^ ord(key[i % len(key)]))  
   return o

clue="https://gist.github.com/AndyNovo"  
import os  
key = os.urandom(len(clue))  
assert(flaglink.count(clue) > 0)

print(xor(flaglink, key).encode('hex'))  
#98edbf5c8dd29e9bbc57d0e2990e4e692efb81c2318c69c626d7ea42f2efc70fece4ae5c89c7999fef1e8bac99021d7266bc9cde3cd97b9a2adaeb08dea1ca0582eaac13ced7dfdbad1194b1c60f5d372eeec29832ca20d12a85b545f9f69b1aaeb6ec4cd4

```

So we're given an XOR encryption, and our biggest clue comes in this line of
code:

`assert(flaglink.count(clue) > 0)`

This basically means that the clue string is in the flaglink!

So how can we use this? Well, the clue has to be at some offset in the text.
If we can brute force that offset, we can get the original text.  
To brute force every offset, we need to do the following:

Loop through all offsets that the clue fits in  
Take the XOR of ciphertext[offset:offset + len(clue)]  
If this is the correct offset, this should be the used key... right?  
Not exactly. Take a look at the following example:

			Pos: 0 1 2 3 4 5 6 7 8 9  
			Key: - - - - 3 2 7 5 4 -  
			Key = 27543  
			Because the XOR encryption starts at index 0, the key might be somewhat shuffled around.  
			In this example, since the key was length 5, and the key was found at offset 4, it is necessary to take the last 4 bytes of the key and move them to the front.  
  
Therefore, we have to move the last [offset] bytes of the "key" we found to
the front to get the actual key  
Then, we can use do xor(ciphertext, key) and check if it has printable ascii
characters to get the link and get the flag!

	UDCTF{x0r_and_I_g0_w4y_back}

The implementation follows below.

```  
import binascii  
import string  
import os

def is_ascii(s): # GeeksForGeeks  
   """Return True if string s is ASCII, False otherwise."""  
   return all(c in string.printable for c in s)

def xor(msg, key):  
   o = ''  
   for i in range(len(msg)):  
       o += chr(msg[i] ^ ord(key[i % len(key)]))  
   return o

c =
"98edbf5c8dd29e9bbc57d0e2990e4e692efb81c2318c69c626d7ea42f2efc70fece4ae5c89c7999fef1e8bac99021d7266bc9cde3cd97b9a2adaeb08dea1ca0582eaac13ced7dfdbad1194b1c60f5d372eeec29832ca20d12a85b545f9f69b1aaeb6ec4cd4"  
clue="https://gist.github.com/AndyNovo"  
c = binascii.unhexlify(c)

'''  
Pos: 0 1 2 3 4 5 6 7 8 9  
Key: - - - - 3 2 7 5 4 -

Key = 27543  
'''

for offset in range(len(c) - len(clue)):  
   key = xor(c[offset:offset+len(clue)], clue)  
   #print("OLD:", bytes(key, 'utf-8'))  
   key = key[len(clue) - offset:] + key[:len(clue) - offset]  
   #print("NEW:", bytes(key, 'utf-8'))  
   m = xor(c, key)  
   #print(m)  
   if is_ascii(m):  
       print(m)  
```