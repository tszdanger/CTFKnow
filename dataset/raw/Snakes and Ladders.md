# Snakes and Ladders

## Description

```  
The flag is fqtbjfub4uj_0_d00151a52523e510f3e50521814141c. The attached file
may be useful.  
```

Category: Reversing

## Analysis

Let's see what's in `main.py`:

```python  
def xor(s1,s2):  
   return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))

def encrypt(a):  
   some_text = a[::2]

   randnum = 14  
   text_length = len(some_text)  
   endtext = ""  
   for i in range(1, text_length + 1):  
     weirdtext = some_text[i - 1]  
     if weirdtext >= "a" and weirdtext <= "z":  
         weirdtext = chr(ord(weirdtext) + randnum)  
         if weirdtext > "z":  
             weirdtext = chr(ord(weirdtext) - 26)  
     endtext += weirdtext  
   randtext = a[1::2]

   xored = xor("aaaaaaaaaaaaaaa", randtext)  
   hex_xored = xored.encode("utf-8").hex()

   return endtext + hex_xored

def decrypt(msg):  
   raise NotImplementedError

def main():  
   opt = input("Would you like to [E]ncrypt or [D]ecrypt? ")  
   if opt[:1].lower() == "e":  
       msg = input("Enter message to encrypt: ")  
       print(f"Encrypted message: {encrypt(msg)}")  
   elif opt[:1].lower() == "d":  
       msg = input("Enter message to decrypt: ")  
       print(f"Decrypted message: {decrypt(msg)}")

if __name__ == "__main__":  
   main()  
```

Alright, we just have to implement `decrypt()` to undo the transformations we
see in `encrypt()`. Let's see what happens when we encrypt a message.

```bash  
kali@kali:~/Downloads$ python3 main.py  
Would you like to [E]ncrypt or [D]ecrypt? e  
Enter message to encrypt: helloworld  
Encrypted message: vzccz040d161305  
kali@kali:~/Downloads$ python3 main.py  
Would you like to [E]ncrypt or [D]ecrypt? e  
Enter message to encrypt: aaaaaaaa  
Encrypted message: oooo00000000  
kali@kali:~/Downloads$ python3 main.py  
Would you like to [E]ncrypt or [D]ecrypt? e  
Enter message to encrypt: bbbb  
Encrypted message: pp0303  
```

`encrypt()` takes the provided input string and splits it into 2 strings:

1) `some_text` with the even letters (starting from 0), which gets passed into
a loop that applies ROT-14 on the lowercase letters.

2) `randtext` with the odd letters (starting from 1), which gets XOR'd with a
static string and converted to a string of hex values.

After those steps are done, it returns the concatenation of the 2 resulting
strings.

## Solution

It would have been nice if there was a delimiter of some sort to separate the
2 strings. Oh well, we just need the flag, so I'll add the space in manually.
Implement the `decrypt()` function to reverse the transformations described
above, with a space separating the 2 strings.

```python  
import binascii

def xor(s1,s2):  
   return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))

def unxor(s1,s2):  
   return ''.join(chr(ord(a) ^ b) for a, b in zip(s1, s2))

def encrypt(a):  
   some_text = a[::2]

   randnum = 14  
   text_length = len(some_text)  
   endtext = ""  
   for i in range(1, text_length + 1):  
     weirdtext = some_text[i - 1]  
     if weirdtext >= "a" and weirdtext <= "z":  
         weirdtext = chr(ord(weirdtext) + randnum)  
         if weirdtext > "z":  
             weirdtext = chr(ord(weirdtext) - 26)  
     endtext += weirdtext  
   randtext = a[1::2]

   xored = xor("aaaaaaaaaaaaaaa", randtext)  
   hex_xored = xored.encode("utf-8").hex()

   return endtext + ' ' + hex_xored

def decrypt(msg):  
   # let's just throw a space in there manually, that seems easier.  
   endtext, hex_xored = msg.strip().rstrip().split(" ")

   randnum = 14  
   some_text = ""  
   for i in range(1, len(endtext) + 1):  
       weirdtext = endtext[i - 1]  
       if weirdtext >= "a" and weirdtext <= "z":  
           weirdtext = chr(ord(weirdtext) - randnum)  
           if weirdtext < "a":  
               weirdtext = chr(ord(weirdtext) + 26)  
       some_text += weirdtext  
  
   xored = binascii.unhexlify(hex_xored)  
   randtext = unxor("aaaaaaaaaaaaaaa", xored)

   cleartext = "\n"  
   for a, b in zip(some_text, randtext):  
       cleartext += a + b

   return cleartext

def main():  
   opt = input("Would you like to [E]ncrypt or [D]ecrypt? ")  
   if opt[:1].lower() == "e":  
       msg = input("Enter message to encrypt: ")  
       print(f"Encrypted message: {encrypt(msg)}")  
   elif opt[:1].lower() == "d":  
       msg = input("Enter message to decrypt: ")  
       print(f"Decrypted message: {decrypt(msg)}")

if __name__ == "__main__":  
   main()  
```

Test some known input:

```bash  
kali@kali:~/Downloads$ python3 solve.py  
Would you like to [E]ncrypt or [D]ecrypt? e  
Enter message to encrypt: helloworld  
Encrypted message: vzccz 040d161305  
kali@kali:~/Downloads$ python3 solve.py  
Would you like to [E]ncrypt or [D]ecrypt? d  
Enter message to decrypt: vzccz 040d161305  
Decrypted message:  
helloworld  
```

Now we just have to run the flag from the description through it, with the
extra space:

```bash  
kali@kali:~/Downloads$ perl -e 'print "d\n" . "fqtbjfub4uj_0_d 00151a52523e510f3e50521814141c\n"' | python3 solve.py   
Would you like to [E]ncrypt or [D]ecrypt? Enter message to decrypt: Decrypted
message:  
ractf{n3v3r_g0nn4_g1v3_y0u_up}  
```

The flag is:

```  
ractf{n3v3r_g0nn4_g1v3_y0u_up}  
```

Original writeup
(https://github.com/dobsonj/ctf/tree/master/writeups/2020/ractf/snakes_and_ladders).