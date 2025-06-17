# Eternal Game (TAMUctf2020)

## Challenge description

> No one has ever won my game except me!  
> nc challenges.tamuctf.com 8812

## The Eternal Game

In this challenge we are provided with **game.py** :  
```python  
from collections import defaultdict  
import random  
import hashlib  
import sys

x = 1  
d = defaultdict(int)  
game_running = True  
high_score = 653086069891774904466108141306028536722619133804

def gen_hash(x):  
   with open('key.txt', 'r') as f:  
       key = f.read()[:-1]  
       return hashlib.sha512(key + x).hexdigest()

def extract_int(s):  
   i = len(s)-1  
   result = 0  
   while i >= 0 and s[i].isdigit():  
       result *= 10  
       result += ord(s[i]) - ord('0')  
       i -= 1  
   return result

def multiply():  
   global x  
   print 'Multiplier: '  
   sys.stdout.flush()  
   m = extract_int(raw_input())  
   sys.stdout.flush()  
   if m < 2 or m > 10:  
       print 'Disallowed value.'  
   elif d[m] == 5:  
       print 'You already multiplied by ' + str(m) + ' five times!'  
   else:  
       x *= m  
       d[m] += 1  
   sys.stdout.flush()

def print_value():  
   print x  
   sys.stdout.flush()

def get_proof():  
   global game_running  
   game_running = False  
   print gen_hash(str(x))  
   sys.stdout.flush()

game_options = [multiply, print_value, get_proof]  
def play_game():  
   global game_running  
   game_running = True  
   print(  
           '''  
           Welcome the The Game. You are allowed to multiply the initial number (which is 1) by any  
           number in the range 2-10. Make decisions wisely! You can only multiply by each  
           number at most 5 times... so be careful. Also, at a random point during The Game, an asteroid  
           will impact the Earth and The Game will be over.

           Feel free to get your proof of achievement and claim your prize at the main menu once  
           you start reaching big numbers. Bet you can't beat my high score!  
           '''  
           )  
   while game_running:  
       print '1. Multiply'  
       print '2. Print current value'  
       print '3. Get proof and quit'  
       sys.stdout.flush()  
       game_options[extract_int(raw_input())-1]()  
       sys.stdout.flush()  
       if random.randint(1, 20) == 10:  
           print 'ASTEROID!'  
           game_running = False  
       sys.stdout.flush()

def prize():  
   print 'Input the number you reached: '  
   sys.stdout.flush()  
   num = raw_input()  
   sys.stdout.flush()  
   print 'Present the proof of your achievement: '  
   sys.stdout.flush()  
   proof = raw_input()  
   sys.stdout.flush()  
   num_hash = gen_hash(num)  
   num = extract_int(num)

   if proof == num_hash:  
       if num > high_score:  
           with open('flag.txt', 'r') as f:  
               print f.read()  
       elif num > 10**18:  
           print 'It sure is a good thing I wrote this in Python. Incredible!'  
       elif num > 10**9:  
           print 'This is becoming ridiculous... almost out of bounds on a 32 bit integer!'  
       elif num > 10**6:  
           print 'Into the millions!'  
       elif num > 1000:  
           print 'Good start!'  
       else:  
           print 'You can do better than that.'  
   else:  
       print 'Don\'t play games with me. I told you you couldn\'t beat my high score, so why are you even trying?'  
   sys.stdout.flush()

def new():  
   global x  
   global d  
   x = 1  
   d = defaultdict(int)  
   sys.stdout.flush()  
   play_game()

main_options = [new, prize, exit]

def main_menu():  
   print '1. New Game'  
   print '2. Claim Prize'  
   print '3. Exit'  
   sys.stdout.flush()  
   main_options[extract_int(raw_input())-1]()  
   sys.stdout.flush()

if __name__ == '__main__':  
   while True:  
       main_menu()  
```

### What does it do ?

Essentialy, it is a simple python game with its rules as the following :  
> Welcome the The Game. You are allowed to multiply the initial number (which
> is 1) by any number in the range 2-10. Make decisions wisely! You can only
> multiply by each number at most 5 times... so be careful. Also, at a random
> point during The Game, an asteroid will impact the Earth and The Game will
> be over.  
>  
> Feel free to get your proof of achievement and claim your prize at the main
> menu once you start reaching big numbers. Bet you can't beat my high score!

- The proof of achievement of the score is the **SHA512** sum of a secret key and the score x, so basically `SHA512(key || x)`, and this is what the function `gen_hash(x)` is responsible for when you ask the game to give you a proof based on your current score.  
- The objective in this game is to reach a score higher than `high_score = 653086069891774904466108141306028536722619133804`.  
- Not surprisingly, we cannot win the game by playing by the rules, even if we manage to multiply all the valid numbers we can't reach `high_score` (Don't even start me on that asteroid).  
- So, in order to win the game and get the flag, how can we forge a proof with a score high enough knowing that we don't have access to the secret key?

## Vulnerability : hash length extension attack

After a good bit of research, I stumbled upon various articles about hash
length extension attacks, which correspond to the scenario of this challenge.

### Overview of the attack

- The hash length extension attack occurs when :  
 - The application entrusts the user with a hash composed of a known **string** prepended with a **secret_key** generated with a vulnerable hash function `H` : `H(secret_key || string)` (In our case the hash is the proof that you ask for when playing the game : `SHA512(key || current_score)`)  
 - To verify the integrity of the **input** data, the application expects the hash : `H(secret_key || input)`. Ideally, this would stop attackers by allowing only inputs that the application provides hashes for. (In our scenario this is when you claim your prize and you are prompted to input the score reached with its proof)

- It turns out that you can still generate a valid hash for arbitrary input as long as we are provided with :  
 - H = the vulnerable hash function used : `SHA512` (SHA512 is part of the SHA-2 family of hashing algorithms, hence it is vulnerable to this attack, more details can be found in the links below)  
 - signature = `H(secret || known_data)` : `SHA512(secret_key || "1")` which is generated when we ask for our proof when the score is `x = 1`  
 - length of `secret` : in our case we don't have the length of the secret key, but that doesn't stop us since we can brute force it

- I link to you these websites which have done a great job of explaining this attack :  
 - <https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks>  
 - <https://en.wikipedia.org/wiki/Length_extension_attack>  
 - <https://crypto.stackexchange.com/questions/3978/understanding-the-length-extension-attack>

### How to carry out the attack ?

We know the game is using SHA512, we have to take note that this hashing
function operates on blocks of **128 bytes** (1024 bits), so the input is
padded until it reaches a multiple of 128 bytes with the following padding : a
'1' bit, a conveniant number of '0' bits, and a final block of 16 bytes
representing the bit length of the input (in big endian encoding for the SHA
family), example :  
```  
00000000: 696e 7075 7480 0000 0000 0000 0000 0000  input...........  
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................  
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................  
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................  
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................  
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................  
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................  
00000070: 0000 0000 0000 0000 0000 0000 0000 0028  ...............(  
```  
"input" contains **5** bytes (0x28 bits), so we add **107** bytes of padding
`80 00 00 ...` and the **16** remaining bytes contain the bit length of
"input" `0000 0000 0000 0000 0000 0000 0000 0028` (5+107+16 = 128 bytes)

When `secret_key + "1"` is hashed, if we suppose the key length is 6, we'd
have :  
```  
00000000: 5345 4352 4554 3180 0000 0000 0000 0000  SECRET1.........  
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................  
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................  
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................  
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................  
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................  
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................  
00000070: 0000 0000 0000 0000 0000 0000 0000 0038  ...............8  
```  
"SECRET"+"1" contains **7** bytes (0x38 bits), so we add **105** bytes of
padding `80 00 00 ...` and the **16** remaining bytes contain the bit length
of "input" `0000 0000 0000 0000 0000 0000 0000 0038` (7+105+16 = 128 bytes)

Now that we have what the function hashes, let's just append `hiiigh_score =
"1"*50` at the end of that block :  
```  
00000000: 5345 4352 4554 3180 0000 0000 0000 0000  SECRET1.........  
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................  
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................  
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................  
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................  
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................  
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................  
00000070: 0000 0000 0000 0000 0000 0000 0000 0038  ...............8  
00000080: 3131 3131 3131 3131 3131 3131 3131 3131  1111111111111111  
00000090: 3131 3131 3131 3131 3131 3131 3131 3131  1111111111111111  
000000a0: 3131 3131 3131 3131 3131 3131 3131 3131  1111111111111111  
000000b0: 3131                                     11  
```

The reason why we did this is that since we have the signature
(`SHA512(secret_key + "1")`), the extension vulnerability allows us to hash
arbitrary data (a high score for example) starting at the end of the first
block (the above 128-byte block) using the state we already know from
*signature*, in other terms we can end up with : `SHA512(secret_key + "1" +
padding + hiiigh_score)`. And then we can get the server to calculate that
hash by providing as input `"1" + padding + hiiigh_score`. Great !

So if we take a look back at the part of the code for claiming the prize :  
```python  
print 'Input the number you reached: '  
sys.stdout.flush()  
num = raw_input()  
sys.stdout.flush()  
print 'Present the proof of your achievement: '  
sys.stdout.flush()  
proof = raw_input()  
sys.stdout.flush()  
num_hash = gen_hash(num)  
num = extract_int(num)

if proof == num_hash:  
   if num > high_score:  
       with open('flag.txt', 'r') as f:  
           print f.read()  
```  
- num = input score = `"1" + padding + hiiigh_score`  
- proof = our own calculated hash using the extension vulnerability = `SHA512(secret_key + "1" + padding + hiiigh_score)`

As you can see above, `num_hash = gen_hash(num)` is calculated before `num =
extract_int(num)` so our input would not be filtered, and after looking at the
function `extract_int(s)` even though our input doesn't contain only digits,
it should successfully extract the `"1"*50`, a.k.a `hiiigh_score`.

Now our only obstacle is that we don't know the actual length of `secret_key`,
so we need to define a length range and try all possible lengths.

## Not so Eternal

To wrap it up we need to execute these steps :  
- Get the hash signature with `get_signature()` (we need to do this only once)  
- Define a key length range of, let's say, 10-20 (this is just a guessing to avoid dealing with large ranges from the beginning, and if it doesn't work we change the range), and for each key length :  
 - Calculate the extended hash using the [hlextend tool](https://github.com/stephenbradshaw/hlextend "hlextend") : `h.extend(append='1'*50, known_data='1', key_len, signature)`  
 - Send the payload = `'1' + padding + '1'*50` (which is returned from the last function)  
 - Send the calculated hash  
 - If it's the correct key length, congrats ! We get the flag !

### Solution  
```python  
#!/usr/bin/env python2

import hlextend  
from pwn import *

# wanted score = '1'*50

known_data = '1'  
append = '1'*50

host = 'challenges.tamuctf.com'  
port = 8812

length_range = range(10, 20)  
# generated with get_signature()  
signature =
'a17b713167841563563ac6903a8bd44801be3c0fb81b086a4816ea457f8c829a6d5d785b49161972b7e94ff9790d37311e12b32221380041a99c16d765e8776c'

# returns sha512(key + '1')  
def get_signature():  
 global game  
 game.sendlineafter('3. Exit\n', '1') # option 1: New Game  
 game.sendlineafter('3. Get proof and quit\n', '3') # option 3: Get proof and
quit  
 return game.recvuntil('\n').strip()

# with payload being the supposedly score and proof being the sha512 sum  
def claim_prize(payload, proof):  
 global game  
 game.sendlineafter('3. Exit\n', '2') # option 2: Claim prize  
 game.sendlineafter('Input the number you reached: \n', payload) # input the
score reached ^^  
 game.sendlineafter('Present the proof of your achievement: \n', proof) #
input the proof ^^  
 answer = game.recvline()  
 print answer  
 # If it starts with that string, it means that we're wrong in the length  
 return not answer.startswith("Don't play games with me")

if __name__ == '__main__':  
 game = remote(host, port)  
 for key_len in length_range:  
   print "\n[+] Trying key length:", key_len  
   h = hlextend.new('sha512')  
   # the extend function returns the `known_data + padding + append`  
   # which will be our payload  
   payload = h.extend(append, known_data, key_len, signature)  
   # for some reason '\x80' and '\x00' are escaped...  
   payload = payload.replace('\\x00', '\x00').replace('\\x80', '\x80')  
   proof = h.hexdigest()  
  
   if claim_prize(payload, proof):  
     break  
```

**Flag** : `gigem{a11_uR_h4sH_rR_be10nG_to_m3Ee3}`

**Fun fact** : Luckily enough, I guessed the correct key length by starting
off with 10 :D  

Original writeup (https://github.com/malikDaCoda/CTFs-
writeups/tree/master/crypto/eternal_game-TAMUctf_2020).