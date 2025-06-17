# Lenore Blum

## Description  
> Lenore Carol Blum (née Epstein born December 18, 1942) is an American
> computer scientist and mathematician who has made contributions to the
> theories of real number computation, cryptography, and pseudorandom number
> generation. She was a distinguished career professor of computer science at
> Carnegie Mellon University until 2019 and is currently a professor in
> residence at the University of California, Berkeley. She is also known for
> her efforts to increase diversity in mathematics and computer science. -
> Wikipedia Entry

> Chal: Connect to `0.cloud.chals.io 28827` and return the flag to the
> computational mathematics professor from this random talk

### Attachments  
[chal1.bin](https://github.com/HarshJolad/CTF-
Writeups/blob/master/CyberHeroines-CTF-2023/crypto/Lenore_Blum/chal1.bin)

## Solution  
* The binary implements **Blum Blum Shub algorithm**(BBS) which is a pseudorandom number generating technique.  
* The program asks you to play a game. If you say yes, you are given a "**seed**" number and asked to guess the next random number.   
* When looking at the binary you can determine that the program generates three values, one of which is given to you and is called the "seed".  
* By looking at the functions which generate these numbers, it can be seen that the p and q are generated according to the rules set for the algorithm (they must be congruent to 3 mod 4) however the seed is not.  
* The `rand()` value the p and q are based off is used to get the seed value, which ends up just being the random value multiplied by 1337.  
* We can solve this by writing a script which connects to the remote service, gets the seed value, and uses it to calculate the 2 random value which the remote server generates  
* Using [script2.py](https://github.com/HarshJolad/CTF-Writeups/blob/master/CyberHeroines-CTF-2023/crypto/Lenore_Blum/script2.py) we can get the flag  
* The functions in the script: `find_prime_congruent_to_3_mod_4`, `bbs`, `is_prime` are taken from the binary using `Ghidra`.  
```  
from pwn import *

HOST = '0.cloud.chals.io'  
PORT = 28827  
# context.log_level = "debug"

p = remote(HOST, PORT)

p.recvuntil("Would you like to play? Y/N >>> ")  
p.sendline("y")

def find_prime_congruent_to_3_mod_4(param):  
   local_10 = param  
   while True:  
       cVar1 = is_prime(local_10)  
       if cVar1 and (local_10 & 3) == 3:  
           break  
       local_10 += 1  
   return local_10

def bbs(param1, param2, param3):  
   local_10 = (param3 * param3) % (param1 * param2)  
   local_18 = 0  
   for local_1c in range(0x3f):  
       local_10 = (local_10 * local_10) % (param1 * param2)  
       local_18 |= (local_10 & 1) << (local_1c & 0x3f)  
   return local_18

def is_prime(param):  
   if param < 2:  
       return 0  
   elif param < 4:  
       return 1  
   elif (param & 1) == 0 or param % 3 == 0:  
       return 0  
   else:  
       for local_10 in range(5, int(param ** 0.5) + 1, 6):  
           if param % local_10 == 0 or param % (local_10 + 2) == 0:  
               return 0  
       return 1

while True:  
   # Receive the seed value  
   seed_line = p.recvline().strip().decode()  
   seed = int(seed_line.split(": ")[1])

   known_factor = 0x539  

   # Calculate the two primes  
   prime1 = find_prime_congruent_to_3_mod_4(seed // 1337)  
   prime2 = find_prime_congruent_to_3_mod_4(prime1 + 1)

   # Calculate the random number using BBS PRNG  
   random_number = bbs(prime1, prime2, seed)

   p.sendline(str(random_number))

   # outcome = p.recvline().strip().decode()  
   outcome = p.recvline()

   if b"Incorrect" in outcome:  
       print(outcome)  
   elif b"Great job!" in outcome:  
       print(outcome)  
       print(random_number)  
       p.interactive()  
       break

p.close()  
```

### FLAG  
```  
chctf{tH3_f1rsT_Blum}  
```

Original writeup (https://github.com/HarshJolad/CTF-
Writeups/tree/master/CyberHeroines-CTF-2023/crypto/Lenore_Blum#lenore-blum).