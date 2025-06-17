### Question  
It seems that my problems with hashing just keep multiplying...  
  
nc umbccd.io 3100  
  
Author: RJ  
```  
#!/usr/bin/env python3

# Hash constants  
A = 340282366920938460843936948965011886881  
B = 127605873542257115442148455720344860097

# Hash function  
def H(val, prev_hash, hash_num):  
   return (prev_hash * pow(val + hash_num, B, A) % A)

if __name__ == "__main__":

   # Print welcome message  
   print("Welcome to TrashChain!")  
   print("In this challenge, you will enter two sequences of integers which
are used to compute two hashes. If the two hashes match, you get the flag!")  
   print("Restrictions:")  
   print("  - Integers must be greater than 1.")  
   print("  - Chain 2 must be at least 3 integers longer than chain 1")  
   print("  - All integers in chain 1 must be less than the smallest element
in chain 2")  
   print("Type \"done\" when you are finished inputting numbers for each
chain.")

   # Get inputs  
   chains = [[], []]  
   for chain_num in range(len(chains)):  
       print("\nProvide inputs for chain {}.".format(chain_num+1))  
       while True:  
           val = input("> ")  
           if val == "done":  
               break  
           try:  
               val = int(val)  
           except ValueError:  
               print("Invalid input, exiting...")  
               exit(0)  
           if val <= 1:  
               print("Inputs must be greater than 1, exiting...")  
               exit(0)  
           chains[chain_num].append(val)

   # Validate chain lengths  
   if not len(chains[0]):  
       print("Chain 1 cannot be empty, exiting...")  
       exit(0)  
   if len(chains[1]) - len(chains[0]) < 3:  
       print("Chain 2 must contain at least 3 more integers than chain 1, exiting...")  
       exit(0)  
   if max(chains[0]) >= min(chains[1]):  
       print("No integer in chain 1 can be greater than the smallest integer in chain 2, exiting...")  
       exit(0)

   # Compute hashes  
   hashes = []  
   for chain_num in range(len(chains)):  
       cur_hash = 1  
       for i, val in enumerate(chains[chain_num]):  
           cur_hash = H(val, cur_hash, i+1)  
       hashes.append(cur_hash)

   # Print hashes  
   print("Hash for chain 1: {0:0{1}x}".format(hashes[0], 32))  
   print("Hash for chain 2: {0:0{1}x}".format(hashes[1], 32))  
   if hashes[0] == hashes[1]:  
       print("Correct! Here's your flag: DogeCTF{not_a_real_flag}")  
```  
### Approach  
On going through the code, it can be realised that this is a sort of block
chain cipher, in which the ciphertext of the previous block is affecting the
plaintext of the present block while the hashing takes place.  
###### Key Points :  
- Integers must be greater than 1."  
- Chain 2 must be at least 3 integers longer than chain 1")  
- All integers in chain 1 must be less than the smallest element in chain 2

So for our convenience, let's consider the no. of elements in `Chain 1` to be
1 and in `Chain 2` to be 4.

###### How it works(say, for chain2):  
c1 = 1 * ((chain2[0] + 1) ** B) % A  
  
c2 = c1 * ((chain2[1] + 2) ** B) % A  
  
c3 = c2 * ((chain2[2] + 3) ** B) % A  
  
hashes[1] = c3 * ((chain2[3] + 4) ** B) % A  

If somehow we can bring the value of `((chain2[i] + (i + 1)) ** B) % A` down
to 1 at every step, we can obtain the values of c1, c2 and c3 to be 1 and
therefore the final hash can be predictable.

Now there's a property of `modulus`,  
  
if a % b = c, then (a ** n ) % b = (c ** n) % b  
  
or in other words, ((n * a + 1) ** b) % a is always 1

Therefore we take the array as:  
  
`chain1 = [A - 1]`  
  
`chain2 = [2A, 2A - 1, 2A - 2, 2A - 4]`  
  
So that `hashes[0] = hashes[1] = 0`

```  
┌──(x117㉿kali)-[~]  
└─$ nc umbccd.io 3100
1 ⨯  
Welcome to TrashChain!  
In this challenge, you will enter two sequences of integers which are used to
compute two hashes. If the two hashes match, you get the flag!  
Restrictions:  
 - Integers must be greater than 1.  
 - Chain 2 must be at least 3 integers longer than chain 1  
 - All integers in chain 1 must be less than the smallest element in chain 2  
Type "done" when you are finished inputting numbers for each chain.

Provide inputs for chain 1.  
> 340282366920938460843936948965011886880  
> done

Provide inputs for chain 2.  
> 680564733841876921687873897930023773762  
> 680564733841876921687873897930023773761  
> 680564733841876921687873897930023773760  
> 680564733841876921687873897930023773758  
> done  
Hash for chain 1: 00000000000000000000000000000000  
Hash for chain 2: 00000000000000000000000000000000  
Correct! Here's your flag: DawgCTF{We1rd_RSA_2nd_Pre1m4g3_th1ng}  
```  
The flag is `DawgCTF{We1rd_RSA_2nd_Pre1m4g3_th1ng}`  

Original writeup (https://github.com/x-0117/CTF-
Writeups/blob/main/Dawg%20CTF/TrashChain.md).