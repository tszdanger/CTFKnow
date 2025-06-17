# aptenodytes-forsteri (597 solves, 183 points)  
## Description  
Here's a warmup cryptography challenge. Reverse the script, decrypt the
output, submit the flag.

[aptenodytes-
forsteri.py](https://hsctf.storage.googleapis.com/uploads/2bf18e2c8c9525f03b830291047fb00942b35d9b91feb2751680d97329aef749/aptenodytes-
forsteri.py)  
[output.txt](https://hsctf.storage.googleapis.com/uploads/30bab898df93535d5c5685a35810721f6472135d3d8cf62fe7e6f1e1b1b44646/output.txt)  
## Solution  
After looking at the initial python file its clear that this algorithm is
taking a character and turning it into another character. To find the key to
this substitution cipher  
I wrote a python script that prints the alphabet, and then the ciphered
alphabet. I used the key to manually decode the output: ``IOWJLQMAGH``

I could've added to the script to fully automate that process but the flag was
really short so I think it was faster to just do it by hand.

Here's the script to generate the key:  
```python3

flag = "flag{ABCDEFGHIJKLMNOPQRSTUVWXYZ}"  
letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"  
encoded = ""  
for character in flag[5:-1]:  
   encoded+=letters[(letters.index(character)+18)%26] #encode each character  
print(letters)  
print(encoded)

```  
## Flag  
``flag{QWERTYUIOP}``  

Original writeup (https://github.com/BASHing-thru-
challenges/HSCTF-2021-Writeups/tree/main/crypto/aptenodytes-forsteri).