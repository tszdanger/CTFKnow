# Chaos Writeup

### ISITDTU Quals 2019 - crypto 304 - 47 solves

> Could you help me solve this case? I have a tool but do not understand how
> it works.  
nc 104.154.120.223 8085

#### Observations

Our goal is to submit `key` to get flag. By interacting(encrypting arbitrary
printable strings), the system is simply pseudo-substitution cipher. Let `ct`
be the given ciphertext, and `pt` the plaintext(`key`). Pattern for decryption
is obtained simply by observations, which is stated below.

```python  
pt = ""  
for c in ct:  
   if len(c) == 8:  
       pt += c[0]  
   elif len(c) == 11 and c[6] in punctuation:  
       pt += c[3]  
   elif len(c) == 11 and c[6] in ascii_uppercase:  
       pt += c[7]  
   else:  
       pt += c[-1]  
```

By sending `key` to server, I get the flag:

```  
ISITDTU{Hav3_y0u_had_a_h3adach3??_Forgive_me!^^}  
```

Exploit code: [solve.py](solve.py)  

Original writeup (https://github.com/pcw109550/write-
up/tree/master/2019/ISITDTU/Chaos).For this challenge, we were given a netcat command that connects to a tool.
Given this tool, maybe we can figure out how to approach this problem.

Once loaded, this was the screen we were presented with:

![main](https://github.com/Cap-
Size/CTF_Write_Ups/blob/master/ISITDTU_2019/chaos/main.png?raw=true)

There seems to be a cipher that they give us, and two options to choose:
encrypt a message, or decrypt the ciphertext.

So I run the program and try to see a pattern:

![test](https://github.com/Cap-
Size/CTF_Write_Ups/blob/master/ISITDTU_2019/chaos/test.png?raw=true)

I notice that 'the' translates into '00/tt/??/ww          11/hh/&&/gg
55/ee/((/dd'. The second set of doubles is the letter of the word, but the
other chars are used to obfuscate the text. I check each type of char and
realize that:  
* Each set is seperated by a space.  
* Lowercase: four sets long, letters in second set  
* Uppercase: four sets long, characters in the third set and capital letters in the fourth set.  
* numbers: three sets long, numbers in the first set.  
* special characters: five sets long, characters in the fifth set.

So with these rules, I made a script that will parse through and enter the
flag, the script can be found [here](https://github.com/Cap-
Size/CTF_Write_Ups/blob/master/ISITDTU_2019/chaos/chaos.py)

Original writeup (https://github.com/Cap-
Size/CTF_Write_Ups/tree/master/ISITDTU_2019/chaos).Collisions in this hash function have been proven in the following paper:
[https://eprint.iacr.org/2005/403.pdf](https://eprint.iacr.org/2005/403.pdf).
For the sake of completeness, however, I have briefly explained one of the
collisions: the "appending" case.

Original writeup (https://zeyu2001.gitbook.io/ctfs/2021/zh3ro-ctf-v2/chaos).