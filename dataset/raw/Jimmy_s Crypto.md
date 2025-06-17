# TU CTF 2018 - Jimmy's Crypto

## Description  
Your nemesis, we'll call him Jimmy for brevity's sake, believes that he has
finally outsmarted you in his secret messaging techniques.  
He's so confident that he even gave his source code.

Show him where he went wrong!

## Given files  
- [secret](./secret)  
- [gen_ciphertext.py](./gen_ciphertext.py)  
- [flag](./flag)

## Solution  
The given python script does the following:  
- generate a random key  
- xor the flag with the key  
- xor the secret with the key  
- save the resulting string into `flag` and `secret`

So we know what are the other two files we are given.

The first and only working idea we had was to xor the two files.

```  
x = (flag ^ key) ^ (secret ^ key) = flag ^ secret  
```

Now we assumed that secret is some english text. So we tried to look at all
indexes where `x ^ 'TUCTF{}'` gave us a valid sequence of characters.
Hopefully there was only one answer: `42`.

At this point we did not found any better solution than completing the two
text in parallel, trying to give a sense to both of them.

After a while, this gave us:

```  
   Secret: steal my secrets. If you are looking at this file,

   Flag: ~TUCTF{D0NT_US3_TH3_S4M3_K3Y_F0R_TH3_S4M3_M3SS4G3}~

```

## Code  
[flag.py](flag.py)  

Original writeup (https://github.com/ctf-
epfl/writeups/tree/master/tuctf18/jimmy_crypto#tu-ctf-2018---jimmys-crypto).