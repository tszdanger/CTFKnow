# xkcd.com/2247 v2  
> Why pick a weird hill to die on when you could pick a soft hill to lie on?  
>  
> Note: this challenge has been revised with a new flag. It was previously
> taken down and all solves for that challenge have been rolled back.  
>  
> The flag format will be `flag{a_bunch_of_words_with_underscores}`. The flag
> is hidden inside the plaintext, and does not include a `flag{}`.

Opening [HillREVISED.txt](HillREVISED.txt) shows us an encryption key and
ciphertext:

```  
Encryption Key:  
Coqfvpbbvzohmogzjjquohnonabjqippelaxnorxrvaxdllwubieletjauvfuktrymtkkdyfdtoos...

Ciphertext:  
ieyirlxxtfiyfpsyvxcjmcdlpeftagszjhqjblyohgknhszyshfvuopozqwivkzeatqihkhdozkkv...  
```

Based on the [xkcd](https://xkcd.com/2247/), the problem statement, and the
name of the file, we guess that this is probably a Hill Cipher (which involves
a matrix for decryption). Checking the length of the encryption key gives
`10000`, which suggests that the encryption matrix is `100 x 100`.
Additionally, the encryption key and ciphertext consist of only lowercase
letters (apart from the capital `C`), so we are probably working mod `26`.

Let's load up sage to calculate the decryption matrix:

```  
sage: enc_str =
"coqfvpbbvzohmogzjjquohnonabjqippelaxnorxrvaxdllwubieletjauv..."  
sage: enc_arr = [ord(x) - ord('a') for x in enc_str]  
sage: enc_mat = Matrix(enc_arr, ring=Integers(26), nrows=100)  
sage: dec_mat = enc_mat.inverse()  
```

Now we decrypt the ciphertext by left multiplying it by the decryption matrix:

```  
sage: ciphertext_str =
"ieyirlxxtfiyfpsyvxcjmcdlpeftagszjhqjblyohgknhszyshfv..."  
sage: ciphertext_arr = [ord(x) - ord('a') for x in ciphertext_str]  
sage: ciphertext_mat = Matrix(ciphertext_arr, ring=Integers(26),
ncols=100).transpose()  
sage: plaintext_mat = (dec_mat * ciphertext_mat).transpose()  
sage: plaintext_arr = [int(x) for x in plaintext_mat.list()]  
sage: plaintext_str = ''.join([chr(x + ord('a')) for x in plaintext_arr])  
sage: plaintext_str  
ryjpureelbzjxqrgzlntnyzzkzaukwqcriugpqefejxhiwrvqiwhjyqzdxxohpfwmmwyzdsggvmvs...  
```

At this point we can just skim through the text or try searching for common
english words. Then, we get the flag:

```  
sage: plaintext_str[3937:3988]  
imaginegivingtheplaintextandnottheciphertextriplmao  
```

> `flag{imagine_giving_the_plaintext_and_not_the_ciphertext_rip_lmao}`

Original writeup
(https://github.com/AMACB/HSCTF-2020-writeups/blob/master/xkcd_2247/xkcd_2247.md).