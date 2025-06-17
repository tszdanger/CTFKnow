## Disclaimer

1. This challenge was resolved after the end of the CTF, so it doesn't count for the final ranking.  
2. Please check the original writeup on https://dothidden.xyz/dantectf_2023/strangebytes/ if you want to see it with the pictures.

## Description of the challenge

I got hacked by a ransomware and it encrypted some important files. Some
crypto analyst told me they were encrypted using AES CBC, but there is
something strange in them which can probably be exploited. I don't have enough
money to give the job to proper crypto analysts, could you decrypt them for me
please?

## Solution

This challenge provided a zip file containing 250 encrypted files with random
names (names of the files were not part of the challenge).  
The description of the challenge tells us many of useful information:

* The encryption algorithm is AES CBC.  
* There is something strange inside the files that we could exploit.  
* The title of the challenge is "StrangeBytes", we can assume that the strange thing is related to the bytes of the files.

Let's open a random file with a hex editor and see what we can find.  
The first we can notice is that there is the following char sequence: `:CBC`,
let's open  
another file and see if we can find the same sequence.

We can see that the sequence `:CBC` is present in all the files, so it's
probably related to the flag. Furthermore, we can see that not only the  
`:CBC` is present in all the files but also the following pattern:  
```  
\...o.....m..(g ...4c...U.M..3..:..%yD..Ob...{..\:CBC  
```  
which has the following hex code:

```  
5c f3 c0 f0 6f fb 02 fe a3 9b 6d ab de 28 67 20 9e 96 86 34 63 a4 b7 8b 55 aa
4d 88 b0 33 81 1e 3a ba 1b 25 79 44 af df 4f 62 0b 0f e4 7b a1 b8 5c 3a 43 42
43  
```

This pattern has a length of 53 bytes in total and if we remove the `:CBC`
pattern we got a length of 49 bytes.  
If we assume that the first 32 bytes are the AES 256 key, the next 17 bytes
are the IV. We can now try to decrypt the files after removing the pattern
using the following python script:

> Please check our official writeup to get the Python script
> https://dothidden.xyz/dantectf_2023/strangebytes/

The `find_flag` function will print the flag if we find the pattern `DANTE`
into a decrypted file.  
The final result will be the following where we can see the flag
`DANTE{AHh9HhH0hH_ThAat_RAnsomware_maDe_m3_SaD_FFFFAAABBBBDDDD67}`:

```  
b'\xe6\xc3S(H\xa89\xf5a"O\x9b\xdc\xae]\xbcJptXFiXMNqAJXFurPPgPYMSWgFRsLbFkdwQXLpBNQDSsJYRqdvYGsRrQxELqXxYjjyAdAWQZijTTPILOBmMJefZooyVmVvhoRoLPOhglTpBrnVFfAQyxrYKcErXIGvoeIMbwSoPwTImkwoByqkaSLhPmhraomgIqkynvRzyGzMBEHfYVxyKQRRQWUqIGnnlmCLICQDlwUeklDqQkHyfTzsGYttyRZvCSPJDANTE{AHh9HhH0hH_ThAat_RAnsomware_maDe_m3_SaD_FFFFAAABBBBDDDD67}\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'  
```

Original writeup (https://dothidden.xyz/dantectf_2023/strangebytes/).