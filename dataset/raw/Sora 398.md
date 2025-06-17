# Sora

## Description

> This obnoxious kid with spiky hair keeps telling me his key can open all
> doors.  
>  
> Can you generate a key to open this program before he does?  
>  
> Connect to challenges.auctf.com 30004

## Solution

We decompile the binary using Ghidra, and see that it encrypts the input
string and then compares it to the key encrypted with the same function. We
just reverse the encryption function and give it the encrypted key found in
the file.

```python  
secret = b"aQLpavpKQcCVpfcg"

key = []

for i in range(len(secret)):  
   for c in range(65, 122):  
       if (c * 8 + 0x13) % 0x3d + 0x41 == secret[i]:  
           key.append(c)  
           print(key)

print("".join([chr(c) for c in key]))  
```

The key is `try_to_break_meG`. This gives us the flag.

Flag: `auctf{that_w@s_2_ezy_29302}`

Original writeup (https://github.com/apoirrier/CTFs-
writeups/blob/master/AUCTF2020/Reversing/sora.md).