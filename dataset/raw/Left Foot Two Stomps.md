# Left Foot Two Stomps

## Description

> n=960242069 e=347  
>
> c=346046109,295161774,616062960,790750242,259677897,945606673,321883599,625021022,731220302,556994500,118512782,843462311,321883599,202294479,725148418,725148418,636253020,70699533,475241234,530533280,860892522,530533280,657690757,110489031,271790171,221180981,221180981,278854535,202294479,231979042,725148418,787183046,346046109,657690757,530533280,770057231,271790171,584652061,405302860,137112544,137112544,851931432,118512782,683778547,616062960,508395428,271790171,185391473,923405109,227720616,563542899,770121847,185391473,546341739,851931432,657690757,851931432,284629213,289862692,788320338,770057231,770121847

## Solution

We recognize a RSA public key, with a very small `n` which will be easy to
factorize.

```python  
n = 960242069  
e = 347  
cipher =
[346046109,295161774,616062960,790750242,259677897,945606673,321883599,625021022,731220302,556994500,118512782,843462311,321883599,202294479,725148418,725148418,636253020,70699533,475241234,530533280,860892522,530533280,657690757,110489031,271790171,221180981,221180981,278854535,202294479,231979042,725148418,787183046,346046109,657690757,530533280,770057231,271790171,584652061,405302860,137112544,137112544,851931432,118512782,683778547,616062960,508395428,271790171,185391473,923405109,227720616,563542899,770121847,185391473,546341739,851931432,657690757,851931432,284629213,289862692,788320338,770057231,770121847]

for p in range(3,n,2):  
   if n % p == 0:  
       break  
q = n // p  
print(p, q)

def egcd(a, b):  
   if a == 0:  
       return (b, 0, 1)  
   else:  
       g, y, x = egcd(b % a, a)  
       return (g, x - (b // a) * y, y)

def modinv(a, m):  
   g, x, y = egcd(a, m)  
   if g != 1:  
       raise Exception('modular inverse does not exist')  
   else:  
       return x % m

d = modinv(e, (p-1)*(q-1))  
print(d)

def pow(a, x, n):  
   if x == 0:  
       return 1  
   if x == 1:  
       return a%n  
   s = pow(a,x//2,n)  
   s *= s  
   if x%2 == 1:  
       s *= a  
   return s%n

plaintext = [pow(a, d, n) for a in cipher]  
print("".join([chr(c) for c in plaintext]))  
```

This gives us the following string:

```  
xhBQCUIcbPf7IN88AT9FDFsqEOOjNM8uxsFrEJZRRifKB1E=|key=visionary  
```

This is a Vigenere cipher and the key is given, so we can give it to
[dCode](https://www.dcode.fr/chiffre-vigenere).  
Output: `czJIOHIldUx7QF88MG9FMHxiMGAwNV8wckNjQWZATnxST1Q=`

The `=` in the end looks like `base64` padding, we decode it with
[asciitohex](https://www.asciitohex.com/). Output:
``s2H8r%uL{@_<0oE0|b0`05_0rCcAf@N|ROT``.

This is a ROT cipher, we once again give it to
[dCode](https://www.dcode.fr/chiffre-rot).

Flag: `DawgCTF{Lo0k_@t_M3_1_d0_Cr4p7o}`

Original writeup (https://github.com/apoirrier/CTFs-
writeups/blob/master/Dawg2020/Crypto/LeftFoot.md).