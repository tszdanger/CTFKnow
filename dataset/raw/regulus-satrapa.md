# regulus-satrapa  
## Description  
```  
Do you like milk?  
```  
## Files:  
- [output.txt](output.txt)  
- [regulus-satrapa.py](regulus-satrapa.py)

Looking the source code, it is a typical RSA challenge:  
```py  
from Crypto.Util.number import *  
import binascii  
flag = open('flag.txt','rb').read()  
p = getPrime(1024)  
q = getPrime(1024)  
n = p*q  
e = 2**16+1  
pt = int(binascii.hexlify(flag).decode(),16)  
print(p>>512)  
print(q%(2**512))  
print(n, e)  
print(pow(pt,e,n))  
```  
But it only give us the public key (n,e) and `p >> 512` , `q % 2^512`

Which means it give us the **top and bottom 512 bits of both factors!**

So how we use these two values to recover both factors?

## Recover factors  
We know that `n = pq`, but this case we add modulus 2^512:

![image1](image1.gif)

We know lower bits of `q`, but we cannot directly divide in modulus

Thats means we need to find **inverse modulus** of `q` then multiply `n` then
we can find lower bits of `p`  

Thanks to Python Crypto library, calculate this is easy:  
```py  
from Crypto.Util.number import inverse  
p_high =
10782851882643568436690840861500470716392138950798808847901800880356088489358510127370728036479767973147003063168467186230765513438172292951359505497400115  
q_low =
156706242812597368863822639576094365104687347205289704754937898429597824385199919052246554900504787988024439652223718201546746425116946202916886816790677  
n =
20478919136950514294245372495162786227530374921935352984649681539174637614643555669008696530509252361041808530044811858058082236333967101803171893140577890580969033423481448289254067496901793538675705761458273359594646496576699260837347827885664785268524982706033238656594857347183110547622966141595910495419030633639738370191942836112347256795752107944630943134049527588823032184661809251580638724245630054912896260630873396364113961677176216533916990437967650967366883162620646560056820169862154955001597314689326441684678064934393012107591102558185875890938130348512800056137808443281706098125326248383526374158851

p_low = n * inverse(q_low,2**512) % 2**512  
```  
Then add the lower bits with higher bits:  
```py  
p = p_high << 512 | p_low  
```  
After that find `q` with `n` divide by `p`, then calculate `d` to decrypt the
flag!

```py  
q = n // p  
assert(n==p*q)  
phi = (p-1)*(q-1)  
d = inverse(e,phi)  
print(long_to_bytes(pow(c,d,n)))  
# b'flag{H4lf_4nd_H4lf}'  
```  
Thats the flag! [Full python script](solve.py)

## Flag  
```  
flag{H4lf_4nd_H4lf}  
```

## Alternative solution  
Another solution is to calculate the high bits of `q` using high bits of `p`

Just `n` divide by high bits `p` then ignore the lower bits and add it with
the high bits of `q`:

```py  
q_high = n//(p_high<<512) >> 512  
q = q_high << 512 | q_low  
```  
But this method might need to minus few value because of the lower bits
missing

Example if n=1234\*5678=7006652  
```  
We know p=12?? q=??78  
7006652 / 1200 = 5838  
58 - 2 = 56  
```  
But in this case no need to minus it is good:  
```py  
q_high = n//(p_high<<512) >> 512  
q = q_high << 512 | q_low  
p = n // q  
assert(n==p*q)  
phi = (p-1)*(q-1)  
d = inverse(e,phi)  
print(long_to_bytes(pow(c,d,n)))  
```

Original writeup (https://github.com/Hong5489/hsctf2021/tree/main/satrapa).