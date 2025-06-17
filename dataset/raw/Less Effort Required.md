**Challenge Description: I found a public key and ciphertext on the ground
near a restaurant in South Boston. Can you decrypt it for me? It shouldn't
take too much effort.**

Given ecnryption file , ciphertext, public key files  
```  
from Crypto.PublicKey import RSA

def encrypt_flag(plaintext_bytes):  
   RSAkey = RSA.generate(1024)  
   n = getattr(RSAkey.key, 'n')  
   e = 5  
   plaintext_bytes += b'\x00'  
   plaintext = int.from_bytes(plaintext_bytes, 'big')  
   ciphertext = pow(plaintext, e, n)  
   open('ciphertext', 'w').write(str(ciphertext))  
   public_key = str(n) + ":" + str(e)  
   open('public_key', 'w').write(public_key)  
```  
Public key is,  
```  
n =
105764039675765007162224197946041421610988226034822789741202355465038405474039844301402146302908742536731331641437484787719599778194205333004482617077526529379473501342486898353691458150850096153562792549383987722885036435071184194348535804171098527517150958992100793020614109813938620093243709325590796177891  
e = 5  
```  
CIphertext is,  
```  
c =
40030182544273856015788999062464973403472186630147528555052489762516210821795493031619376345647069575950526306492922573846162431037037824967074058132327917359025595463728944947118480605422897682821384491771926743103021286982319660969379132360886299787840185308892024028684314873509707776  
```

As given challenge name, don't think much to solve the challenge.

**The Vulneralability:**  
Here, e is very small. So that's the vulneralability.  
So,  
plaintext is just the eth root of the ciphertext!  
Here is complete exploit,  
```  
from Crypto.Util.number import *  
import gmpy

c =
40030182544273856015788999062464973403472186630147528555052489762516210821795493031619376345647069575950526306492922573846162431037037824967074058132327917359025595463728944947118480605422897682821384491771926743103021286982319660969379132360886299787840185308892024028684314873509707776  
e = 5  
m = gmpy.root(c,e)[0]  
flag = long_to_bytes(m)  
print flag  
#UMDCTF-{f1x_y0ur_3xp0s}  
```  
**Flag:** UMDCTF-{f1x_y0ur_3xp0s}