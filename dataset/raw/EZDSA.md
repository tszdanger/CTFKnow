# ezdsa

## Description  
This task has two parts to it, the first part is the signer. You can send a
message to the server and it will sign it and send it back. The second part is
the verifier. The verifier will take the message and the signature of the
message and verify they match.

## Analysis  
Lets take a look at the signer code:  
```Python  
import socketserver  
import random  
import ecdsa

key = open("secp256k1-key.pem").read()  
sk = ecdsa.SigningKey.from_pem(key)

def sony_rand(n):  
   return random.getrandbits(8*n).to_bytes(n, "big")

def sign(data):  
   if data == b"admin":  
       raise ValueError("Not Permitted!")  
   signature = sk.sign(data, entropy=sony_rand)  
   return signature

class TCPHandler(socketserver.StreamRequestHandler):

   def handle(self):  
       data = self.rfile.readline().strip()  
       try:  
           signature = sign(data).hex()  
           self.wfile.write(b"Your token: " + data + b"," + signature.encode())  
       except ValueError as ex:  
           self.wfile.write(b"Invalid string submitted: " + str(ex).encode())

if __name__ == '__main__':  
   server = socketserver.ForkingTCPServer(("0.0.0.0", 10101), TCPHandler)  
   server.serve_forever()  
```  
Basic info we can get from it:  
- Every request will call `sign(our_data)`  
- `sign()` will check that our input is NOT "admin", and will sign  
- It's using some sort or rand function for the entropy of the signer  
- The ecdsa curve they are using is "secp256k1"  
- We can send it any message (besides "admin") and get the signature of the message

Now lets take a look at the verifier:  
```Python  
import socketserver  
import ecdsa  
import pyjokes  
from flag import FLAG

key = open("pub.pem").read()  
vk = ecdsa.VerifyingKey.from_pem(key)

def valid_signature(msg, sig):  
   try:  
       vk.verify(sig, msg)  
       return True  
   except ecdsa.BadSignatureError:  
       return False

class TCPHandler(socketserver.StreamRequestHandler):

   def handle(self):  
       data = self.rfile.readline().strip()  
       user, signature = data.split(b",")  
       sig = bytes.fromhex(signature.decode())  
       try:  
           if valid_signature(user, sig):  
               if user == b"admin":  
                   self.wfile.write(b"Hello admin! Here is your flag: " + FLAG)  
               else:  
                   self.wfile.write(pyjokes.get_joke().encode())  
           else:  
               self.wfile.write(b"Invalid signature!")  
       except Exception as ex:  
           self.wfile.write(b"Something went wrong!")

if __name__ == '__main__':  
   server = socketserver.ForkingTCPServer(("0.0.0.0", 10100), TCPHandler)  
   server.serve_forever()  
```  
Basic info we can get from it:  
- The handler will try to first `valid_signature`  
- `valid_signature` will use the msg and signature you provided and verify they match  
- Checks that the message you send equals "admin" before sending the flag

Since we cannot send "admin" to the signer I had to do some research into how
ecdsa works.

## How the algorithm  
An ECDSA signature is a pair of integers `(r,s)`.

The ECDSA signature algorithm works like so:  
1. `e = H(m)` where H is a hashing function (i.e sha1, sha256)  
2. Pick a random `k` such that `0 < k < n-1`  
3. Compute `(x,y) = kG` where G is the prime order of curve  
4. `r = x mod n`  
5. `s = inverse(k)*(z+r*d) mod n` where d is a private key integer and z is the leftmost bits of e  
6. Send `(m,r,s)`

The ECDSA verification algorithm works like so:  
1. `e = H(m)`  
2. `w = inverse(s) mod n`  
3. `u_1 = zw mod n` and `u_2 = zw mod n`  
4. `(x,y) = u_1*G + u_2*Q` where Q = d x Q  
5. If `r` is congruent with `x mod n` we know the signature is valid

## How we can crack it  
When I send the signer different strings to sign i noticed it would always
send something with the prefix
"13d8f71de2338048bcddd4846ea9762fa022172b6602f269c519892d8bf7e94f".... If we
think back to how the ECDSA signature looks `(r,s)` we can see that r is not
changing. This means we know that `r = x mod n` has to always be the same.
From this information we can figure out that they are using the same "random"
`k` everytime. So now lets make two request to the server with different m's.
The signer will send us back `(m1,r,s1) and (m2,r,s2)`.

Since we know k is constant we can easily solve for it with the following
equation:  
```  
k = (H(m1) - h(M2)) / (s1 - s2)  
```  
We then can solve for what x was:  
```  
x = (k*s1 - h(m1)) / r  
```

With k and x known we can now start writing the script to sign "admin" and
send to the server.

## Solution  
```Python  
# https://crypto.stackexchange.com/questions/57846/recovering-private-key-
from-secp256k1-signatures  
import ecdsa, hashlib  
from ecdsa.numbertheory import inverse_mod  
from ecdsa.ecdsa import Signature  
from ecdsa import SigningKey, VerifyingKey, der  
from pwn import *

curve          = ecdsa.SECP256k1  
text_to_sign   = b"admin"  
hash_algorithm = hashlib.sha1

def get_key_from_hash():

   m_hash1 = '21298df8a3277357ee55b01df9530b535cf08ec1'  
   sig1_hex =
'13d8f71de2338048bcddd4846ea9762fa022172b6602f269c519892d8bf7e94f77608e0387a7ba5392bd1e2b4ded1048133fb584b7686233af00a6e7c5d427e7'  
   m_hash2 = 'c692d6a10598e0a801576fdd4ecf3c37e45bfbc4'  
   sig2_hex =
'13d8f71de2338048bcddd4846ea9762fa022172b6602f269c519892d8bf7e94fdcb6d55b347bfbe8c6a37e2b7c6ca764d7bd07f52d56df2ff80df7a59cbe51ec'

   m_hash1 = int(m_hash1, 16)  
   r = int(sig1_hex[:len(sig1_hex)//2], 16)  
   sig1 = int(sig1_hex[len(sig1_hex)//2:], 16)  
   m_hash2 = int(m_hash2, 16)  
   sig2 = int(sig2_hex[len(sig2_hex)//2:], 16)

   print("m_hash1 = " + hex(m_hash1))  
   print("sig1 = " + hex(sig1))  
   print("m_hash2 = " + hex(m_hash2))  
   print("sig2 = " + hex(sig2))  
   print("r = " + hex(r))

   r_i = inverse_mod(r, curve.order)  
   m_h_diff = (m_hash1 - m_hash2) % curve.order

   for k_try in (sig1 - sig2, sig1 + sig2, -sig1 - sig2, -sig1 + sig2):

       k = (m_h_diff * inverse_mod(k_try, curve.order)) % curve.order

       s_E = (((((sig1 * k) % curve.order) - m_hash1) % curve.order) * r_i) % curve.order

       key = SigningKey.from_secret_exponent(s_E, curve=curve, hashfunc=hash_algorithm)

       if key.get_verifying_key().pubkey.verifies(m_hash1, Signature(r, sig1)):  
           print("ECDSA Private Key = " + "".join("{:02x}".format(c) for c in key.to_string())) # If we got here we found a solution  
           return key

def sign_text(priv_key):  
   sk = ecdsa.SigningKey.from_string(priv_key.to_string(), curve=curve)  
   vk = sk.get_verifying_key()  
   sig = sk.sign(text_to_sign)  
   signed_message = "".join("{:02x}".format(c) for c in sig)  
   return "{},{}".format(text_to_sign.decode("utf-8"), signed_message)

def send_message(s_m):  
   target = remote('chal.cybersecurityrumble.de', 10100)  
   print("Sending '{}'".format(s_m))  
   target.sendline(s_m)  
   target.interactive()

signed_message = sign_text(get_key_from_hash())  
print(send_message(signed_message))  
```  
Once you run this script the server will print "Hello admin! Here is your
flag: CSR{m33333333333p}".

flag = CSR{m33333333333p}

Original writeup
(https://github.com/tHoMaStHeThErMoNuClEaRbOmB/ctfwriteups/blob/master/CyberSecurityRumblectf/crypto/ezdsa/README.md).This is [FAUST](https://www.faust.ninja) playing CTF again, this time
[midnightsun](https://ctf.midnightsunctf.se/).

Team: [FAUST](https://www.faust.ninja)  
Crew: [siccegge](https://christoph-egger.org)

OK so we're looking at the EZDSA service. This is a signature service and the
task is essentially to recover the signing key. Code is reproduced below.

```python  
#!/usr/bin/python2  
from hashlib import sha1  
from Crypto import Random  
from flag import FLAG

class PrivateSigningKey:

   def __init__(self):  
       self.gen = 0x44120dc98545c6d3d81bfc7898983e7b7f6ac8e08d3943af0be7f5d52264abb3775a905e003151ed0631376165b65c8ef72d0b6880da7e4b5e7b833377bb50fde65846426a5bfdc182673b6b2504ebfe0d6bca36338b3a3be334689c1afb17869baeb2b0380351b61555df31f0cda3445bba4023be72a494588d640a9da7bd16L  
       self.q = 0x926c99d24bd4d5b47adb75bd9933de8be5932f4bL  
       self.p = 0x80000000000001cda6f403d8a752a4e7976173ebfcd2acf69a29f4bada1ca3178b56131c2c1f00cf7875a2e7c497b10fea66b26436e40b7b73952081319e26603810a558f871d6d256fddbec5933b77fa7d1d0d75267dcae1f24ea7cc57b3a30f8ea09310772440f016c13e08b56b1196a687d6a5e5de864068f3fd936a361c5L  
       self.key = int(FLAG.encode("hex"), 16)

   def sign(self, m):

       def bytes_to_long(b):  
           return long(b.encode("hex"), 16)

       h = bytes_to_long(sha1(m).digest())  
       u = bytes_to_long(Random.new().read(20))  
       assert(bytes_to_long(m) % (self.q - 1) != 0)

       k = pow(self.gen, u * bytes_to_long(m), self.q)  
       r = pow(self.gen, k, self.p) % self.q  
       s = pow(k, self.q - 2, self.q) * (h + self.key * r) % self.q  
       assert(s != 0)

       return r, s  
```

The outer service was not provided but you could pass in base64 encoded byte
arrays and got back r and s as already indicated. Looking at the final
computation for s we notice that given \\((h + k * r)\\) and \\(h, r\\) we can
easily recover \\(k\\). For this to work it would be convenient if the first
term ends up being 1. Unfortunately, the easiest way to get there is
prevented: \\(g^{q-1} = 1\\). Fortunately this is not the only exponent where
this works and a good candidate is \\((q-1 / 2)\\).

```python  
pow(gen, (q-1)//2, q)  
1  
```

From there the only thing left is solving \\(s = (h + k * r)\\). Fortunately
gmpy has the solution prepackaged again: `divm`. So we proceed by getting a
valid "signature" on \\((q-1 / 2)\\). The rest is simple calculation:

```python  
#!/usr/bin/python3  
sha1(binascii.unhexlify("%x" % ((q-1)//2))).hexdigest()  
'e6d805a06977596563941c1e732e192045aa49f0'

base64.b64encode(binascii.unhexlify("%x" % ((q-1)//2)))

gmpy2.divm(s-h, r, q)  
mpz(39611266634150218411162254052999901308991)

binascii.unhexlify("%x" % 39611266634150218411162254052999901308991)  
b'th4t_w4s_e4sy_eh?'  
```

OK so why does \\((q-1 / 2)\\) work? Essentially, the field defined \\(F_q\\)
-- calculations mod q -- has q elements additively and \\(q-1\\) elements
multiplicatively(and we're considering exponentiation as repeated
multiplication). Therefore it contains cyclic subgroups for all factors of
\\(q-1\\) and for every element \\(e\\), \\(e^o = 1\\) where o is the order of
the subgroup *that* element belongs to. as the generator is trivially not
\\(-1\\) -- the subgroup of size 2 -- \\((q-1 / 2)\\) must be a multiple of
the generated group's order.

Original writeup (https://weblog.christoph-
egger.org/Midnight_Sun_CTF_2019_EZDSA_Writeup.html).