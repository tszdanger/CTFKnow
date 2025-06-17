https://mhackeroni.it/archive/2018/06/30/google-ctf-2018-mitm.html

Original writeup (https://mhackeroni.it/archive/2018/06/30/google-
ctf-2018-mitm.html).The file `app.py` contains an implementation of Diffie-Hellman (`DHx` class),
with fingerprinting too.  
Assuming `Alice`, `Bob` and `Carol` have private keys `a`, `b` and `c`
respectively, the following desrbies the key-exchange scheme:  
1. `Alice` sends `g^a (mod p)` to `Bob`.  
2. `Bob` raises by `b`, generating `g^ab (mod p)` and sends that to `Carol`.  
3. `Carol` receives, raises by `b` and keeps that as the secret: `g^abc (mod p)`.

If we denote this chain as `A --> B --> C` then similar chains happen to get
everyone synced to the same secet: `B --> C --> A` and `C --> A --> B`.

As the name suggests, the attacker is a MiTM (man-in-the-middle) and can
interfere with all comms, but there is a catch: after all of the exchanges,
everyone compares their secrets (as fingerprinting), and `Alice` will only
send the encrypted flag if this check passes.  
This is kind of equivalent to the QR code option inside WhatsApp to ensure key
exchange hasn't been tampered.

So, as an attacker, I didn't find any way to break the d-log problem, but I do
note that the key exchange has a weekness, as the receiving party still trusts
the sending party to follow the "correct" key exchange schema.  
For example, if as an attacker I send to `Carol` some number `x` instead of
`g^ab (mod p)`, then `Carol` blindly trusts it and calculates the secret `x^c
(mod p)`. There is a limitation, however, as the code checks that the input is
stricly larger than 1 and strictly smaller than `p`.

Therefore, I have decided to supply `x = -1 = p-1 (mod p)`. Note that raising
`-1` to any power results in either `1` or `-1` (which is again, `p-1`). So,
supplying `Carol`, for instacne, with `p-1` results in her saving the joint
key as either `1` or `p-1`, randomly.  
This needs to be done to each party, and each of them "randomly" generates
either `1` or `p-1`.  
What are the chances of all parties to agree on a key? Well, there are `2^3=8`
possibilities and only in `2` of them there is an agreement, so the chances
are `2/8 = 0.25%`, which is pretty good odds.

After a successful run, we only need to guess the shared secret out of 2
possibilities (`1` or `p-1`), which is easy to do.

The solution is therefore:  
```python  
from pwn import *

import hashlib  
from Crypto.Cipher import AES  
from Crypto.Util.number import long_to_bytes

p =
0xf18d09115c60ea0e71137b1b35810d0c774f98faae5abcfa98d2e2924715278da4f2738fc5e3d077546373484585288f0637796f52b7584f9158e0f86557b320fe71558251c852e0992eb42028b9117adffa461d25c8ce5b949957abd2a217a011e2986f93e1aadb8c31e8fa787d2710683676f8be5eca76b1badba33f601f45

minus_one = p-1

output = ''  
while True:

   print('Starting attempt...')  
   conn = remote('crypto1.q21.ctfsecurinets.com', 1337)

   for i in range(3):  
       conn.recvline()  
       conn.recvuntil(': ')  
       conn.sendline(str(minus_one))  
       conn.recvline()  
       conn.recvuntil(': ')  
       conn.sendline(str(minus_one))

   conn.recvline().decode('ascii') # "Alice says"  
   output = conn.recvline().decode('ascii')  
   if 'ABORT MISSION' in output:  
       print('Attempt failed, rerying...')  
       continue  
   print('Success %s' % (output,))  
   break

crypt_bytes = bytes.fromhex(output.strip())  
iv = crypt_bytes[:16]  
encrypted = crypt_bytes[16:]

# Try key=p-1  
key = hashlib.sha1(long_to_bytes(minus_one)).digest()[:16]  
print(AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted))

# Try key=1  
key = hashlib.sha1(long_to_bytes(1)).digest()[:16]  
print(AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted))  
```

Original writeup
(https://thegoonies.github.io/2021/03/21/securinetctf-2021-mitm/).This challenge involves a Diffie-Hellman key exchange between 2 parties, Alice
and Bob. The intended solution involves establishing different keys with Alice
and Bob, however the values are so small (around 32 bits) that we can simply
solve the discrete logarithm problem (the hardness of which Diffie-Hellman's
security depends on) with brute force.

```py  
# pip install pwntools sympy pycryptodome  
import pwn  
from sympy.ntheory import discrete_log  
from Crypto.Cipher import AES

# from MITM.c  
primes = [1697841911,1438810907,666397859,941857673]  
g =
13061880230110805485346525688018595113271880103717720219673350299083396780730251766148414377512386061643807530751287373200960399392170617293251618992497053

conn_a = pwn.remote("13.233.166.242", 49154)  
conn_b = pwn.remote("13.233.166.242", 49155)

# read the 4 public values from alice  
a_pub = []  
conn_a.recvline()  
for i in range(4):  
   a_pub.append(int(conn_a.recvline()))  
conn_a.recvline()

# and from bob  
b_pub = []  
conn_b.recvline()  
for i in range(4):  
   b_pub.append(int(conn_b.recvline()))  
conn_b.recvline()

# send alice's public values to bob, and vice versa  
conn_a.sendline('\n'.join(map(str, b_pub)))  
conn_b.sendline('\n'.join(map(str, a_pub)))

# read alice's ciphertext  
ct_a = conn_a.recvline()  
ct_a = bytes.fromhex(ct_a.split(b" : ")[1].replace(b"0x", b"").decode())

# and send it to bob  
conn_b.recvline()  
conn_b.send(ct_a)

# and then read bob's ciphertext  
ct_b = conn_b.recv()  
ct_b = bytes.fromhex(ct_b.split(b" : ")[1].replace(b"0x", b"").decode())

# Now, compute the private values of both alice and bob by solving the  
# discrete logarithm problem on their public values (since g^priv = pub).  
# These aren't the actual values, but rather the values mod each of the 4  
# primes used, but that is good enough since we always operate mod those
primes  
priv_a_res = [int(discrete_log(primes[i], a_pub[i], g)) for i in range(4)]  
priv_b_res = [int(discrete_log(primes[i], b_pub[i], g)) for i in range(4)]

# Now that we know the private values, compute the AES keys  
key_a = [pow(b_pub[i], priv_a_res[i], primes[i]) for i in range(4)]  
key_b = [pow(a_pub[i], priv_b_res[i], primes[i]) for i in range(4)]

# convert from integers to byte sequences  
key_a = b''.join(x.to_bytes(4, 'little') for x in key_a)  
key_b = b''.join(x.to_bytes(4, 'little') for x in key_b)

# and decrypt the ciphertexts  
pt_a = AES.new(key_a, AES.MODE_CBC, iv=b'\x00'*16).decrypt(ct_a)  
pt_b = AES.new(key_b, AES.MODE_CBC, iv=b'\x00'*16).decrypt(ct_b)

print(pt_a + pt_b)  
# b'darkCON{d1ff13_h3llm4n_1s_vuln3r4bl3_t0_m4n_1n_th3_m1ddl3_1789}\x00'  
```

Original writeup (https://github.com/keyboard-monkeys/ctf-
writeups/blob/main/2021-darkctf/crypto_mitm.md).