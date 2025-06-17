## Trunc

### Challenge  
> I wish I could say more, but I don't want to!  
> `nc 02.cr.yp.toc.tf 23010`  
>
> [TRUNC.txz](https://cr.yp.toc.tf/tasks/TRUNC_dd1e2d91b790125fdfc7596f0076fa476446d2fb.txz)

```python  
#!/usr/bin/env python3

from Crypto.Util.number import *  
from hashlib import sha256  
import ecdsa  
from flag import FLAG

E = ecdsa.SECP256k1  
G, n = E.generator, E.order

cryptonym = b'Persian Gulf'

def keygen(n, G):  
   privkey = getRandomRange(1, n-1)  
   pubkey = privkey * G  
   return (pubkey, privkey)

def sign(msg, keypair):  
   nbit, dbit = 256, 25  
   pubkey, privkey = keypair  
   privkey_bytes = long_to_bytes(privkey)  
   x = int(sha256(privkey_bytes).hexdigest(), 16) % 2**dbit  
   while True:  
       k, l = [(getRandomNBitInteger(nbit) << dbit) + x for _ in '01']  
       u, v = (k * G).x(), (l * G).y()  
       if u + v > 0:  
           break  
   h = int(sha256(msg).hexdigest(), 16)  
   s = inverse(k, n) * (h * u - v * privkey) % n  
   return (int(u), int(v), int(s))

def verify(msg, pubkey, sig):  
   if any(x < 1 or x >= n for x in sig):  
       return False  
   u, v, s = sig  
   h = int(sha256(msg).hexdigest(), 16)  
   k, l = h * u * inverse(s, n), v * inverse(s, n)  
   X = (k * G + (n - l) * pubkey).x()  
   return (X - u) % n == 0

def die(*args):  
   pr(*args)  
   quit()

def pr(*args):  
   s = " ".join(map(str, args))  
   sys.stdout.write(s + "\n")  
   sys.stdout.flush()

def sc():  
   return sys.stdin.readline().strip()

def main():  
   border = "+"  
   pr(border*72)  
   pr(border, " hi all, welcome to the high secure elliptic curve signature
oracle!", border)  
   pr(border, " Your mission is to sign the out cryptonym, try your best :)
", border)  
   pr(border*72)

   keypair = keygen(n, G)  
   pubkey, privkey = keypair

   while True:  
       pr("| Options: \n|\t[P]rint the pubkey \n|\t[S]ign \n|\t[V]erify \n|\t[Q]uit")  
       ans = sc().lower()  
       if ans == 'p':  
           pr("| pubkey =", pubkey.x(), pubkey.y())  
       elif ans == 's':  
           pr("| send your hex message to sign: ")  
           msg = sc()  
           try:  
               msg = bytes.fromhex(msg)  
           except:  
               die("| your message is not valid! Bye!!")  
           if msg == cryptonym:  
               die('| Kidding me? Bye')  
           msg = msg[:14]  
           sig = sign(msg, keypair)  
           pr("| sign =", sig)  
       elif ans == 'v':  
           pr("| send your hex message to verify: ")  
           msg = sc()  
           try:  
               msg = bytes.fromhex(msg)  
           except:  
               die("| your message is not valid! Bye!!")  
           pr("| send the signature separated with comma: ")  
           sig = sc()  
           try:  
               sig = [int(s) for s in sig.split(',')]  
           except:  
               die("| your signature is not valid! Bye!!")  
           if verify(msg, pubkey, sig):  
               if msg == cryptonym:  
                   die("| Good job! Congrats, the flag is:", FLAG)  
               else:  
                   pr("| your message is verified!!")  
           else:  
               die("| your signature is not valid! Bye!!")  
       elif ans == 'q':  
           die("Quitting ...")  
       else:  
           die("Bye ...")

if __name__ == '__main__':  
   main()  
```

### Solution  
Here we have a ECDSA-like signature scheme: nonces $k$ and $l$ are generated
in such a way, that they always have their 25 LSBs dependent only on private
key, thus always the same, then $u$ and $v$ are obtained as $x$-coordinates of
$kG$ and $lG$ respectively, where $G$ is a generator on the curve `secp256k1`,
then $h$ = `sha256(msg)` and $s \equiv k^{-1}(hu - vd) \mod n$ are computed,
where $d$ is the private key and $n$ is the order of the curve. $(u, v, s)$ is
a signature for $h$.

Verification works as follows: again, $h$ = `sha256(msg)` is computed, then $k
\equiv hus^{-1} \mod n$ and $l \equiv vs^{-1} \mod n$ are computed, after that
$X$ is derived as $x$-coordinate of $kG - lP$, where $P = G * d$ is the public
key. Signature verifies iff $X \equiv u \mod n$.  
During interaction with the service we can obtain the public key by sending
`p`, sign any message (except `Persian Gulf`) by sending `s`, verify a
signature for a message with `v`, and if the signature for `Persian Gulf`
verifies, we are given the flag, and quit with `q`.

This is an unintended solution, which doesn't exploit odd nonce generation
during signature creation.  
If $h_1$ is a hash of some message $m$, and $h_2$ is the hash for `Persian
Gulf`, we can write $h_2 \equiv m h_1 \mod n$, and if $(u_1, v_1, s_1)$ is a
valid signature for $h_1$, then $(u_1, v_1m, s_1m)$ is a valid signature for
$h_2$.

Proof: during verification of $h_1$ we have $k \equiv h_1u_1s_1^{-1} \mod n$
and $l \equiv v_1s_1^{-1} \mod n$. During verification of $h_2$ we have $k
\equiv h_1mu_1(ms_1)^{-1} \equiv h_1mu_1m^{-1}s_1^{-1} \equiv
h_1u_1s_1^{-1}\mod n$ and $l \equiv v_1m(s_1m)^{-1} \equiv v_1ms_1^{-1}m^{-1}
\equiv v_1s_1^{-1}\mod n$, so $k, l$ are the same, thus $X$ is the same. And
since $u$ is also the same, this signature will also verify.

#### Implementation

```python  
#!/usr/bin/env python3  
from pwn import remote  
from ecdsa import SECP256k1  
from hashlib import sha256

n = SECP256k1.order  
m1 = b'lol' # any other message is fine  
m2 = b'Persian Gulf'  
h1 = int(sha256(m1).hexdigest(), 16)  
h2 = int(sha256(m2).hexdigest(), 16)  
m = h2 * pow(h1, -1, n) % n  
r = remote("02.cr.yp.toc.tf", 23010)  
for _ in range(9):  
   r.recvline()  
r.sendline('s')  
r.recvline()  
r.sendline(m1.hex())  
u1, v1, w1 = eval(r.recvline()[8:])  
u2, v2, w2 = u1, v1 * m % n, w1 * m % n  
for _ in range(5):  
   r.recvline()  
r.sendline('v')  
r.recvline()  
r.sendline(m2.hex())  
r.recvline()  
r.sendline(','.join(map(str, [u2, v2, w2])))  
print(r.recvline().decode().strip().split()[-1])  
r.close()  
```  
##### Flag

`CCTF{__ECC_Bi4seD_N0nCE_53ns3_LLL!!!}`

Original writeup (https://blog.cryptohack.org/cryptoctf2021-hard#trunc).