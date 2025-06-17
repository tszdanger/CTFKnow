Note, you can see this writeup in its [Original
Post](https://www.hackinprovence.fr/balccon-katherine-ceta-iones-writeup/).

Catherine Zeta-Jones was born on September 25th, which was the starting day of
the CTFs, on certain time zones.

## Goals

The server code is available, but that's all. We have to connect to the server
and convince it we are worth of the flag.

Looking at the code, the target is to be identified as a BFF, so that the
server gives us the `FLAG`:

```  
def communicate():  
   # [...]

   # We are really talking to a friend  
   if(peer_publickey_encoded in best_friends):  
       print("Hello BFF. Here is your flag: {}".format(FLAG))  
       exit(0)  
   else:  
       print("Well done, friend. Now sod off.")  
```

To reach this part of the `communicate()` function, we have to pass the
authentication (which uses Elliptic Curve Diffie-Hellman) to prove that we
possess the private key associated to the `peer_publickey` of a `best_friend`
(we also have to make a ECDH Ephemeral, but that should be ok).

The ECDH authentication part:

```  
   # Authenticate the peer with the identity keys to prevent Man-in-the-middle  
   sharedkey_static = private_key.exchange(peer_publickey)  
```

Because the pubkey of the BFF is hardcoded (`best_friends =
["SgZSsPzLpfoEqnJojn+lftJekF7Q0yKYqcGSAOL2cyM="]`), and there is no mean to
add someone to the best friend list, we have to `impersonate` the BFF without
her private key.

To be more precise, we have to obtain the `sharedkey_static`.

## KCI: how it works

The initials of Katherine Zeta-Iones refers to KCI, which probably means Key
Compromise Impersonation. The idea behind a KCI attack is to impersonate
someone with the use of a stolen or comprised key. This last sentence seems
obvious: you can impersonate anyone whose key is compromised...

The KCI attack is more subtle: when Malory talks to Katherine, and Katherine
tries to authenticate Malory as her BFF, if Malory knows Katherine's private
key, they can impersonate `anyone`. This is because knowing Katherine's secret
makes Malory able to also make the ECDH (in our case, obtain
`sharedkey_static`).

Now, specifically, saying that Malory can `impersonate `anyone means that
Malory can pretend they have the private key of any public key, if they know
Katherine's private key.

## Still, where are private keys?

We could target the BFF's private key, but we don't any clue for it. The
public key is available in the code, but it is Curve25519, so we have no hope
of cracking its private key.

(we also have Katherine's public key when connecting to the server
(`ZIggNb0BcxBYnplA+AQNehxlUG8/x0okCfFJnoHZFFA=`), but it is the same
difficulty to crack it)

So we have to target Katherine's key. It simpler than it sounds! Katherine's
authentication is all based on a pin:

```  
def get_server_privatekey(pin: str) -> x25519.X25519PrivateKey:  
   digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())  
   digest.update(pin.encode())  
   privatekey_bytes = digest.finalize()  
   return x25519.X25519PrivateKey.from_private_bytes(privatekey_bytes)

private_key = get_server_privatekey(argv[1])  
```

A pin is usually a small password made of numbers. A very unsecure way, but
handy, to protect a private key... We can brute force pins and check if we
obtained the correct public key:

```  
def encode_publickey(key: x25519.X25519PrivateKey) -> str:  
   return
b64encode(key.public_key().public_bytes(encoding=serialization.Encoding.Raw,
format=serialization.PublicFormat.Raw)).decode("ascii")  
```

Let's crack it:

```  
def crack_server_key():  
   # Note: Catherine Zeta-Jones is born on 1969/09/25  
   print('Trying pins with digits and increasing length 0000 0001')  
   for r in range(1,6):  
       print('Testing length', r)  
       for pin in product('0123456789', repeat=r):  
           pin = ''.join(pin)  
           if encode_publickey(get_server_privatekey(pin)) == server_puk_enc:  
               print('Cracked! pin:', pin)  # 7741  
               return  
```

Now we have Katherine's private key. Don't tell her! Because we can now
compute the `sharedkey_static` We can be the BFF now, but we still have to
follow the protocol...

(note that Katherine always uses the same pin (probably so that we can
authenticate her), so we can crack the pin offline, even though it took
seconds)

## Hello Katherine!

Let's put it all together:

```python  
#!/usr/bin/python3

from base64 import b64encode, b64decode  
import re  
from os import urandom  
from telnetlib import Telnet

from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives import hashes, hmac  
from cryptography.hazmat.primitives.asymmetric import x25519  
from cryptography.hazmat.primitives import serialization

ADDR = ('pwn.institute', 36667)

# Utilies taken from the server  
def get_server_privatekey(pin: str) -> x25519.X25519PrivateKey:  
   digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())  
   digest.update(pin.encode())  
   privatekey_bytes = digest.finalize()  
   return x25519.X25519PrivateKey.from_private_bytes(privatekey_bytes)  
def encode_publickey(key: x25519.X25519PrivateKey) -> str:  
   return
b64encode(key.public_key().public_bytes(encoding=serialization.Encoding.Raw,
format=serialization.PublicFormat.Raw)).decode("ascii")

# The server public key does not seem to change. We may have to crack it
offline...  
server_puk_enc = 'ZIggNb0BcxBYnplA+AQNehxlUG8/x0okCfFJnoHZFFA='  
# Result of the crack  
server_prk = get_server_privatekey('7741')

# Best_friend_puk from script  
best_friend_puk = 'SgZSsPzLpfoEqnJojn+lftJekF7Q0yKYqcGSAOL2cyM='

if __name__ == '__main__':  
   with Telnet(*ADDR) as tn:  
       text = tn.read_until(b'(2)? ').decode()  
       server_puk_enc_recv, = re.search(r'key is (.+)\.', text).groups()  
       print(text)  
       assert server_puk_enc == server_puk_enc_recv, 'Static pin hypothesis wrong'  
       # Start the exchange:  
       tn.write(b'2  
')  
       print(tn.read_until(b'key: ').decode())

       # Tell we are the BFF  
       tn.write(best_friend_puk.encode()+b'  
')  
       text = tn.read_until(b'yours? ').decode()  
       print(text)

       # KCI is done here: we build the shared static key with server's own private key instead of BFF's, which we don't know...  
       bestff_puk = x25519.X25519PublicKey.from_public_bytes(b64decode(best_friend_puk))  
       shared_static = server_prk.exchange(bestff_puk)

       # Gather the ephemereal server key, generate ours, make the DH (inspired from server's code)  
       servereph_puk_enc, = re.search(r'key is (.+)\.', text).groups()  
       servereph_puk = x25519.X25519PublicKey.from_public_bytes(b64decode(servereph_puk_enc))  
       clienteph_prk = x25519.X25519PrivateKey.from_private_bytes(urandom(32))  
       tn.write(encode_publickey(clienteph_prk).encode()+b'  
')  
       shared_epheme = clienteph_prk.exchange(servereph_puk)

       # Now build the shared secret as the server does it  
       digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())  
       digest.update(shared_static)  
       digest.update(shared_epheme)  
       sharedkey = digest.finalize()

       # We can peacefully do the chall/resp  
       text = tn.read_until(b'response? ').decode()  
       print(text)  
       chall_enc, = re.search(r'challenge: (.+)', text).groups()

       # Same, just follow the server's receipt. We are her, we do the same as her!  
       mac = hmac.HMAC(sharedkey, hashes.SHA3_256(), backend=default_backend())  
       mac.update(b64decode(chall_enc))  
       expected_response = b64encode(mac.finalize())  
       tn.write(expected_response+b'  
')  
       print(tn.read_all().decode())  
```

## Wrapping up

- Connect to a server  
- Compromise its key because of ill-secured secrets  
- Impersonate someone (KCI) and pass the challenge  
- Flag. (`BCTF{K3y_c0mprom1se_iMp3rs0nation_we11_d0ne}`)