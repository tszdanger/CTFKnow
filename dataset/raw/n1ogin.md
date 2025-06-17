# Task  
> To prevent any adversary sitting in the middle from eavesdropping, we apply
> hybrid encryption in our n1ogin system.

> nc 43.155.59.224 7777

We are provided 4 files: server.py, packet.pcapng, n1ogin.pub, client.py.  
Link to download them (if not active, ask us):
https://drive.google.com/file/d/1FprtxVB6Tt7ZZsfuYn9LGDS_iT2INXEZ/view?usp=sharing  
In short: client uses server's public key n1ogin.pub to create a packet in
which it sends a password by combining different cryptography functions,
server verifies it using the private key and the appropriate functions,
according to the protocol; our goal is to login as admin, and in packet.pcapng
there is a successful authentication, so it's a known ciphertext scenario.  
Now, let's see the actual protocol.  
The client sends a JSON packet:

```  
{  
   "rsa_data": rsa_data.hex(),  
   "aes_data": aes_data.hex()  
}  
```

where, conceptually:

```  
rsa_data = pow(PKCS_1_pad(aes_key + hmac_key), e, n)  
```

```(e, n)``` are taken from n1ogin.pub, whereas ```aes_key``` and
```hmac_key``` are randomly generated, along with the ```iv```:

```  
iv = os.urandom(16)  
aes_key = os.urandom(24)  
hmac_key = os.urandom(24)  
```

```aes_data``` is ```iv + cipher + mac```, where ```cipher``` is the AES-CBC
encryption of a ```content```, and ```mac``` is a repeated HMAC-MD5 computed
starting from ```iv + cipher```:

```  
mac = iv + cipher  
   for _ in range(7777):  
       h = hmac.HMAC(hmac_key, hashes.MD5())  
       h.update(mac)  
       mac = h.finalize()  
aes_data = iv + cipher + mac  
```

The ```content``` is like that (```choice``` can be either "register" or
"login"):

```  
content = json.dumps({  
       "choice": "register" or "login",  
       "timestamp": int(time.time()),  
       "nonce": os.urandom(8).hex(),  
       "username": username,  
       "password": password  
   })  
```

```username``` and ```password``` are user-provided.  
The server receives the packet (denoted as ```envelope```) and handles it
using an ```handle``` function.  
The ```handle``` function wraps all the code in a try-except block, returning
a generic ```error``` message. It performs the following actions:

- Loads the JSON packet;  
- Decrypts ```rsa_data``` using server's private key in function ```RSA_decrypt```, obtaining ```aes_key || hmac_key```;  
- Decrypts ```aes_data```, with the function ```AES_decrypt```, which also checks the ```mac``` for integrity and authenticity and returns some error message, which in any case is mapped to the generic ```error``` message mentioned before;  
- Loads ```content``` from the decrypted JSON;  
- Checks if the ```nonce``` was already observed;  
- Checks the time window of the ```timestamp```;  
- Calls ```login```, ```register``` or returns ```error``` according to the value of ```choice```.

Let's go deeper in any single step.  
If the JSON fails to parse, an exception occurs and an ```error``` is
returned.  
```RSA_decrypt``` function is very simple, it decrypts the ciphertext and then
check PKCS1 padding. If the padding is okay, it returns the last 48 bytes of
the plaintext (see PKCS1 padding specs), else it returns 48 random bytes, to
prevent Bleichenbacher's attack.  
```AES_decrypt``` function first separates ```aes_key``` and ```hmac_key```,
then it separates ```iv```, ```cipher``` and ```mac```; so it decrypts
```cipher``` using ```aes_key``` and ```iv```, then it checks the PKCS7
padding and returns an error message if the check fails. At last it checks the
```mac```, using the same procedure used by the client to generate it, and
returns an error message if the check fails. Remember that both the error
messages are masked under the hood of the same ```error``` message, which will
be sent to the client in case of error.  
The ```nonce``` is checked against a set, which is empty every time the
program starts; this means that the ```nonce``` check makes sense only if a
replay attack is attempted within the same connection.  
The ```timestamp``` check has an absolute time window of 30 seconds:
```abs(int(time.time()) - timestamp) < 30```.  
At this point, ```login``` or ```register``` is called.  
Users are handled in a dict ```{username:password_hash}```.  
```register``` doesn't allow to overwrite entries in Users dict, and doesn't
allow ```len(username) > 20```.  
```login``` checks the existence of the ```username``` and checks the
```password``` hash against the one stored in Users dict. If the check is
okay, it calls ```echo_shell``` function, which allows to get the flag if you
managed to login as admin.  
The ```password``` hash is computed using the following function:

```  
def cal_password_hash(password):  
   hash = password.encode() + SALT  
   for _ in range(7777):    # enhanced secure  
       digest = hashes.Hash(hashes.MD5())  
       digest.update(hash)  
       hash = digest.finalize()  
   return hash  
```

The procedure is similar to the one used for the ```mac```, but it just uses
MD5 iteratively (not HMAC-MD5). ```SALT``` is secret.  
This is everything about the authentication protocol. Let's analyze the public
key and the pcap file.  
n1ogin.pub is a 2048 bit RSA public key, generated with openssl (there is a
comment in server.py stating that).  
In the capture file there is a single TCP connection, with the following
conversation:

```  
Welcome to the n1ogin system!  
> {"rsa_data":
> "391b06a1740b8c9cf1c8d2bb66ba5b191caa8534b4be18c22ce81069658dd2cd3ca3a8d1a3fc8dfab4b68a6b076bf89be807404e0a98dd1bf9daaf8ba34e0556131d3e56cae61c0302d24a177481209e82de7ecf91c2fe66aa39162d7af9c2fdabaf0c444badfc6b82b071fda8e3b26d4d3e57dba25c36298601ae0153c73b7469c472ac4702531c38849772e7c6e24313e6eb7def64a7bec1c21150c1fded52b3ca716d4444b4d75836dff8c92a371f6256ee7a48034f6d5ea949d982f9f05c04d3d7cce10bd11b806cc02088b42fa0cb069390700fb586287ba224ea0b210ebd0479a4f1d2ef5f914bcc861125b7d8d714cf0feecb515c1b1ef869e91ca179",
> "aes_data":
> "1709bf9489f6df6dc31491cee4711f7a2a3e050f1ed3e9772442e8a8483e341313713383dd31fbf0133d55e977b8edf54ba832002ee4ee52da32c260b083a35b01626201c36dad6fca7b2be2aa03d90bf5c9a601a24149f55cdcd39f0bf6a032bfabeebee5259a21e188f5c5f8776cd9d7c072054781169174bddbc390e6da21bd7b85f76c93f48914fb1958ac89e464511d9a17fb2174aab825cb13eb3f0dfa"}  
admin login ok!  
admin@local> 777777777777777  
777777777777777  
admin@local> exit  
```

This is a successful authentication as admin, which gives us some hints.

# Attack vectors  
The first idea that comes to mind is a replay attack.  
The ```nonce``` is useless in blocking replay attacks, because the collection
of observed nonces is reset for each connection.  
Anyway, we are blocked by the ```timestamp```.  
The ```rsa_data``` packet seems not vulnerable, because it is encrypted using
a 2048 bit RSA key using PKCS1 padding, and is protected against
Bleichenbacher's attack: whether the pad check fails or not, it follows the
same code path, resulting in the PKCS7 padding check failing after AES
decryption. This is because the resulting ```aes_key``` is taken from
decrypted message, which is random if the PKCS1 pad check fails, else it is
```s * M```, where ```M``` is ```aes_key || hmac_key```, and ```s``` is the
chosen value for the multiplication with ```C = rsa_data```, that is,
according to the attack: ```C' = C * s**e mod n```.  
It's useful to split ```cipher``` from ```aes_data``` in blocks; we have a
partially known plaintext, because we know how ```content``` is built. We can
see from ```cipher``` that we have 8 blocks; let's see the plaintext, filling
unknown bytes in ```timestamp```, ```nonce``` and ```password```:

```  
{"choice": "logi  
n", "timestamp":  
1637422729, "no  
nce": "163ae3421  
69b5674", "usern  
ame": "admin", "  
password": "AAAA  
AAAAAAAAAAAAA"}  
```

The password will be at least 4 characters and at most 17 characters. From
server.py, we have the hint that it follows the "strong password policy", so
it contains lowercase, uppercase, digits and punctuation characters.  
If we wanted to play with these blocks, like duplicating some of them, doing
CBC bitflipping and so on, we would broke the ```mac``` check.  
It also seems that we can't do a CBC padding oracle attack because we've got a
generic ```error``` message.  
Forging a valid ```mac``` by using approaches like hash length extension
attack isn't feasible, because it is computed using HMAC.  
We don't even have the hash of admin's ```password```, so it's difficult to
work on MD5 collisions. An idea was that, in theory, if you compute MD5 many
times starting from two different values, at a certain point the two processes
should converge to the same value. But maybe this is not practical in our
case, with a number of iterations equal to 7777. Anyway, we observe that this
number of iteration is enough to take a sensitive computation time.  
This observation leads us to the conclusion that we can use the elapsed time
as oracle for the CBC padding oracle attack. In fact, in ```AES_decrypt``` the
server first checks the padding and returns if the check fails, then it checks
the ```mac```. The ```mac``` check takes more time, ~100 ms delta on the
challenge server (it's hard to say for sure, because it's hard to make a
remote timing attack: there is network jitter and there are the other users
stressing the server in a non-deterministic way).  
Before diving into the technical details of the exploit, it's useful to carry
here ```AES_decrypt``` function, so long as it is our target:

```  
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  
from cryptography.hazmat.primitives import hashes, hmac

def AES_decrypt(key, enc_data):  
   # key: aes_key || hmac_key  
   aes_key = key[:24]  
   hmac_key = key[24:]  
   # enc_data: iv || cipher || mac  
   iv, cipher, mac = enc_data[:16], enc_data[16:-16], enc_data[-16:]

   aes = Cipher(algorithms.AES(aes_key), modes.CBC(iv))  
   decryptor = aes.decryptor()  
   data = decryptor.update(cipher) + decryptor.finalize()

   # check padding  
   print(data)  
   data = unpad(data)  
   if not data:  
       return None, "padding error"

   # check hmac  
   cal_mac = iv + cipher  
   for _ in range(7777):    # enhanced secure  
       h = hmac.HMAC(hmac_key, hashes.MD5())  
       h.update(cal_mac)  
       cal_mac = h.finalize()  
   if cal_mac != mac:  
       return None, "hmac error"

   return data, None  
```

We also included the imported libraries, for completeness.

# Exploit

In order to perform a remote time-based CBC padding oracle attack we have to
understand how this type of attack works and how to extract the error type
from the elapsed time.

A padding oracle attack consists of multiple decryption requests aimed at
obtaining informations through the response of the server: if the padding
validation is successful we obtain a decrypted byte, otherwise we need to
retry with a different input. Using this approach we can decrypt a block with
at most 256*BLOCK_SIZE requests, far fewer than the usual 256^BLOCK_SIZE (256
raised to BLOCK_SIZE).

Let's analyze briefly our exploit code (a modified version of the code from
https://github.com/jjcomline/padding-oracle-attack):

```  
def attack_message(msg: bytes, _seal: bytes, n: int, HOST: str, PORT: int,
first_block = 0) -> str:  
   plaintext = [0]*BLOCK_SIZE  
   current = 0  
   message=""

   # I devide the list of bytes in blocks, and I put them in another list  
   number_of_blocks = int(len(msg)/BLOCK_SIZE)  
   blocks = [msg[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE] for i in
(range(number_of_blocks))]

   for z in range(first_block, len(blocks)-1):  
       cipherfake = [0] * BLOCK_SIZE  
       for itera in range(1,BLOCK_SIZE+1): #the length of each block is 16. I start by one because than I use its in a counter  
           found = False  
           if plaintext[-itera] == 0:  
               for v in gen(blocks[z][-itera], itera):  
                   cipherfake[-itera]=v  
                   print(f"TEST: {v}")

                   # the idea is that I put in 'is_padding_ok' the cipherfake(array of all 0) plus the last block  
                   # if the function return true I found the value  
                   r = None  
                   while (r == None):  
                       r = is_padding_ok(bytes(cipherfake)+blocks[z+1], _seal, HOST, PORT, n)  
                       if r == True:  
                           if is_padding_ok(bytes(cipherfake)+blocks[z+1], _seal, HOST, PORT, n):  
                               found = True  
                               current=itera  
                               plaintext[-itera]= v^itera^blocks[z][-itera]  
                               print(bytes(plaintext))  
                           else:  
                               r = False  
  
                   if found:  
                       break  
           else:  
               current = itera

           for w in range(1,current+1):  
               cipherfake[-w] = plaintext[-w]^itera+1^blocks[z][-w] #for decode the second byte I must set the previous bytes with 'itera+1'

       for i in range(BLOCK_SIZE):  
           if plaintext[i] >= 32:  
               char = chr(int(plaintext[i]))  
               message += char  
           print(message)

   print("Crack: " + message + "\n")  
   return str.encode(message)  
```

Assume the server runs a less secure code that sends us the more specific
error when one of it occurs. When our simplified oracle decrypts an
```aes_data``` made of an ```IV```, a ```ciphertext``` of length BLOCK_SIZE
(16) and a ```HMAC``` it follows the following procedure:  
- divide the ```aes_data``` in its parts:  
 > ```iv, cipher, mac = enc_data[:16], enc_data[16:-16], enc_data[-16:]```  
- perform the ```AES_decrypt``` using the single block of the ```cipher``` and ```aes_key```:   
 > ```dec = decrypt(cipher, key)```  
- xor the decrypted block with the ```iv```:  
 > ```data = xor(dec, iv)```  
- checks if the padding is correct:  
 > ```pad(data[:-data[-1]]) == data```  
- return ```OK``` or an error not related to this process if the padding is correct, ```PAD_ERROR``` otherwise.

If we don't get a ```PAD_ERROR``` we can recover the decrypted byte:

```  
cipher[i] decrypts to dec[i]^iv[i]  
dec[i] is plain_blocks[N][i]^cipher_blocks[N-1][i] # N > 0  
```

So to decrypt the entire ciphertext we choose a block at a time and first we
iterate over the last byte.

```  
iv = [0]*BLOCK_SIZE  
cipher = CIPHER_BLOCK[N]  
mac = "\x00"*BLOCK_SIZE

for i in range(256):  
   iv[-1] = i  
   aes_data = bytes(iv) + cipher + mac  
   res = oracle_decrypt(aes_data)  
   if res == "OK": # this happens if dec[i]^iv[i] == b"\x01"  
       last_byte = 1^iv[i]^CIPHER_BLOCK[N-1][i]  
```

After having found it, we have to change the known part of the ciphertext in
order to have it decrypted as the expected padding for the next round and
iterate over the next bytes from right to left.

This attack works fine when the server gives us a clear error message, but the
challenge's server returns, instead, a generic error. Using the fact that the
hmac generation is quite slow we can setup a time attack to recover the real
error ("pad error" vs "hmac error").  
Let's see the code:

```  
client_modified.py:

...  
def gen(c: int, index: int):  
   for a in ALPHABET:  
       v = c ^ index ^ ord(a)  
       print(f"CHAR: {a}")  
       yield v

def findRefs(verbose = False) -> Tuple[float, float]:  
   with remote(HOST, PORT) as conn:  
       base_envelope = login()  
       send_envelope(base_envelope, conn, verbose=verbose)

   pad_fails = []  
   mac_fails = []  
  
   iv = b"\x00"*16  
   cipher = b"A"*16  
   mac = b"\x00"*16  
   pad_fail = iv + cipher + mac  
   pad_fail_envelope = base_envelope.copy()  
   pad_fail_envelope['aes_data'] = pad_fail.hex()

   with remote(HOST, PORT) as conn:  
       send_envelope(None, conn, verbose=False)  
       for _ in range(N):  
           _, elapsed = send_envelope(pad_fail_envelope, conn, verbose=verbose)  
           pad_fails.append(elapsed)

   aes_data = bytes.fromhex(base_envelope["aes_data"])  
   iv, cipher = aes_data[:16], aes_data[16:-16]  
   mac_fail = iv + cipher + b"A"*16  
   mac_fail_envelope = base_envelope.copy()  
   mac_fail_envelope['aes_data'] = mac_fail.hex()

   with remote(HOST, PORT) as conn:  
       send_envelope(None, conn, verbose=False)  
       for _ in range(N):  
           _, elapsed = send_envelope(mac_fail_envelope, conn, verbose=verbose)  
           mac_fails.append(elapsed)

   min_pad_fail_elapsed = min(pad_fails)  
   min_mac_fail_elapsed = min(mac_fails)

   if verbose:  
       print(f"{pad_fails} = ")  
       print(f"{mac_fails} = ")  
       print(f"{min_pad_fail_elapsed = }")  
       print(f"{min_mac_fail_elapsed = }")  
  
   return min_pad_fail_elapsed, min_mac_fail_elapsed  
...  
```

```  
oracle.py:

from Crypto.Cipher import AES  
from Crypto import Random  
from client_modified import send_envelope, findRefs  
from pwn import *

KEY_LENGTH = 16  # AES128  
BLOCK_SIZE = AES.block_size  
PRINT = True

def is_padding_ok(data, _seal, host, port, n):  
   ref_value = sum(findRefs()) / 2

   mac = b'A' * 16  
   _seal['aes_data'] = data + mac  
   _seal['aes_data'] = _seal['aes_data'].hex()

   if PRINT:  
       print(f"aes_data = {_seal['aes_data']}")  
  
   with remote(host, port) as conn:  
       times = []  
       for _ in range(n):  
           _, elapsed = send_envelope(_seal, conn)  
           times.append(elapsed)  
       min_time = min(times)  
  
   if PRINT:  
       print(f"{ref_value = }")  
       print(f"{min_time  = }")  
       print()  
  
   if min_time >= ref_value and min_time < 2*ref_value:  
       return True  
   elif min_time < ref_value:  
       return False  
   else:  
       return None  
```

Sending ```N``` times a fixed request, that fails with a known error, we
obtain ```N``` measurements for the ```elapsed time``` that differ because of
multiple factors; the major ones were the jitter of the network and the lack
of time isolation of the server, which was also attacked by other players. To
obtain a reliable reference time to compare our ```test padding``` request to,
we calculate the minimum among ```N``` ```elapsed times``` and assume it as
the one with the minimum impact of random variables.

Found the reference times for the ```pad error``` and ```mac error```, we use
as ```ref_value``` the mean between them; we send our payload and compute the
```elapsed time``` adjusting it with the same method as before: if N is big
the result has a high probability of being correct (and we get a more reliable
estimation of ```latency```), but the process becomes really slow.

To retrieve the password of the admin from ```aes_data```, we combine the
function ```is_padding_ok``` with the CBC padding oracle attack to decrypt the
last two blocks of the ciphertext, trying a second time on every success to be
sure that we didn't encounter a false positive.

In order to keep the process time-short enough, we set the ```N``` constant to
10 and introduced a ```gen``` function to reduce the brute-force space to only
the printable characters. Unluckily, the exploit took us too much time and we
finally found the password one hour after the end of the CTF.

The password was ```R,YR35B7^r@'U3FV``` and after a successful login we
requested the ```FLAG``` and got
```n1ctf{R3m0t3_t1m1ng_4ttack_1s_p0ssibl3__4nd_u_sh0uld_v3r1fy_th3_MAC_f1rs7}```  

Original writeup
(https://pwnthenope.github.io/writeups/2021/11/22/n1ogin.html).