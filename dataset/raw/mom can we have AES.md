Disclaimer: The ASCII-Diagrams are properly rendered in the
[original](https://ctf0.de/posts/uiuctf2022-mom-can-we-have-aes/).

------------

The challenge consists of two services communicating with each other:
[`server.py`](https://2022.uiuc.tf/files/db45f0c6d5e88ae21c97ba4641f6971d/server.py)
on port 1337 and
[`client.py`](https://2022.uiuc.tf/files/ebccf298bcd26b5b2258ec4279202f2f/client.py)
on port 1338.

# Services  
Most part of the provided services is used for initializing AES, which is done
with a protocol very similar to TLS. In the following I will explain the
initialization in the order of the communication and will therefore switch
between `client.py` and `server.py`.

```goat  
.--------.                            .--------.  
| client |                            | server |  
'--------'                            '--------'  
   |              AES modes               |  
   | -----------------------------------> |  
   |            client random             |  
   | -----------------------------------> |  
   |                                      |  
   |       signed hash of certificate     |  
   | <----------------------------------- |  
   |              AES modes               |  
   | <----------------------------------- |  
   |            server random             |  
   | <----------------------------------- |  
   |                                      |  
   |    RSA encrypted premaster secret    |  
   | -----------------------------------> |  
   |               AES mode               |  
   | -----------------------------------> |  
   |         AES encrypted finish         |  
   | -----------------------------------> |  
   |                                      |

```

Both scripts start with the same imports and by defining the supported AES
modes:  
```python  
from Crypto.Util.Padding import pad, unpad  
from Crypto.PublicKey import RSA  
from Crypto.Cipher import AES, PKCS1_OAEP  
from Crypto.Hash import SHA256  
from Crypto.Signature import PKCS1_v1_5

import random  
import string

from fields import cert, block_size  
from secret import flag

cipher_suite = {"AES.MODE_CBC" : AES.MODE_CBC, "AES.MODE_CTR" : AES.MODE_CTR,
"AES.MODE_EAX" : AES.MODE_EAX, "AES.MODE_GCM" : AES.MODE_GCM,  "AES.MODE_ECB"
: AES.MODE_ECB}  
```

The initialization begins at the client by generating four random characters
and sending them together with the supported AES modes to the server. TLS uses
much larger random values (32 byte) and will send some additional information
such as the protocol version.  
```python  
########## Client Hello ##########  
# Cipher suite  
print(*cipher_suite.keys(), sep=', ')

client_random = ''.join(random.SystemRandom().choice(string.ascii_uppercase +
string.digits) for _ in range(4))  
# Client random  
print(client_random)  
```

The server receives both and stores them for later use.  
```python  
########## Client Hello ##########  
# Enter encryption methods  
input_encryptions_suite = input()  
client_cipher_suite = input_encryptions_suite.split(", ")  
# Enter client random  
client_random = input()  
```

Now the server proceeds with sending his own hello, starting with a signed
hash of his certificate. In TLS, the server would send the actual certificate
and a signed hash of all previous messages.  
```python  
########## Server Hello ##########

# Certificate  
private_key = RSA.import_key(open("my_credit_card_number.pem").read())  
cipher_hash = SHA256.new(cert)  
signature = PKCS1_v1_5.new(private_key).sign(cipher_hash)  
#Signed certificate  
print(signature.hex())  
```

After that the server computes the intersection of the AES modes supported by
him and the client and sends the resulting list back to the client. In TLS,
the server chooses one of the ciphers that is understood by client and server
and sends only the selected cipher to the client.  
```python  
# select cipher suite  
selected_cipher_suite = {}  
for method in cipher_suite:  
   if method in client_cipher_suite:  
       selected_cipher_suite[method] = cipher_suite[method]

if len(selected_cipher_suite) == 0:  
   print("Honey, we have a problem. I'm sorry but I'm disowning you :(")  
   exit()

# Selected cipher suite  
print(*selected_cipher_suite.keys(), sep=', ')  
```

Finally, the server generates four random characters and sends them to the
client. As with the client random, TLS will generate a 32 byte long random
value.  
```python  
server_random = ''.join(random.SystemRandom().choice(string.ascii_uppercase +
string.digits) for _ in range(4))  
# Server random  
print(server_random)  
```

Now back to the client. It first loads the preshared public key of the server
and verifies the signature. As the certificate is preshared in this case, the
server didn't have to send it. Furthermore in TLS the public key would be read
from the certificate and not from a separate file. As an alternative to
certificates, TLS supports the Diffie-Hellman key exchange, which is covered
in last years UIUCTF challenge
[`dhke_intro`](https://ctftime.org/writeup/34637).  
```python  
########## Server Hello ##########

# verify server  
# Enter signed certificate  
server_signature_hex = input()  
server_signature = bytearray.fromhex(server_signature_hex)  
public_key = RSA.import_key(open("receiver.pem").read())  
cipher_hash = SHA256.new(cert)  
verifier = PKCS1_v1_5.new(public_key)

if not verifier.verify(cipher_hash, server_signature):  
   print("Mom told me not to talk to strangers.")  
   exit()  
```

As next step, the client parses the cipher suits supported by the server.  
```python  
# Enter selected cipher suite  
input_encryptions_suite = input()  
if len(input_encryptions_suite) == 0:  
   print(" nO SeCUriTY :/")  
   exit()

selected_cipher_suite = {}  
input_encryptions_suite = input_encryptions_suite.split(", ")  
for method in input_encryptions_suite:  
   if method in cipher_suite:  
       selected_cipher_suite[method] = cipher_suite[method]

if len(selected_cipher_suite) == 0:  
   print("I'm a rebellious kid who refuses to talk to people who don't speak
my language.")  
   exit()  
```

As last part of the parsing of the server hello, the random characters from
the server are stored for later use.  
```python  
# Enter server random  
server_random = input()  
```

As next step, the client initializes AES, starting with the generation of the
premaster secret. This is then encrypted and send to the server. As in
previous cases, the premaster secret of TLS is larger and uses 48 bytes.  
```python  
premaster_secret = ''.join(random.SystemRandom().choice(string.ascii_uppercase
+ string.digits) for _ in range(8))

cipher_rsa = PKCS1_OAEP.new(public_key)  
premaster_secret_encrypted =
cipher_rsa.encrypt(premaster_secret.encode()).hex()  
# Encrypted premaster secret  
print(premaster_secret_encrypted)  
```

Then the session key is computed from the previously generated premaster
secret and both random values.  
Because the premaster secret is send encrypted, the session key is only known
to the client and server. The use of client and server random prevents replay
attacks, as the target of the replay will choose a different one. This is
especially true for TLS, since 4 of the 32 bytes of the client and server
random are the current timestamp.  
```python  
session_key = SHA256.new((client_random + server_random +
premaster_secret).encode()).hexdigest()  
```

Now the client chooses one of the ciphers supported by client and server and
informs the server about the selected cipher.  
```python  
chosen_cipher_name = next(iter(selected_cipher_suite))  
# Using encryption mode  
print(chosen_cipher_name)  
cipher = AES.new(session_key.encode()[:16], cipher_suite[chosen_cipher_name])  
```

The server receives the premaster secret, decrypts it with its private key and
uses it to calculate the same session key.  
```python  
########## ClientKeyExchange & CipherSpec Finished ##########  
# Enter premaster secret  
encrypted_premaster_secret = input()  
cipher_rsa = PKCS1_OAEP.new(private_key)  
premaster_secret =
cipher_rsa.decrypt(bytearray.fromhex(encrypted_premaster_secret)).decode('utf-8')

session_key = SHA256.new((client_random + server_random +
premaster_secret).encode()).hexdigest()  
```

After that, the server will check wether the selected cipher is one of the
supported ones and will then initialize AES with the session key and the
selected mode.  
```python  
# Enter chosen cipher  
chosen_cipher_name = input()  
if chosen_cipher_name not in selected_cipher_suite:  
   print("No honey, I told you we're not getting ", chosen_cipher_name, '.',
sep='')  
   exit()  
cipher = AES.new(session_key.encode()[:16], cipher_suite[chosen_cipher_name])  
```

Finally the client sends an AES encrypted `finish` to the server.  
```python  
# Encrypted finish message  
print(cipher.encrypt(pad(b"finish", block_size)).hex())  
```

The server decrypts the `finish` and checks wether it is correct. This is a
final proof, that both sides have calculated the same session key.  
```python  
# Enter encrypted finish  
client_finish = input()  
client_finish = bytearray.fromhex(client_finish)

########## ServerKeyExchange & CipherSpec Finished ##########

finish_msg = unpad(cipher.decrypt(client_finish), block_size)  
assert(finish_msg == b'finish')  
```

In TLS, the server would also send a finish message over the encrypted channel
to proof the client the it has the same session key. In this challenge, the
message is not send but the client wants to receive an unencrypted `finish`
and checks it.  
```python  
########## ServerKeyExchange & CipherSpec Finished ##########  
# Confirm finish  
finish_msg = input()  
assert(finish_msg == "finish")  
```

Now the connection is established and the contents can be exchanged.

The server checks each message if it exactly matches the flag and prints a
message indicating the result.  
```python  
########## Communication ##########

# Listening...  
while True:  
   client_msg = input()  
   client_msg = unpad(cipher.decrypt(bytearray.fromhex(client_msg)),
block_size)

   if client_msg == flag:  
       print("That is correct.")  
   else:  
       print("You are not my son.")  
```

This has little to no interest for us, since we would have to guess the whole
flag at once, which is way to much effort. We can only use it to verify the
flag.

The client is much more useful. It requests a hex-encoded prefix, appends the
flag to the decoded prefix and prints the AES encrypted result.  
```python  
########## Communication ##########

while True:  
   prefix = input()  
   if len(prefix) != 0:  
       prefix = bytearray.fromhex(prefix)  
       extended_flag = prefix + flag  
   else:  
       extended_flag = flag  
  
   ciphertext = cipher.encrypt(pad(extended_flag, block_size)).hex()  
   print(str(ciphertext))  
```

This enables us to brute force the flag character by character, which can be
done in a few minutes.

# Exploit  
For solving the challenge, we used pwntools'
[`remote`](https://docs.pwntools.com/en/stable/tubes/sockets.html#pwnlib.tubes.remote.remote)
for the communication with the services and python's `string` to obtain a list
of flag characters.  
```python  
from pwn import *  
import string  
```

First we have to initialize the connection to the client. Therefore we connect
to the client and server and relay the messages from the server to the client
and vice versa.

After connecting to the services,  
```python  
def get_services():  
   # connect to server and client  
   server = remote("mom-can-we-have-aes.chal.uiuc.tf", 1337)  
   client = remote("mom-can-we-have-aes.chal.uiuc.tf", 1338)  
```

the services will send `== proof-of-work: disabled ==\n`, which we have to
skip, since this is not part of the protocol.  
```python  
   # skip proof of work message  
   client.recvline()  
   server.recvline()  
```

As first message, the client will send us the supported AES modes. As we want
to use ECB, we drop the received list and send only `AES.MODE_ECB` to the
server. We will explain this decision later, when we actually use the
properties of this mode.  
```python  
   # AES modes  
   client.recvline()  
   server.sendline(b"AES.MODE_ECB")  
```

The remaining initialization can be relayed.  
```python  
   # client random  
   server.send(client.recvline())

   # server signature  
   client.send(server.recvline())

   # server AES mode  
   client.send(server.recvline())

   # server random  
   client.send(server.recvline())

   # client encrypted premaster secret  
   server.send(client.recvline())

   # client chosen AES mode  
   server.send(client.recvline())

   # client finish  
   finish = client.recvline()  
   server.send(finish)  
```

Since the client expects a plain text `finish` and the server does not send
it, we must send it ourselves. After that we have a server and a client in
their main loop, which can be returned.  
```python  
   # send finish for client  
   client.sendline(b"finish")

   return server, client  
```

Now we come to the actual exploit and the chosen AES mode.

AES works by dividing the message to encrypt in blocks of 16 bytes. The
difference between the modes is the handling of these blocks. The simplest
mode is *Electronic CodeBook* (ECB), which just takes each block and encrypts
it separately. This has the effect, that the same plain text block will always
result in the same encrypted block. Because of this, structures are retained.
A popular example for this property is the [ECB encrypted
Tux](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB). As a
result of this insecureness, ECB is not part of the ciphers available in TLS.  
```goat  
.-------------.          .-------------.  
| plaintext 1 |          | plaintext 2 |  
'-------------'          '-------------'  
       |                        |  
       v                        v  
  .---------.              .---------.  
  | encrypt |              | encrypt |  
  '---------'              '---------'  
       |                        |  
       v                        v  
.--------------.         .--------------.  
| ciphertext 1 |         | ciphertext 2 |  
'--------------'         '--------------'  
```

We can use this insecureness to our advantage. If we send a prefix, the flag
is moved to the right, resulting in a different alignment against the block
boundaries. By changing the length of the prefix, we can adjust the position
of the flag relative to the block boundaries. In the example below we used
underscores as prefix.  
```  
     block 1          block 2  
|----------------|----------------|  
|uiuctf{FAKEFLAG}|                |  
|_______________u|iuctf{FAKEFLAG} |  
|______________ui|uctf{FAKEFLAG}  |  
```  
Let's assume, we already know the first character (which we do, since all
flags start with `uiuctf{`). We now can guess the second character by
appending the prefix used in the last row of the above example with the
already known part of the flag and our guess. If we guess the correct
character, the first block will be identical to the one requested with only
the underscores.  
```  
    block 1          block 2  
|----------------|----------------|  
|______________ui|uctf{FAKEFLAG}  |  
|                |                |  
|______________uA|uiuctf{FAKEFLAG}|  
|______________uB|uiuctf{FAKEFLAG}|  
|______________ui|uiuctf{FAKEFLAG}|  
```

With this knowledge we can begin to write the function for brute forcing one
character. It takes a connection to a `client`, the already guessed `flag` and
the `alphabet` to use as parameters. At first we request the encrypted blocks
to search for by sending only the prefix. This results in the flag being moved
to the right, such that the second block will end one character after the
already guessed flag characters. Since the encrypted flag spans over two
blocks, we send a prefix of 32 minus the number of wanted flag characters as
prefix.

For converting the string to hex, we have to convert the string to bytes first
and can then convert them to hex. As pwntools needs the data to send as bytes
and the returned hex representation is a string, we have to encode it again.  
```python  
def brute_force_char(client, flag, alphabet):  
   # get encrypted flag part  
   client.sendline(("A"*(31-len(flag))).encode().hex().encode())  
```

As the remaining blocks won't match, since they contain the remaining flag
characters in the search request and the whole flag in the guess requests, we
keep only the hex representation of the first two blocks, i.e. 64 hex
characters.  
```python  
   search = client.recvline()[:64]  
```

Now we can iterate over the given alphabet and test each character.  
```python  
   # precompute prefix  
   prefix = "A"*(31-len(flag)) + flag

   # iterate over alphabet  
   for c in alphabet:  
       # encrypt guess  
       client.sendline((prefix + c).encode().hex().encode())  
       recv = client.recvline()[:64]  
```

If the received blocks match with the search pattern, we have found the next
flag character and can abort the loop  
```python  
       # return if correct char found  
       if recv == search:  
           return c  
```

As we now have the initialization of the services and the brute forcing of one
flag character done, we can develope the main control flow and define the
alphabet of the flag. `string.printable` contains all printable ASCII
characters, including whitespace.  
```python  
ALPHABET = string.printable  
```

Furthermore we can define the known start of the flag, as its the same format
for all challenges  
```python  
flag = "uiuctf{"  
```

Before starting the brute forcing, we have to get a client. Since we do not
need the server, we can close it.  
```python  
# get services  
server, client = get_services()

# close server  
server.close()  
```

Now we brute force the flag character by character until we reach the closing
curly brace.  
```python  
while flag[-1] != "}":  
   flag += brute_force_char(client, flag, ALPHABET)

   # print progress  
   print(flag)  
```

By running this script, we get the flag after less than two minutes:
`uiuctf{AES_@_h0m3_b3_l1ke3}`.

# Optimization  
The acquisition of the search blocks can be optimized by requesting only each
of the possible 16 offsets of the flag in a block once and then reusing them.
The following example demonstrates this by brute forcing the second (compare
only the first block) and the 18. character of the flag (compare the first two
blocks).  
```  
    block 1          block 2          block 3          block 4  
|----------------|----------------|----------------|----------------|  
|______________ui|uctf{LONGFAKEFLA|G}              |                |  
|                |                |                |                |  
|______________u?|uiuctf{LONGFAKEF|LAG}            |                |  
|______________ui|uiuctf{LONGFAKEF|LAG}            |                |  
|                |                |                |                |  
|______________ui|uctf{LONGFAKEFL?|uiuctf{LONGFAKEF|LAG}            |  
|______________ui|uctf{LONGFAKEFLA|uiuctf{LONGFAKEF|LAG}            |  
```

This strategy would require to first request all possible search offsets:  
```python  
searchs = []  
for i in range(16):  
   client.sendline(("A"*(15-i)).encode().hex().encode())  
   searchs.append(client.recvline())  
```

`brute_force_char` would then use up to 15 prefix characters and compare as
many blocks as needed to include characters up to the guessed one.  
```python  
def brute_force_char(client, flag, alphabet, searchs):  
   # precompute prefix  
   prefix = "A"*(15 - len(flag)%16) + flag

   # calculate length of hex representation of prefix + guess  
   compare_length = 2 * (len(prefix)+1)

   # get search blocks  
   search = searchs[len(flag)%16][:compare_length]

   # iterate over alphabet  
   for c in alphabet:  
       # encrypt guess  
       client.sendline((prefix + c).encode().hex().encode())  
       recv = client.recvline()[:compare_length]

       # return if correct char found  
       if recv == search:  
           return c  
```

The main loop remains identical, except from `searchs` being passed as third
parameter to `brute_force_char`. Since the flag only contains 27 characters,
this optimization saves 11 requests, which is negligible compared to the up to
93 tries for the closing curly brace.

# Parallelization  
The approach used in the exploit can be parallelized by using multiple
connections. Since the session key will be different for each connection, the
encrypted plain text and therefore the search pattern will be different and
must be requested for each session. Then the alphabet can be distributed
between the connections.

A good library for this is python's
[`concurrent.futures`](https://docs.python.org/3/library/concurrent.futures.html)
library. It allows to distribute tasks between a defined number of workers and
returning finished tasks without manually querying all workers. Furthermore we
will use the `threading` library to store data at the worker threads and
`ceil` from the math library.  
```python  
import concurrent.futures as cf  
import threading  
import math  
```

The main part of `concurrent.futures` are the executors. They control the
workers and distribute the tasks. `concurrent.futures` offers two types of
executors: `ThreadPoolExecutor` and `ProcessPoolExecutor`. As the names
indicate, the former one uses threads and the later one subprocesses for it's
workers. Concurrency can be solved in multiple ways. Python decided to use the
easiest and safest one by introducing the global interpreter lock. This lock
ensures, that there is always only one thread executing bytecode. In contrast
to threads, subprocesses are, as the name indicates, separate processes,
resulting in having an own global interpreter lock for each process. As a
consequence, the access to variables outside the process is limited.
Furthermore `ProcessPolExecutor` cannot be used inside the python console.
Since the requests are I/O bound tasks with negligible computing time, there
should be no noticeable difference between those two executors. But as threads
are more light weight, they can be spawned a bit faster. Because of the
beforementioned advantages of threads, we will take the `ThreadPoolExecutor`.

Since we want to reuse clients for multiple requests, we have to initialize
the workers first. Since each client has a different session key, we have to
request the search pattern for each client and therefore store it together
with the corresponding flag part in the client.  
```python  
def init_worker():  
   # get services  
   server, client = get_services()

   # close server  
   server.close()

   # set additional client attributes  
   client.flag = None  
   client.search = None

   # store client with the thread  
   threading.current_thread().client = client  
```

Now we can adjust the brute force function, which will be executed by the
threads. Each run will try only one character. We first have to ensure, that
the blocks to search for are the ones for the current flag character. Then we
can request the encryption of our try and return the result of the comparison
together with the tested character.  
```python  
def try_character(flag, char):  
   # get client  
   client = threading.current_thread().client

   # test if search pattern is for current flag character  
   if client.flag != flag:  
       # get encrypted flag part  
       client.sendline(("A"*(31-len(flag))).encode().hex().encode())  
       client.search = client.recvline()[:64]

   # test character  
   client.sendline(("A"*(31-len(flag)) + flag + char).encode().hex().encode())  
   test = client.recvline()[:64]

   # return test result  
   return test == client.search, char  
```

After we having all prerequisites, we can now rebuild the main control flow,
starting with the already known definitions of the flag start and the
alphabet.  
```python  
flag = "uiuctf{"  
ALPHABET = string.printable  
```

Now we can create the executor. We choose each thread to handle up to five
characters, which results in every sixth request being one for the search
pattern.  
```python  
max_workers = math.ceil(len(ALPHABET)/5)  
executor = cf.ThreadPoolExecutor(max_workers=max_workers,
initializer=init_worker)  
```

The main loop looks different this time, since we have to deal with the
executor and its results. Since we want to pass the already brute forced part
of the flag to `try_character`, we cannot use the `map` function of the
executor and must submit each call ourselves.  
```python  
while flag[-1] != "}":  
   # get futures  
   futures = [executor.submit(try_character, flag, c) for c in ALPHABET]  
```

After having a list with futures, we have to resolve them. By using
`as_completed`, we get completed futures independent of the order in the
passed list. As before, we stop the loop when we found the next flag
character.  
```python  
   # handle results  
   for future in cf.as_completed(futures):  
       result, char = future.result()  
       if result:  
           flag += char  
           print(flag)  
           break  
```

But stopping the loop won't stop the executor from executing the futures, so
we have to cancel them ourselves. The cancellation of the remaining futures
will reduce the runtime from around 30 seconds to around 22 seconds.  
```python  
   # cancel remaining futures  
   for future in futures:  
       future.cancel()  
```

# Other Modes  
In our exploit we used the ECB mode, as it is the easiest one, but other modes
can also be used after slight adjustments. So let's have a closer look on the
other AES modes featured in this challenge.

## AES CTR  
The CounTeR mode encrypts the concatenation of a 64 bit nonce and a 64 bit
counter and xors the result with the plaintext. Since the nonce and the
session key will be different for each connection, the encrypted nonce+counter
cannot be predicted. It is possible to infer the encrypted nonce+counter by
sending a prefix large enough to know the plaintext of an entire block. But
since we do not know the session key, this doesn't enables us to predict the
next one. Since encrypting something with AES will result in an equal chance
of a bit being 0 or 1, we do not know the encrypted nonce+counter or we have
no unknown bit in the plaintext and are therefore unable to infer the flag
with this mode. Counter mode has the advantage, that its keys can be
precomputed and then xored over the plaintext. Furthermore this mode only
requires the possibility to encrypt and is therefore easier to implement.  
```goat  
          .-------+----------.              .-------+----------.  
          | nonce | 00000001 |              | nonce | 00000002 |  
          '-------+----------'              '-------+----------'  
                    |                                 |  
                    v                                 v  
               .---------.                       .---------.  
               | encrypt |                       | encrypt |  
               '---------'                       '---------'  
                    |                                 |  
                    v                                 v  
.-------------.   .-----.         .-------------.   .-----.  
| plaintext 1 |-->| xor |         | plaintext 2 |-->| xor |  
'-------------'   '-----'         '-------------'   '-----'  
                    |                                 |  
                    v                                 v  
            .--------------.                  .--------------.  
            | ciphertext 1 |                  | ciphertext 2 |  
            '--------------'                  '--------------'  
```

# AES OFB  
The Output FeedBack mode starts with encrypting the initialization vector. It
then xors the result with the plaintext. For subsequent blocks, the output of
the encryption of the previous block is used instead of the initialization
vector. Since the initialization vector is not defined, the used python
library will generate it randomly. Using this mode has the same consequences
as using the counter mode: we can get the output of the encryption by
providing 16 known bytes of plaintext or we can include unknown bits in the
plaintext but are unable to infer them, since there is an equal chance of the
unknown bits to be flipped or not, as the corresponding bits of the encryption
result have an equal probability of being 0 or 1. As a consequence, this mode
is unsuitable for solving the challenge. Its has the same advantages as the
counter mode but has the disadvantage that it is not possible to decode a
block without generating all previous keys.  
```goat  
        .-----------------------.  
        | initialization vector |  
        '-----------------------'    .-----------------.  
                    |                |                 |  
                    v                |                 v  
               .---------.           |            .---------.  
               | encrypt |           |            | encrypt |  
               '---------'           |            '---------'  
                    |                |                 |  
                    +----------------'                 |  
                    |                                  |  
                    v                                  v  
.-------------.   .-----.          .-------------.   .-----.  
| plaintext 1 |-->| xor |          | plaintext 2 |-->| xor |  
'-------------'   '-----'          '-------------'   '-----'  
                    |                                  |  
                    v                                  v  
            .--------------.                   .--------------.  
            | ciphertext 1 |                   | ciphertext 2 |  
            '--------------'                   '--------------'  
```

# AES EAX  
In EAX mode, AES will output a tuple with two values. The first one is the
plaintext encoded with counter mode and the second one is a tag, which can be
used for authentication. Since counter mode is used to generate the plaintext
and the tag is generated from the ciphertext, a header unrelated to the plain
text and the nonce from counter mode, it is also inappropriate for solving
this challenge.

# AES CBC  
The only mode left is Cipher Block Chaining. It starts with an initialization
vector, which is not set in our case and therefore randomly generated. It then
xors the initialization vector with the plaintext and encrypts the result. For
subsequent blocks, the ciphertext of the previous block is used instead of the
initialization vector. This has the effect, that the decryption of each block
depends only on the session key and the ciphertext of the previous block,
which enables the decryption without decryption of random blocks. Since we
know the ciphertext of the previous block and are able to set the prefix of
the plaintext freely, we can use this mode to solve the challenge. So let's
implement it. Since it might be easier to understand if we implement it
without multithreading, we will leave the parallelization and other
optimizations to the reader.  
```goat  
                       .-------------.                          .-------------.  
                       | plaintext 1 |                          | plaintext 2 |  
                       '-------------'                          '-------------'  
                              |                                        |  
                              v                                        v  
.-----------------------.   .-----.                                  .-----.  
| initialization vector |-->| xor |            .-------------------->| xor |  
'-----------------------'   '-----'            |                     '-----'  
                              |               |                        |  
                              v               |                        v  
                         .---------.          |                   .---------.  
                         | encrypt |          |                   | encrypt |  
                         '---------'          |                   '---------'  
                              |               |                        |  
                              v               |                        v  
                      .--------------.        |                .--------------.  
                      | ciphertext 1 |--------'                | ciphertext 2 |  
                      '--------------'                         '--------------'  
```

The `get_services` function from the original exploit must be slightly
adjusted. We can either choose `AES.MODE_CBC` directly or just relay the
original list and let the client choose it later, as it is the first mode in
the list and therefore the default of this challenge.  
```python  
   # relay AES mode list -> client will choose AES.MODE_CBC  
   server.send(client.recvline())  
```

Since the last ciphertext block is a relevant property in CBC, we will store
it with the connection. The first ciphertext we receive is the encrypted
`finish` for the server. We can store it directly before the return of
`get_services`. The client pads the finish message to 32 bytes despite it
being shorter than 16 bytes and therefore fitting into only one block. This
indicates, that the challenge author set `block_size` to 32 bytes. Furthermore
we have to strip the new line at the end of the response.  
```python  
   # save last ciphertext block  
   client.last = finish.strip()[-32:]  
```

The main control flow can be left unchanged.

Unfortunately python does not natively support xoring variables of type
`bytes`, so we have to write our own helper function. As the right side will
always be the raw hex ciphertext, we will also handle the transformation in
this helper function.  
```python  
def bytes_xor_hex(left, hex_right):  
   return bytes(l^r for l, r in zip(left, bytes.fromhex(hex_right.decode())))  
```

Now we have to actually exploit the challenge. The basic strategy stays the
same: we brute force the flag character by character and by aligning the
character to brute force against the end of a block. The only thing to do is
the xor. Since we cannot xor the flag appended to the prefix, we will leave
the entire search request unchanged.  
```python  
def brute_force_char(client, flag, alphabet):  
   # get encrypted flag part  
   client.sendline(("A"*(31-len(flag))).encode().hex().encode())  
   response = client.recvline()  
   search = response[:64]  
```

For getting comparable ciphertexts, we have to revert the expected xor with
the last ciphertext and apply the xor used for `search`. We have to do it only
for the first block, because we only change the plaintext from the last
character of the second block onwards. By xoring with the last ciphertext
block and the one before the first search block, the ciphertext of the first
block will be the same as the first one in `search`.  
```python  
   # precompute prefix ^ search  
   prefix = ("A"*(31-len(flag)) + flag).encode()  
   prefix = bytes_xor_hex(prefix[:16], client.last) + prefix[16:]  
```

Since we no longer need `client.last` and can update it with the last block of
the last ciphertext.  
```python  
   client.last = response.strip()[-32:]  
```

Now we can try all characters of the alphabet. For each request, we have to
revert the upcoming xor by xoring with the last ciphertext.  
```python  
   for c in alphabet:  
       # encrypt guess  
       request = bytes_xor_hex(prefix[:16], client.last) + prefix[16:] + c.encode()  
       client.sendline(request.hex().encode())  
       response = client.recvline()

       # Update last ciphertext block  
       client.last = response.strip()[-32:]

       # return if correct char found  
       if response[:64] == search:  
           return c  
```

And now we get the flag in approximately the same time as the first exploit,
even without forcing the client to use ECB.

Original writeup (https://ctf0.de/posts/uiuctf2022-mom-can-we-have-aes/).