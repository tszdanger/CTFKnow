When connecting to the server we get the following output:

```  
$ nc challs.xmas.htsp.ro 1006  
Provide a hex string X such that sha256(unhexlify(X))[-5:] = e5980

421bd70835ba28c45065  
Good, you can continue!  
Welcome back, we've fixed the problem with the key generation you found in our
system.  
Now we're facing another problem, we seem to be having a power outgage, and
our machines are running undervoltaged, hopefully that's not a problem.  
Can you please take a look again at our protocol and try to find some
vulnerability?  
Oh, by the way, you only have 64 actions.  
Here's the public key, you'll be needing that!  
n:4683d9c698d09a11a0d456093c24d9e769ffbad1c99e7e1e4d9b75338c6cc45877df260ac27848829d728ef1ea9684e14dc2ace35b1debebe39bb9357992a8204f9b90a9469414414d9ec959d12a8d68c1432c7a54c2fe98004fa425cd7756a0de6450bf312471e8991677e824a98254e005a9c63375cf36bfcce31fb3bbe77d  
e:10001

Choose what you want to do:  
1. sign message  
2. forge signature  
3. exit

```

From the source code we learn that the generated signatures are RSA-CRT
signatures which are highly vulnerable to fault attacks like the [Bellcore
attack](https://eprint.iacr.org/2012/553.pdf). Since the server is running on
low voltage, faults are likely to occur.

We are given the public key, so we can check each signature for whether it is
valid or not. For the Bellcore attack, one valid and one invalid signature of
the same message suffices. When given a valid signature `s` and an invalid
signature `s'` of the same message, we can factor the public modulus `N` by
computing `gcd(s-s', N)`. If the result is neither 1 nor `N`, it must be one
of the secret factors of `N`. From here, we can easily compute the other
factor and then compute the modular inverse of the public exponent `e` to get
the private `d`.

With the knowledge of `d`, we can generate valid signatures for any message.

The following Sage9 script `too_low_voltage.sage` requests signatures for a
random but fixed message from the server until an invalid signature is
detected. It then computes the secret key and finally provides a valid
signature for a given message to the server.

```python3  
#!/usr/bin/sage

import sys  
from pow import PoW

def inp(i=1):  
   for _ in range(i):  
       line = input()  
       print(line, file=sys.stderr)  
   return line

def prnt(line):  
   print(line, file=sys.stderr)  
   print(line)  
   pass

def check_sig(msg, sig, e, N):  
   return msg == pow(sig, e, N)

def bellcore(sig, sig_p, e, N):  
   p = gcd(sig-sig_p, N)  
   if p == 1 or p == N:  
       return None  
   q = N // p  
   phi = (p-1) * (q-1)  
   return inverse_mod(e, phi)

def sign(msg, d, N):  
   return pow(msg, d, N)

# PoW  
p_o_w = inp().split(' ')[-1]  
inp()  
prnt(PoW(p_o_w))

# Get signatures  
inp(6)  
N = int(inp().split(':')[1], 16)  
e = int(inp().split(':')[1], 16)  
d = None  
inp()

msg_s = 'deadbeef'  
msg_i = int(msg_s, 16)  
sig_valid = None  
sig_fault = None  
for i in range(64):  
   # Read menu  
   inp(5)

   prnt(1)  
   inp()  
   prnt(msg_s)  
   inp()  
   sig = int(inp().split(': ')[1], 16)  
   inp()  
  
   # If fault occured  
   if not check_sig(msg_i, sig, e, N):  
       print('[INFO] Fault detected!', file=sys.stderr)  
       sig_fault = sig  
       pass  
   else:  
       sig_valid = sig  
       pass  
   if not sig_valid == None and not sig_fault == None:  
       d = bellcore(sig_valid, sig_fault, e, N)  
       if d == None:  
           print('No success yet...', file=sys.stderr)  
           sig_fault = None  
           continue  
           pass  
       else:  
           break  
           pass  
       pass  
   pass

print('Success', file=sys.stderr)

# Read menu  
inp(5)

prnt(2)  
msg_s = inp().split("b'")[1][:-1]  
msg_i = int(msg_s, 16)  
sig = sign(msg_i, d, N)  
prnt(hex(sig)[2:])  
inp(4)  
```

The script was run in combination with netcat as follows:

```  
$ ncat -e ${PWD}/too_low_voltage.sage challs.xmas.htsp.ro 1006  
Provide a hex string X such that sha256(unhexlify(X))[-5:] = e5980

421bd70835ba28c45065  
Good, you can continue!  
Welcome back, we've fixed the problem with the key generation you found in our
system.  
Now we're facing another problem, we seem to be having a power outgage, and
our machines are running undervoltaged, hopefully that's not a problem.  
Can you please take a look again at our protocol and try to find some
vulnerability?  
Oh, by the way, you only have 64 actions.  
Here's the public key, you'll be needing that!  
n:4683d9c698d09a11a0d456093c24d9e769ffbad1c99e7e1e4d9b75338c6cc45877df260ac27848829d728ef1ea9684e14dc2ace35b1debebe39bb9357992a8204f9b90a9469414414d9ec959d12a8d68c1432c7a54c2fe98004fa425cd7756a0de6450bf312471e8991677e824a98254e005a9c63375cf36bfcce31fb3bbe77d  
e:10001

Choose what you want to do:  
1. sign message  
2. forge signature  
3. exit

1  
Let's sign something for you.  
deadbeef

Here's the signature:
f0cbe70e8d4c103cb1f36cfb7ca521d47b3288b8d1983204eddbcc608e45498092b775fc92c3192922e660d125278c9030924d3acb809c5975f72b51b12cb73567ca344c9deb9f43be92b22624ba377fa8f845dd9a74b364d8e6636bb6f34c09ed57f77473cd585825ed747e0f2396c59397d3157d5bfd1cd122d19e75d880d

Choose what you want to do:  
1. sign message  
2. forge signature  
3. exit

1  
Let's sign something for you.  
deadbeef

Here's the signature:
122b6ca2992cb35684ffa8ad9b6517b39e93c93f97cd24f6729daa9df00678d82d1ea3e5e9facfc5ba6ae0f20a492fc5d6faa4eaa7524a40dd3f00afb2a637d5b3e8db6c0203ee1494ec46bb3c53f759b91de12564a511627e4f6f30224fbf7f046fac0c532c84c5be692a5e14649594346f71483e975dcc97d58b0f3eace5be

[INFO] Fault detected!  
Success  
Choose what you want to do:  
1. sign message  
2. forge signature  
3. exit

2  
Give me the signature for this following message:
b'8013471ffbb3d2ab509e3bea4b8cd6135ae9f2eb36d21763ecf78e13dfa89168e8d20b757f6944b6bd753f90fa68f854d851c79040a594723b93e313e4260fe9'  
11ee6523985b95d6c258de92594e67532409c9a338cb40e04bdf3eefee446beeb49e4f230084e9f4461b33e72e9ce2c3495cebabb251a8d590fa041e16eb8ba7562de52b19b6faaca317f82e510d9e5d8a8dd38d58a43528b7cce0d4884b2d4b6c872b90ac285c6aaa7940964054d51ec8de68f12ace605b5fa7fc1946edfd1c  

Congratulations, you trully are a great hacker!  
Here's your flag:
X-MAS{Oh_CPU_Why_h4th_th0u_fors4k3n_u5_w1th_b3llc0r3__th3_m4th_w45_p3rf3c7!!!_2194142af19aeea4}  
```