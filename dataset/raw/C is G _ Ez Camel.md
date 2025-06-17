When connecting to the service we are greeted with

```  
Due to corona virus even our service is attacked that even the public key is
kept hidden !!  
in order to get the cure ! we need to provide the private key first  
the ciphers given :
(4828923438101798131358711325036338387624266011380116499823047167836752389251677008594058210083062687104436291796809910157158078255370092036467798396832711603,6488671001622414982950327372560783133951156413417577211599077106429966795436098504393940893985690150541527159987366145431768339494445062105797825158609787817)  
1 - Encrypt  
2 - Decrypt  
3 - Get the cure  
```

The "Encrypt" option asks for a message (an integer) and "Your random",
"Decrypt" asks for C1 and C2, while "Get the cure" says "Give me the private".
Of course, passing the ciphertext provided at the start to the "decrypt"
option is not accepted.

Looking up a list of asymmetric encryption schemes, we quickly find ElGamal
encryption. To quote Wikipedia,

> ElGamal encryption system is an asymmetric key encryption algorithm for
> public-key cryptography which is **based on the Diffie–Hellman key
> exchange.**

Thus, like the Diffie-Hellman key exchange, ElGamal is defined over a group
$G$. The group should be cyclic (that is, isomorphic to $\mathbb Z/q\mathbb Z$
where $q = |G|$, the order of $G$), and the discrete logarithm problem should
be hard.

We also define a generator $g \in G$ --- an element of the group such that
powers of $g$ *generate* the entire group:  
$$\forall a \in G. \exists w \in \mathbb Z. g^w = a$$

Generating a key consists of choosing the group and generator, and then
essentially performing the first step of a Diffie-Hellman key exchange: we
choose the private exponent $x$ and compute $$h = g^x.$$ $G$, $g$ and $h$ are
published, and $x$ is kept secret.

Encrypting a message also looks just how you'd expect it to: a random exponent
$y$ is chosen, and a Diffie-Hellman share is calculated: $$c_1 = g^y.$$ We
also use the public key part $h$ to calculate a shared secret $$s = h^y.$$ The
message is then encrypted with this shared secret in the most straightforward
way: $$c_2 = m \cdot s.$$

### The group

One question remains: what group do we choose? The simplest cyclic group is a
section of the integers with addition mod $n$ as the operation, but the
discrete logarithm in that group amounts to a modular inverse, making it
unsuitable for cryptographic use.

The next simplest is the multiplicative group of integers: we take a modulus
$n$, and the group is the set of invertible elements mod $n$, together with
multiplication mod $n$ as the group operation. This is one of the groups we
commonly see in cryptography, the other ones being elliptic curves over finite
fields. It is reasonable to assume we're dealing with $(\mathbb Z/n\mathbb
Z)^\times$ and not an elliptic curve; this assumption turns out to be true.

### Recovering the public key

We have the ability to encrypt any value we choose, and to provide the
"random" value $y$ that is to be used by the process. If we pick $m = y = 1$,
we get $c_1 = g$ and $c_2 = h$ in response. The modulus $n$ remains a mystery,
though.

If we encrypt $m = 2$ with $y$ still equal 1, we get $2h$ as a response. We
can calculate `2 * h` locally, without reducing modulo the unknown $n$, and
we'll see that the result is equal to the value returned by the server. This
encryption doesn't give us any new information, then.

We can keep going though, and while the conclusion is the same for $m = 3$, $m
= 4$ gives a different result. This means that $4h \geq n$. However,  
$$4h \equiv c_2 \pmod n.$$ By definition, this means that $4h - c_2$ is a
multiple of $n$. If we think about it, though, we added $3h + h$, where both
values were below $n$, thus it's not only a *multiple* of $n$, but exactly
$n$:  
$$n = 4h - c_2.$$

*Side note:* at this moment, we can see that $n$ is a prime. This is a common choice when the order of the group is to be public, because then all values (except the congruence class of 0, of course), are invertible.

### Abusing homomorphic encryption

Thinking back to the encrypted message we get at the start, and how the
"decrypt" option refuses to touch it, we might notice that the server accepts
our request if we only change $c_2$. From here, we can go two different ways:

1. Note that the formula $c_2 = m \cdot s$ implies that multiplying the ciphertext $c_2$ by some constant will also multiply the plaintext $m$ by the same constant. This is the strategy I used during the CTF, where I sent $(c_1, 2c_2)$ to the server, and then multiplied the response by the modular inverse of 2.  
2. Send $(c_1, 1)$ to the server, get the inverse of $s$ as a response. Multiply it by $c_2$ yourself.

In both cases, when we turn the plaintext message into hexadecimal and decode
the resulting bytes as ASCII, we get the flag:

```  
Unstoppable ! Well done !! -> Securinets{B4444d_3lG4m4l_system}  
```

### The code

For reference, here's the code I used to solve this challenge:

```  
from pwn import *  
from sympy import mod_inverse, isprime  
from binascii import unhexlify  
s = remote('3.88.65.254', 1338)

C1 =
4828923438101798131358711325036338387624266011380116499823047167836752389251677008594058210083062687104436291796809910157158078255370092036467798396832711603  
C2 =
6488671001622414982950327372560783133951156413417577211599077106429966795436098504393940893985690150541527159987366145431768339494445062105797825158609787817

def encrypt(m, y):  
   s.sendlineafter(b'Your choice :', b'1')  
   s.sendlineafter(b'Your Message in mentioned format', str(m).encode())  
   s.sendlineafter(b'Your random', str(y).encode())  
   s.recvuntil(b'\n(')  
   c1 = int(s.recvuntil(b',').rstrip(b',').decode())  
   c2 = int(s.recvuntil(b')').rstrip(b')').decode())  
   return c1, c2

def decrypt(c1, c2):  
   s.sendlineafter(b'Your choice :', b'2')  
   s.sendlineafter(b'C1 :', str(c1).encode())  
   s.sendlineafter(b'C2 :', str(c2).encode())  
   s.recvuntil(b'Get your message : ')  
   return int(s.recvline().strip().decode())

g, h = encrypt(1, 1)  
#g_, h3 = encrypt(3, 1)  
_, h4 = encrypt(4, 1)

#assert g == g_  
#assert h3 == 3 * h  
assert h4 != 4 * h

N = h * 4 - h4  
assert isprime(N)  
log.info('Got N')

C2x = 2 * C2 % N  
mx = decrypt(C1, C2x)  
m = mx * mod_inverse(2, N) % N  
print(hex(m))  
print(unhexlify(hex(m)[2:]))  
```