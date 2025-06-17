# City RSA (worth 300+257 points)  
Part of the P.W.N. University CTF 2018 (https://uni.hctf.fun/pages/home/)

```  
I know that frank that a**hole ate the last cookie, but no one believes me.

He wrote himself a service to sign messages, I found part of the source.

It runs here:

nc rsa.uni.hctf.fun 4422

Can you get me the message "YES, I did eat the last cookie" signed by his
service?

I added a verifier for you using his public key:

nc checker.uni.hctf.fun 31337  
[...]  
```

The description included a download link for the source of the service, which,
judging by the methods signatures, uses Textbook-RSA without any padding and
is implemented using the chinese remainder theorem (CRT). The service also has
a check which ensures `"594553"` is not part of the hex representation of the
message to be signed, so we cannot sign the string directly. We also had
access to the python script used for the checker, obviously excluding the
flag.

Textbook-RSA means the service uses no padding, so for each message `m` the
signature `sig(m)` can be calculated as `sig(m) = m^d mod N` where `d` is the
private exponent and `N` is the public modulo.

The relevant parts of the signing service are:  
```  
int main(int argc, const char** argv) {  
   city_rsa_config cfg;  
   /* RSA parameters */  
   char p_str[1024];  
   char p_inv_str[1024];  
   char q_str[1024];  
   char d_str[1024];  
   char e_str[1024];  
   char d_q_str[1024];  
   char d_p_str[1024];  
   char input[32];  
   char input_hex[67];  
   char result[1024];  
   int i;

   // [...] config is loaded here

   printf("Enter message:");  
   fflush(stdout);  
   fgets(input, sizeof(input_hex) / 2, stdin);

   input_hex[0] = '0';  
   input_hex[1] = 'x';  
   for(i = 0; i <= strlen(input); i++){  
       sprintf(input_hex + 2 + i*2, "%02X", input[i]);  
   }

   puts(input_hex);

   if (strstr(input_hex, "594553") != NULL) {  
       // Security measure, don't agree to anything  
       return 1;  
   }

   /* Sign via RSA */  
   city_rsa_init(&cfg, p_str, q_str, p_inv_str, d_str, e_str, d_p_str,
d_q_str);  
   //city_print_config(&cfg;;  
   city_rsa_sign(&cfg, result, input_hex);  
   printf("The signature of your message is: 0x%s\n", result);

   return 0;  
}  
```

## Blinding attack  
Since no padding is used, for three messages `x, y, z` where `x*y == z` it
holds that `sig(x) * sig(y) == sig(z)` since `x^d * y^d == (x*y)^d == z^d`.
Although we cannot sign the string directly, we can simply find some factors
of the string and let the service sign these separately.

However, `fgets` will convert all non-ASCII characters to `0xff`, so the input
cannot contain any bytes between `0x80` and `0xfe`. It is possible to find
such factors and other teams have done this (there is also a writeup available
explaining this approach), but we did not pursue this idea further.

## Buffer Overflow  
The alternative solution, which we came across by accident, is caused by a
buffer overflow when reading the string with `fgets`. We tried to get the
service to sign `0x0`, but to do this we had to input the `0x00`-byte 33
times, otherwise the service would continue reading input. When we did this,
we got the following signature back:  
`0x32bc2267af0d1568cb1fef1ee27b2f6bf6beda7187ca4da1aab93d5b799dd210d055c030119ffc657008084ba7dd45c1cbb6134edb84a3efe977cb3b5993484b090ae53fac40cd13522b2d817d04ccf7ebd6f631aa2de1530b53e47b1c0400b481d13a1b28cc70c745d08ba15b491c8551bc857de56834e728f652f08af0dff744ea4efe7da17fd0bef19ab009195acfd2c32234fb5b3433a7422cc32c0298349fad24fba3dd4925c05047589ba82d873e6abecb2c8495d7899003773c21daf82ff53bcdad5b3bc895e6b2edfbf604f4de6df2f07a4f474cb655e2477de38f6d3209a1b69aaae71f7fb5a904ed6bb92a3b55fc62c45cde9bb5925ae41c92b942`  
This was unexpected, since `0^d (mod N) == 0` should always hold, even when
using the CRT.

What happened is that we overwrote `d_p_str`, since the `fgets` call reads 33
bytes including the terminating `0x00`, which in turn leads to `d_p_str` being
read as `0x00`.

### Chinese Remainder Theorem  
As mentioned before, the service uses the chinese remainder theorem to make
the signature calculation more efficient. Instead of calculating `sig(m) = m^d
mod N`, it does the following instead (according to Wikipedia):

Calculate `d_p = d mod (p-1)`, `d_q = d mod (q-1)` and `q_inv = q^(-1) mod p`
s.t. `q_inv * q (mod p) == 1`. The first two are trivial, the latter one uses
the extended euclidian algorithm.

Then the signature `m` can be calculated with `m_1 = m^(d_p) mod p` and `m_2 =
m^(d_q) mod q` and finally `sig(m) = (q_inv * (m_1 - m_2) mod p) * q + m_2`.

### Solution  
Note that the `d_p` and `d_q` are switched in the implementation and
Wikipedia, so while we overwrote `d_p_str`, what really happened is that we
set `d_q = 0` and our `m = 0`. Thus:  
```  
m_1 = m^(d_p) = 0^(d_p) = 0  
m_2 = m^(d_q) = 0^0 = 1  
s = (q_inv * (m_1 - m_2) mod p) * q + m_2 = (q_inv * (0 - 1) mod p) * q + 1  
```  
Since `q_inv * q == 1 (mod p)`, we know that `((-1 * q_inv) mod p) * q == -1
(mod p)` and, with the final `1` added, this is `s == 0 (mod p)`. What does
this mean? Well, since `x mod p == 0` means that `x` is a multiple of `p` s.t.
`x = k*p` for some natural `k`, we can find `p` by calculating `gcd(s,N) ==
p`. This allows us to recover `q = N/p` and thus we have solved the RSA
factoring problem for this `N == p*q`, giving us access to the private key and
allowing us to sign the message ourselves.

When sending the signature to the checker we obtain the flag
`flag{https://www.youtube.com/watch?v=MpMBETNC-44#C0ngr4tz}`. As mentioned
before we actually discovered this overflow by accident (and even afterwards
overlooked it), so at this point I would like to thank the organizers for
pointing out that we actually triggered one of the intended solutions whereas
we assumed there was a bug in their implementation (which was not released for
the challenge) when signing 0 :-) (Although this technically is a bug, but an
intentional one).

The final solution code is:  
```  
from math import gcd  
# a is the signature obtained from the service  
a =
0x32bc2267af0d1568cb1fef1ee27b2f6bf6beda7187ca4da1aab93d5b799dd210d055c030119ffc657008084ba7dd45c1cbb6134edb84a3efe977cb3b5993484b090ae53fac40cd13522b2d817d04ccf7ebd6f631aa2de1530b53e47b1c0400b481d13a1b28cc70c745d08ba15b491c8551bc857de56834e728f652f08af0dff744ea4efe7da17fd0bef19ab009195acfd2c32234fb5b3433a7422cc32c0298349fad24fba3dd4925c05047589ba82d873e6abecb2c8495d7899003773c21daf82ff53bcdad5b3bc895e6b2edfbf604f4de6df2f07a4f474cb655e2477de38f6d3209a1b69aaae71f7fb5a904ed6bb92a3b55fc62c45cde9bb5925ae41c92b942  
# N and e are the publicly known modulo and public exponent from the checker
script we had access to  
N =
0x98ac865ef6a31313e50fb37853ce96804cb2d864e2a4d14bf7cca85a444a40b453de7c3ae8416e8976cd1cac7f548a43fe8c2eb3d4cfcd3808cf9458c0c87bf4c037d515d22d1299b72e79fcd4a1d1531789cb3013031fb0e28fdfe73f090027b3b3428cacef6dbf7823d5da8d3158101e0c07e707224d451fcbb3114ab85a925bcb7faf9b317bbbddba81285ab93f0ee5f968b258f4675e9d893ec7f0e8379b67527d78fe920ab201cb3a6459d4f3902754b36e3264db7727c6d32e014593c39991f54c7b034d69b986616a39454c85d9e032afa853a6e12fea06472ed3573707da3df9ca7ce8d2c3b820e745da6e3cc523789f858d98645ea042bb54b463d3  
e = 0x10001

p = gcd(a,N)  
q = N // p

# verify that we have the correct p,q  
assert(p*q == N)

# the message we are supposed to sign as a hex number  
target = 0x5945532C2049206469642065617420746865206C61737420636F6F6B6965

# Source: https://gist.github.com/tylerl/1239116  
def eea(a,b):  
	if b==0:return (1,0)  
	(q,r) = (a//b,a%b)  
	(s,t) = eea(b,r)  
	return (t, s-(q*t) )

def find_inverse(x,y):  
   inv = eea(x,y)[0]  
   if inv < 1:  
       inv += y #we only want positive values  
   return inv

# find the private exponent  
d = find_inverse(e, (p-1)*(q-1))

# calculate the signature  
sig = pow(target, d, p*q)

print("Solution: %x" % sig)  
# verify that the signature, when verified, matches the original message  
print("Verified: %d" % int(pow(sig, e, p*q) == target))

# simulate the behavior of the CRT as it is being executed on the server  
# the following implements the scheme as described on Wikipedia  
# since we set d_q = 0 below to obtain the signature, but we overwrote d_p_str
in the service,  
# we know that d_p and d_q are switched in the Wikipedia explanation and in
the service implementation  
d_p = d % (p-1)  
d_q = d % (q-1)  
q_inv = find_inverse(q, p)

m = 0 # the message we sent the service to sign  
d_q = 0  
m_1 = pow(m, d_p, p)  
m_2 = pow(m, d_q, q)  
s = (q_inv * (m_1 - m_2) % p) * q + m_2

print("Signature from service for m == 0: %x" % s)  
print("This matches the original signature from the service: %d" % int(s ==
a))  
```  

Original writeup (https://github.com/ldruschk/ctf-
writeups/blob/master/2018_pwnctf_cityrsa.md).