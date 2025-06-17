# ASIS CTF 2021 - DamaS writeup

## tl;dr

Use Boneh-Durfee with m=12 and delta=0.28 to recover the secret key (despite
nothing in the chall indicating that is the right way to go)

## code  
``` python  
def rand_poly(n, N):  
   R.<x> = PolynomialRing(Zmod(N))  
   f = R(0)  
   for i in range(n):  
       f += randint(1, n-1) * x ** i  
   return f

def keygen(nbit, l):  
   p, q = [random_prime(2**nbit - 1) for _ in '01']  
   e, N = randint(2, p * q - 1), p * q  
   Zn = Zmod(N)  
   f, A = rand_poly(l, N), random_matrix(Zn, l)  
   B = f(A)  
   phi = (p - 1) * (q - 1)  
   d = inverse_mod(e, phi)  
   if e * d % phi == 1:  
       Q = B ** d  
       pubkey = (e, N, Q, B)  
       return pubkey

def encrypt(msg, pubkey):  
   e, N, Q, B = pubkey  
   l = Q.nrows()  
   r = randint(2, N - 1)  
   R, S = Q ** r, B ** r  
   assert bytes_to_long(msg) < N  
   c = pow(bytes_to_long(msg), e, N)  
   C = [_ for _ in long_to_bytes(c)]  
   CM = matrix(Zmod(N), [[pow(C[l*i + j], e, N) for j in range(l)] for i in
range(l)])  
   ENC = (CM * R, S)  
   return ENC

nbit, l = 484, 11  
pubkey = keygen(nbit, l)  
ENC = encrypt(flag, pubkey)  
print(f'pubkey = {pubkey}')  
print(f'ENC = {ENC}')  
```  
___  
## Solution

We are given public-key parameters "N" and "e" as in regular RSA and two
matrices "B" and "Q". Each matrix's row contains coefficients of a random
polynomial mod N. After the CTF ended, the chall's author revealed that this
cryptosystem is based on [this
paper](https://dpublication.com/journal/EJEST/article/view/157/130).

There are public-key algorithms based on a matrix similar to this one but
defined over mod p with "p" prime. We've found little to nothing on the topic
in the first hours after the chall's release.

After some time, we noticed that the public exponent's length was close to N.
In some RSA challs this meant that the secret key was intentionally made short
so it could be recovered using
[Weiner](https://en.wikipedia.org/wiki/Wiener%27s_Attack) or [Boneh-
Durfee](https://cryptohack.gitbook.io/cryptobook/untitled/low-private-
component-attacks/boneh-durfee-attack) attacks. Since the public key was
randomly chosen (according to the key generation algorithm), the probability
of "d" being small was negligible, so none of the attacks would work.

Despite that, we gave it a try. Weiner's attack couldn't find any solution.
Without knowing the size of the secret key we had to guess Boneh-Durfee's main
parameters, "m" and "delta", until we found a solvable system. The code, based
on [David Wong's implementation](https://github.com/mimoo/RSA-and-LLL-
attacks/blob/master/boneh_durfee.sage) of the attack, took about 20 minutes to
find the secret key. Then we were able to decrypt the flag.

```python  
def simpleBonehDurfee(e, N, delta=.18, m=4):    # modified from
https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/boneh_durfee.sage  
  
   t = int((1-2*delta) * m)  # optimization from Herrmann and May  
   print(t)  
   X = 2*floor(N^delta)  # this _might_ be too much  
   Y = floor(N^(1/2))    # correct if p, q are ~ same size

   # Problem put in equation  
   P.<x,y> = PolynomialRing(ZZ)  
   A = int((N+1)/2)  
   pol = 1 + x * (A + y)

   #  
   # Find the solutions!  
   #

   # Checking bounds  
   if debug:  
       print("=== checking values ===")  
       print("* delta:", delta)  
       print("* delta < 0.292", delta < 0.292)  
       print("* size of e:", int(log(e)/log(2)))  
       print("* size of N:", int(log(N)/log(2)))  
       print("* m:", m, ", t:", t)

   # boneh_durfee  
   if debug:  
       print("=== running algorithm ===")  
       start_time = time.time()

   solx, soly = boneh_durfee(pol, e, m, t, X, Y)

   # found a solution?  
   if solx > 0:  
       print("=== solution found ===")  
       if False:  
           print("x:", solx)  
           print("y:", soly)

       d = int(pol(solx, soly) / e)  
       print("private key found:", d)  
   else:  
       print("=== no solution was found ===")

N =
229390284327362543631665561538247955943148090861464626741869076801016755542189232243447878145301540155649892155496714591713267451549337065451608041169675633296363209537979285128757920653236098206767564349167459543243559294991799646959526281872382987894932951892563759168376575008335477035621  
e =
164317532240415045202765124100454586391785201865316431289581518383413159130652307960709946708738537015272258748252057381718720993385777298921277253898971188100901630406599274662247377867031195839726642402978340331553176421498052361412931554817586093593349074448250972947033186911822384592457  
delta = 0.28  
m=12  
  
#d = simpleBonehDurfee(e, N, delta, m)  
d =
1839320038472006359578228121964872958248984913931534334417556559320978533688828921

def decrypt(ENC, N, privkey):  
   N = N  
   C0, S = ENC  
   T = matrix(Zmod(N) ,S) ** privkey  
   CM = matrix(Zmod(N), C0) * T ** (-1)  
   C = matrix(Zmod(N), [[pow(CM[i][j], privkey, N) for i in range(11)] for j
in range(11)])  
   C = [C[i][j] for j in range(11) for i in range(11)]  
   enc = b''  
   for c in C:  
       enc += bytes([c])  
   msg = long_to_bytes(pow(bytes_to_long(enc), privkey, N))  
   return msg

print(decrypt(ENC, N, d))  
#ASIS{S1mPl3_8uT_N0vEL_pUBl1C_K3Y_Cryp70sy5t3M!!}

```  
___  
## Final thoughts

That chall received a lot of valid criticism after the CTF ended, mainly
because the only thing necessary to solve the chall (the private key's length)
was "obscured" at best. I strongly believe that there would be a lot more
solves if anything suggested that the private exponent was small or generated
differently.  

Original writeup (https://github.com/thalestvba/write-
ups/tree/main/2021/ASIS%20CTF%20Quals).