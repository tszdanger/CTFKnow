# Inctfi 2020 Writeups

- Crypto  
	- [PolyRSA](#polyrsa)   
	- [DLPoly](#dlpoly)  
	- [bakflip&sons](#bakflip)  
	- [EaCy](#Eacy)

---

#  PolyRSA Challenge Writeup [Crypto]

For this challenge we were given a single file
[out.txt](/Inctfi-2020/PolyRSA/out.txt) which contains commands used in sage
interactive shell and there output.

In the `out.txt` file we have, three values

- p = 2470567871 (a prime number)  
- n = ... (a 255 degree polynomial)  
- c = m ^ 65537 (also a polynomial)

These parameters constitute the `RSA` Encryption but instead of `Group` of
numbers modulo `n`, this  
uses `univariate polynomials over the finite field Zp`.  
  
Use the following resource to understand about this  
  
[Polynomial based RSA](http://www.diva-
portal.se/smash/get/diva2:823505/FULLTEXT01.pdf)  

As in integer group, we have to find the `multiplicative` order of the group
formed by `residue polynomials` of given `n`.

Above resource specifies the formula in page 14 as  
  
`s = (p**d1 - 1) * (p**d2 - 1)` where d1 and d2 are the degrees of irreducible
polynomials constituing the given `modulus(n)`.

After obtaining `s` (multiplicative order), finding the inverse of `e = 65537`
and raising the `ct` polynomial to the inverse gives the `message` polynomial.

Converting the coefficients of `message` polynomial gives us the `flag`.

```python  
q1, q2 = n.factor()  
q1, q2 = q1[0], q2[0]  
s = (p**q1.degree() - 1) * (p**q2.degree() - 1)  
assert gcd(e, s) == 1  
d = inverse_mod(e, s)  
m = pow(c, d, n)  
flag = bytes(m.coefficients())  
```  
solution code :: [solve.sage](/Inctfi-2020/PolyRSA/solve.sage)

Flag :: inctf{and_i_4m_ir0n_m4n}

---

#  DLPoly challenge writeup [Crypto]

Got second blood for this challenge.  
This challenge is similar to above challenge. we were given
[out.txt](/Inctfi-2020/DLPoly/out.txt) file which contains the commands and
output in sage interactive shell.

In the `out.txt` file we have,  
- p = 35201  
- n (a 256 degree polynomial with coefficients in Zmod(p))  
- len(flag) = 14  
- g = x (a 1 degree polynomial)  
- X = int.from_bytes(flag.strip(b'inctf{').strip(b'}') ,  'big')  
- g ^ X

In order to get the `flag`, we have to solve the `discrete logarithm` in the
`group`of `residues(polynomial)` modulo `n` with coefficients in
`Zmod(p)`(Zp[x]).

Use the resource mentioned in [PolyRSA](#polyrsa) writeup for a better
understanding.

factoring `n` and finding the `order`  
```python  
nfactors = n.factor()  
s = 1  
for i in nfactors:  
	s *= p**(i[0].degree()) - 1  
```  
factoring the `order(s)` shows that `s` has many small factors.  
```python  
2^208 * 3^27 * 5^77 * 7^2 * 11^26 * 13 * 31^25 * 41^25 * 241 * 271 * 1291^25 *
5867^26 * 6781^25 * 18973 * 648391 * 62904731^25 * 595306331^25 *
1131568001^25  
```

As the `order` contains `small factors`, we can use `pohlig hellman algorithm`
to find `discrete logarithm`.  
  
we have to select the `factors` carefully as raising `base element (g)` to
many of the factors gives the `identity element (1)` which we cannot use.

So, taking the following factors  
```python  
[7^2, 13, 241, 271, 18973, 648391]  
```  
we can calculate the value of `flag(X)` modulo `prod([7^2, 13, 241, 271,
18973, 648391])` using `CRT`.  
  
Value obtained is the correct value of the `flag` as the `X` is less than
`2**(7*8)` i.e `X` is 7 bytes long.

quick and ugly implementation of pohlig hellman ::  
```python  
def brute_dlp(gi, ci, n, lim):  
	bi = gi  
	for i in range(1, lim+1):  
		if bi == ci:  
			return i  
		bi = (bi * gi) % n  
	print("[-] NOT in the range")  
	print("[-] Something's Wrong, you gotta check the range", lim)

def pohlig_hellman(g, c, s, n, factors):  
	res = []  
	modulus = []  
	for q, e in factors:  
		assert pow(g, s//(q**e), n) != 1  
		gi = pow(g, s//(q**e), n)  
		ci = pow(c, s//(q**e), n)  
		dlogi = brute_dlp(gi, ci, n, q**e)  
		print("[+] dlog modulo {0} == {1}".format(q**e, dlogi))  
		res.append(dlogi)  
		modulus.append(q**e)  
	print("\n[*] res = ", res)  
	print("[*] modulus = ", modulus)  
	dlog = CRT(res, modulus)  
	print("\n[+] dlog modulo {0} == {1}".format(prod(modulus), dlog))  
	return dlog  
```

solution code :: [solve.sage](Inctfi-2020/DLPoly/solve.sage)

Flag :: inctf{bingo!}

---

#  Bakflip&sons challenge Writeup [Crypto]

This challenge runs the
[challenge.py](/Inctfi-2020/Bakflip_n_sons/challenge.py) on the server.  
  
It provides two functionalities `signMessage` and `getFlag`.  
  
`signMessage` signs the given message using then`ecdsa` with `NIST198p`
elliptic curve.  
  
`getFlag` gives us the `flag` if we can provide the `ecdsa signature` of
message `please_give_me_the_flag`.

```python  
def signMessage():  
   print("""  
   Sign Message Service - courtsy of bakflip&sons  
   """)  
   message = input("Enter a message to sign: ").encode()  
   if message == b'please_give_me_the_flag':  
       print("\n\t:Coughs: This ain't that easy as Verifier1")  
       sys.exit()  
	secret_mask = int(input("Now insert a really stupid value here: "))  
	secret = secret_multiplier ^ secret_mask  
   signingKey = SigningKey.from_secret_exponent(secret)  
   signature = signingKey.sign(message)  
   print("Signature: ", hexlify(signature).decode())

def getFlag():  
   print("""  
   BeetleBountyProgram - by bakflip&sons

       Wanted! Patched or Alive- $200,000  
       Submit a valid signature for 'please_give_me_the_flag' and claim the flag  
   """)  
   signingKey = SigningKey.from_secret_exponent(secret_multiplier)  
   verifyingKey = signingKey.verifying_key  
   try:  
       signature = unhexlify(input("Forged Signature: "))  
       if verifyingKey.verify(signature, b'please_give_me_the_flag'):  
           print(flag)  
   except:  
       print("Phew! that was close")  
```

As we can see in the `signMessage` function declaration, it doesn't allow us
to obtain `signature` of our `target message`.

At the start of execution, `challenge.py` generates `secret key` with `101
bit_length`  
```python  
secret_multiplier = random.getrandbits(101)  
```  
In order to forge the signature, we have to calculate the `secret key`, we
won't be able to solve the  
`ecdlp` but we can use the `additional secret mask` requested in `signMessage`
function.  
```python  
secret_mask = int(input("Now insert a really stupid value here: "))  
secret = secret_multiplier ^ secret_mask  
```  
so, we can modify the `secret key` used for `signing`.  
we can use this to completely obtain the `secret key` in a few iterations.  
```  
Let G be the generator  
s1 is the secret_key  
s2 is the secret_key ^ mask (^ --> xor operation)  
P = s1 * G  
Q = s2 * G  
suppose if the mask is `1`  
	s2 = s1 ^ 1 , (xor with 1 flips the lsb)  
	if lsb of s1 is 0 then s2 = s1 + 1 => Q = s2 * G = (s1 + 1) * G = P + G  
	else if lsb of s1 is 1 then s2 = s1 - 1 => Q = s2 * G = (s1 - 1) * G = P - G

Given the points P, Q we can obtain the lsb of secret_key s1  
by checking  
	if Q == P + G then lsb of secret key is 0  
	else Q == P - G then lsb of secret key is 1

similarly we can set the nth(lsb is 0 bit) lower bit in the mask i.e mask = (1
<< n)  
flipping the nth lower bit,  
	decreases or increases the secret_key(s1) by 2**n based on whether nth bit in secret_key is set or not  
so, checking if Q == P + (2**n) * G or Q == P - (2**n) * G gives the nth bit  
```

Using the above method recursively gives the complete `secret key` and we can
use that to forge the  
required `signature`.

There are small hurdles in the challenge  
1. Only `signature` is given, we have to calculate the `Public Key (P)`.  
2. We have only `73` iterations, we have to calculate the `101 bit key` using less than `72` iterations.

For the first problem, we can use the `signature (r,s)` to obtain the `Public
Key`, two valid `Public Keys` are possible for a given `signature` pair `(r,
s)`.  
  
we have to use other `Public Keys` to identify the correct key.  

For the second problem, we can extend the same theory for any number of bits
with bruteforceable number of cases.  
  
example of `2 bits`.  
```python  
secret_key_lsb =>  
00 --> Q = P + 3*G  
01 --> Q = P + G  
10 --> Q = P - G  
11 --> Q = P - 3*G  
```  
Using the above approach with `2 bits`, we can calculate secret_key using less
than `72` iterations and get the `flag`.

There are a lot of small implementation details, check out my solution code ::
[solve.sage](/Inctfi-2020/Bakflip_n_sons/solve.sage)

FLAG :: inctf{i_see_bitflip_i_see_family}

---

#  EaCy challenge writeup [Crypto]

Luckily I got First Blood for this challenge.

we were given four files  
1. [ecc.py](/Inctfi-2020/EaCy/ecc.py) contains classes to work with elliptic curves  
2. [ansi931.py](/Inctfi-2020/EaCy/ansi931.py) contains classes to generate random data using ANSI X9.31 with AES 128  
3. [prng.py](/Inctfi-2020/EaCy/prng.py) contains implementation of dual_ec_drbg random generator along with prng using ANSI X9.31  
4. [encrypt.py](/Inctfi-2020/EaCy/encrypt.py)

The basic flow of service is as follows  
- Generates a `random number` e using the `prng` defined in `prng.py`.  
- Asks to choose between `[1] Asynchronous SchnorrID` and `[2] Synchronous SchnorrID`.   
- Asks the user for two Points `Q`, `R`.  
- Gives the value of `e` to the user if 1 is selected (Asynchronous SchnorrID)  
- User has to provide value of `s` such that `s*P == e*Q + R`, P is an hard coded point  
- if the above condition fails then it closes the connection  
- if we can provide the correct `s` without the `e` value i.e in `Synchronous SchnorrID`, we can request the flag

service repeats the above process for 10 times.  

if we have `e` value, we can pass the condition by sending point `P` for both
`Q` and `R` values and `(e + 1)` value.  
```  
s*P = (e + 1) * P = e*P + P = e*Q + R  
```  
so, if we know the value of `e` we can easily pass the condition, in order to
get the flag we have to  
calculate the `s` value without taking `e` from the service.

Only way is to crack the `prng` used  
```python  
   def prng_reseed(self):  
       self.prng_temporary = long_to_bytes(self.ecprng_obj.ec_generate())  
       assert len(self.prng_temporary) == 32  
       self.prng_seed = self.prng_temporary[:8]  
       prng.prng_output_index = 8  
       self.prng_key = self.prng_temporary[8:]  
       prng.prng_output_index = 32  
       return bytes_to_long(self.prng_temporary)

   def prng_generate(self):  
       _time = time.time()  
       prng.prng_output_index = 0  
       if not self.one_state_rng:  
           print("prng_reseed ", self.prng_reseed())

       ansi_obj = ANSI(self.prng_seed + self.prng_key + long_to_bytes(_time).rjust(16, "\x00"))  
       while prng.prng_output_index <= 0x1f:  
           self.prng_temporary += ANSI.get(8)  
           prng.prng_output_index += 8  
       print("prng generate = ", bytes_to_long(self.prng_temporary))  
       return bytes_to_long(self.prng_temporary)  
```  
At the first glance, it may seem like the `prng` is using `ANSI` class to
generate `random data` but in the settings used by the challenge, `prng`
directly gives the `random_data` generated by `dual_ec_drbg`.  
```python  
class ecprng:  
   # Curve P-256; source: https://safecurves.cr.yp.to/  
   p = 2**256 - 2**224 + 2**192 + 2**96 - 1  
   a = p-3  
   b =
41058363725152142129326129780047268409114441015993725554835256314039467401291  
   ec = ecc.CurveFp(p, a, b)

   _Px =
115113149114637566422228202471255745041343462839792246702200996638778690567225  
   _Py =
88701990415124583444630570378020746694390711248186320283617457322869078545663  
   Point_P = ecc.Point(ec, _Px, _Py)

   _Qx =
75498749949015782244392151836890161743686522667385613237212787867797557116642  
   _Qy =
19586975827802643945708711597046872561784179836880328844627665993398229124361  
   Point_Q = ecc.Point(ec, _Qx, _Qy)

   def __init__(self, seed):  
       self.seed = seed  
       if self.seed:  
           assert len(long_to_bytes(self.seed)) == 32

   def update_seed(self, intermediate_state_S_1):  
       self.seed = (intermediate_state_S_1 * ecprng.Point_P).x()  
       assert len(long_to_bytes(self.seed)) == 32

   def ec_generate(self):  
       intermediate_state_S_1 = (self.seed * ecprng.Point_P).x()  
       self.update_seed(intermediate_state_S_1)  
       r_1 = long_to_bytes((intermediate_state_S_1 * ecprng.Point_Q).x())[-30:]  
       r_2 = long_to_bytes((self.seed * ecprng.Point_Q).x())[-30:][:2]  
       assert len(r_1 + r_2) == 32  
       print("seed == ", self.seed)  
       return bytes_to_long(r_1 + r_2)  
```  
so, `random_number` `e` is generated using `dual_ec_drbg` with `P-256` curve.  
  
we can predict the `next state` of the generator if author has inserted a
backdoor into the generator.  
  
See the video from `David Wong` for an excellent explanation about the
backdoor [link](https://www.youtube.com/watch?v=OkiVN6z60lg).

so, generator state consists of two points and seed.  
  
To generate a random number  
- s1 = (seed * P).x()  
- random_number = (s1 * Q).x() & ((1 << 240) - 1) ; (lower 240 bits)  
- seed = (s1 * P).x()

generator follows this above procedure to calculate a single random number.  
  
One who decides the points `P` and `Q` has the ability to insert a `backdoor`
into the `generator` which will allow him to `predict` the `future states` of
`generator` given a `single random number`  
generated and little other information.  
  
The way one can do it is,  
  
```  
if Q = c * P (c can be any number)  
given random_number = (s1 * Q).x()  
lifting the random_number gives the value of (s1 * Q)  
multiplying the value of (s1 * Q) with the inverse(c, order) and take the x
co-ordinate of the result gives the seed.  
```  
```  
cinv * (s1 * Q) = cinv * s1 * c * P = s1 * P = seed  
```  
After obtaining the `seed`, one can generate all the future states.

There are little changes in the implementation of `dual_ec_drbg` in this
challenge.

For the points used in this challenge, `Q = 1735 * P`.  
  
backdoor exists in this generator.  
  
Normally, top `16 bits` of the `random number` i.e `(s1 * Q).x()` are removed,
we have to use another `random number` to filter out the wrong ones but in
this challenge we are given with additional information in the form of `r2`,
we can use that to filter.  
  
So, we only need single `e`, after that we can predict all the future states.

Final solution is  
- obtain a value of e by selecting the 1 option(`Asynchronous SchnorrID`)  
- bruteforce the top `16 bits` and find the `seed`  
- select option 2, predict the value of e, pass the check using above mentioned method   
- get the `flag`  

solution code :: [solve.sage](/Inctfi-2020/EaCy/solve.sage)

FLAG :: inctf{Ev3ry_wa11_1s_4_d00r_but_7his_1s_4_D0ubl3_d0or}  

Original writeup (https://github.com/S3v3ru5/CTF-
writeups/tree/master/Inctfi-2020).