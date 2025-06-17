# sidhe (crypto, 300p, 29 solved)

In the task we get [server
code](https://raw.githubusercontent.com/TFNS/writeups/master/2020-04-17-PlaidCTF/sidhe/server.sage)
and we can connect to the server.

## Task analysis

The server code impelements Supersingular isogeny Diffie–Hellman key exchange
protocol.  
The code is simple to follow:

1. Server randomly selects a `private secret`  
2. We can perform 300 interactions with the server  
3. Each time we can provide a new public key  
4. Each time we can send payload encrypted using derived shared secret  
5. If we send encrypted `Hello World` we get back confirmation of valid message  
6. If we send encrypted `private secret` we get back a flag  
7. If we send anything else, we get confirmation of invalid message

## Vulnerability

The vulnerability lies in the fact that `private secret` is selected only once
per connection, and we can perform 300 key exchanges, with the same secret in
place.

## Solution

The general idea behind the attack is pretty simple to understand.  
The private secret (sk3) is used in:

```python  
def isoex3(sk3, pk2):  
   Ei, P, Q = pk2  
   S = P+sk3*Q  
   for i in range(e3):  
       R = (3^(e3-i-1))*S  
       phi = Ei.isogeny(R)  
       Ei = phi.codomain()  
       S = phi(S)  
   return Ei.j_invariant()  
```

Where `P` and `Q` values are provided as part of our public key.  
Let's imagine for a moment that those are just some numbers.  
Server starts off by doing `S = P+sk3*Q`.  
Let's perform one exchange with some values P and Q and derive a shared
secret.  
Now let's modify `Q` by flipping the least significant bit, and perform
another exchange.  
There are 2 things which could happen:  
- If `sk3` has it's own LSB as `0`, then both derived shared secrets will be identical  
- If `sk3` has it's own LSB a `1`, then we effectively changed `S`, and thus rest fo calculations will differ

Of course we're not dealing with numbers, but much more complex structures,
but general idea stays the same.  
We want to modify `P` and `Q` in such a way, that the resulting shared secret
either stays the same, or changes, depending on bits of private secret.

We can detect this by sending `Hello World` payload and checking if server is
able to decrypt it (so shared secrets match) or not.

For the solution we're closely following the paper `On the security of
supersingular isogeny cryptosystems` by SD Galbraith, C Petit, B Shani, YB Ti:

https://ora.ox.ac.uk/objects/uuid:840faec4-382f-44ec-
aeac-76bd5962f7cb/download_file?file_format=pdf&safe_filename=859.pdf

The paper provides clear description of recovery process in case server is the
one using `2^e2`, while in our case server is using `3^e3`, so we need to
adapt the solution a bit for that.  
We also have to use the slightly harder version, because server is performing
some `Weil Pairing` checks.

First off we need to implement the missing counterpart of operations for `2^e`
for our own client, based on those for `3^e` provided with server:

```python  
def isogen2(sk2):  
   Ei = E  
   P = Pb  
   Q = Qb  
   S = Pa+sk2*Qa  
   for i in range(e2):  
       phi = Ei.isogeny((2^(e2-i-1))*S)  
       Ei = phi.codomain()  
       S = phi(S)  
       P = phi(P)  
       Q = phi(Q)  
   return (Ei,P,Q)

def isoex2(sk2, pk3):  
   Ei, P, Q = pk3  
   S = P+sk2*Q  
   for i in range(e2):  
       R = (2^(e2-i-1))*S  
       phi = Ei.isogeny(R)  
       Ei = phi.codomain()  
       S = phi(S)  
   return Ei.j_invariant()  
```

### Recovery for 2^n PoC

We start off by implementing the simpler case for `2^e`:

```python  
def two():  
   Sa = randint(0, 2^e2-1)  
   print('sa',bin(Sa))  
   Ea, phiPb, phiQb = isogen2(Sa)  
   Sb = randint(0, 3^e3-1)  
   Eb, phiPa, phiQa = isogen3(Sb)  
   #phiQa = phiQa+2^(e2-1)*phiPa # simple case for lSB  
   R = phiPa  
   S = phiQa

   Ki = 0  
   for i in range(len(bin(Sa)[2:])-2):  
       ZE = Zmod(2^e2)  
       theta = 1/ZE(1+2^(e2-1-i))  
       theta = theta.nth_root(2)  
       phiPa = (int(theta)*R-int(theta*2^(e2-i-1)*Ki)*S)  
       phiQa = int(theta*(1+2^(e2-i-1)))*S

       # simpler case wihout scaling theta, but won't pass the assertions below  
       #phiPa = R-(2^(e2-i-1)*Ki)*S  
       #phiQa = (1+2^(e2-i-1))*S

       P = phiPa  
       Q = phiQa  
       assert(P*(2^e2) == Eb(0) and P*(2^(e2-1)) != Eb(0))  
       assert(Q*(2^e2) == Eb(0) and Q*(2^(e2-1)) != Eb(0))  
       assert(P.weil_pairing(Q, 2^e2) == (Pa.weil_pairing(Qa, 2^e2))^(3^e3))

       JA = isoex2(Sa,(Eb, phiPa, phiQa))  
       JB = isoex3(Sb,(Ea, phiPb, phiQb))  
       if (JA == JB):  
           print('even')  
       else:  
           Ki+=2**i  
           print('odd')  
   print(bin(Ki))  
```

The simplest option just to recover LSB is changing `phiQa` to `phiQa =
phiQa+2^(e2-1)*phiPa`.  
For full recovery we could use the option:  
```python  
phiPa = R-(2^(e2-i-1)*Ki)*S  
phiQa = (1+2^(e2-i-1))*S  
```

Where `Ki` is the recovered known part of the private secret, but this won't
pass we `Weil Pairing` checks.  
To do that we need to include scaling factor theta metioned in the paper.

### Recovery for 3^n PoC

Now that we have a working PoC for 2, we can modify it to fit our actual case:

```python  
def three():  
   Sb = randint(0, 3^e3-1)  
   tmp = Sb  
   coeffs = []  
   while tmp != 0:  
       coeffs.append(tmp % 3)  
       tmp //= 3;  
   print(coeffs)  
   print("Sb",Sb)  
   Eb, phiPa, phiQa = isogen3(Sb)

   Sa = randint(0, 2^e2-1)  
   Ea, phiPb, phiQb = isogen2(Sa)

   R = phiPb  
   S = phiQb

   x = 0  
   for i in range(5):  
       ZE = Zmod(3^e3)  
       theta = 1/ZE(1+3^(e3-1-i))  
       theta = theta.nth_root(2)  
       found_coeff = 0  
       for case in range(1,3):  
           phiPb = (int(theta)*R-int(theta*3^(e3-i-1)*(x+case*3**i))*S)  
           phiQb = int(theta*(1+3^(e3-i-1)))*S

           # simpler case wihout scaling theta, but won't pass the assertions below  
           #phiPb = R-(3^(e3-i-1)*(x+case*3**i))*S  
           #phiQb = (1+3^(e3-i-1))*S

           P = phiPb  
           Q = phiQb  
           assert(P*(3^e3) == Ea(0) and P*(3^(e3-1)) != Ea(0))  
           assert(Q*(3^e3) == Ea(0) and Q*(3^(e3-1)) != Ea(0))  
           assert(P.weil_pairing(Q, 3^e3) == (Pb.weil_pairing(Qb, 3^e3))^(2^e2))

           JA = isoex2(Sa,(Eb, phiPa, phiQa))  
           JB = isoex3(Sb,(Ea, phiPb, phiQb))  
           if (JA == JB):  
               found_coeff = case  
               break;  
       print('coefficient', found_coeff, 'for power 3^'+str(i))  
       x+=found_coeff*3**i  
   print(x)

three()  
```

Here `x` denotes the known part of private secret and `case` is the new
coefficient we're testing.

The only major difference is the fact that we're working now in base3.  
This means that we can recover coefficients for consecutive powers of `3`, and
that we may need to perform 2 exchanges to recover one coefficient, because we
need to check coefficient `1` and if it doesn't work we need to check `2` and
only then we can assume that original coefficient was `0`.

### Solver

Now that we have a working PoC for 3^n recover, we can finally implement full
client to grab the flag.  
Note that according to the paper, this method will not work for the highest 2
coefficients, so we need to brute-force those at the very end.

Core of the solver is:

```python  
def oracle(Ei, P, Q, ciphertext, s):  
   pk2 = Ei,P,Q  
   send_key(s,pk2)  
   receive_until(s, ":")  
   send(s, ciphertext.encode("hex"))  
   result = receive_until(s, [".","!"])  
   return "Good" in result  

def recover_coefficients(Ea,R,S,oracle, ciphertext, s):  
   x = 0  
   ZE = Zmod(3^e3)  
   for i in range(e3-2):  
       print("Recovering 3^%d coefficient" % i)  
       theta = 1/ZE(1+3^(e3-1-i))  
       theta = theta.nth_root(2)  
       found_coeff = 0  
       for case in range(1,3):  
           phiPb = (int(theta)*R-int(theta*3^(e3-i-1)*(x+case*3**i))*S)  
           phiQb = int(theta*(1+3^(e3-i-1)))*S  
           if oracle(Ea, phiPb, phiQb, ciphertext, s):  
               found_coeff = case  
               break;  
       print('coefficient', found_coeff, 'for power 3^'+str(i))  
       x+=found_coeff*3**i  
   return x  
```

This allows us to recover all but last 2 coefficients, then we can do:

```python  
limit = e3  
for a in range(3):  
   for b in range(3):  
       secret = res+a*3**(limit-1)+b*3**(limit-2)  
       super_secret_hash = hashlib.sha256(str(secret).encode('ascii')).digest()[:16]  
       ciphertext = cipher.encrypt(super_secret_hash)  
       send_key(s, pk2)  
       send(s,ciphertext.encode("hex"))  
       response = s.recv(9999)  
       print(response)  
```

And one of the responses where we guessed `a` and `b` correctly will contain
the flag.  
After a while we manage to recover:
`PCTF{if_you_wish_for_postquantum_crypto_ask_a_supersingular_isogenie}`

Complete solver
[here](https://raw.githubusercontent.com/TFNS/writeups/master/2020-04-17-PlaidCTF/sidhe/client.sage)

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-04-17-PlaidCTF/sidhe/README.md).