I think that Diffie-Hellman is better with some curves, maybe elliptic ones.
Let's share a secret!  

Wrap the secret (which is a point) in uoftctf{(x:y:z)}, where (x:y:z) are
homogeneous coordinates.  

Author: Phoenix  
[chal.sage](https://github.com/Nightxade/ctf-
writeups/blob/master/assets/CTFs/UofT-CTF-2024/chal.sage)  

---

We're given a source file in sage. Here it is:  

```sage  
m = 235322474717419  
F = GF(m)  
C = EllipticCurve(F, [0, 8856682])

public_base = (185328074730054:87402695517612:1)

Q1 = (184640716867876:45877854358580:1) # my public key  
Q2 = (157967230203538:128158547239620:1) # your public key

secret = ...  
my_private_key = ...  
assert(my_private_key*public_base == Q1)  
assert(my_private_key*Q2 == secret)  
```

So this is pretty standard elliptic cryptography encryption. Basically, the
scalar multiplication of our private key by the public base will return Q1,
our public key, while the scalar multiplication of our private key with Q2,
the other individual's public key, will return the shared secret. For those
familiar with Diffie-Hellman, it's the same process, just with elliptic
curves. It's also the same problem, i.e. the Discrete Log Problem. For those
who don't know what the discrete log problem is, I recommend reading up on it
and some algorithms to tackle it.  

I spent like 1+ hours researching what could possibly solve this problem. For
context, though I do main crypto, I have yet to learn elliptic curve
cryptography. Eventually, I realized that Smart's attack could work on it.
Smart's attack is described in greater depth in
[this](https://wstein.org/edu/2010/414/projects/novotney.pdf) paper. All we
need to know, however, is it works when the order of the finite group is
equivalent to p, which we can easily check with Sage's .order() function.  

Knowing I needed to use Smart's attack, I simply Googled for a past CTF
writeup using Smart's attack. I found [this
one](https://ctftime.org/writeup/30559), which had an implementation linked.
All that was left was to replace the parameters with ours and then multiply it
by Q2 to get the shared secret!  

Here's the implementation:  

```sage  
def SmartAttack(P,Q,p):  
   E = P.curve()  
   Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in
E.a_invariants() ])

   P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)  
   for P_Qp in P_Qps:  
       if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:  
           break

   Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)  
   for Q_Qp in Q_Qps:  
       if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:  
           break

   p_times_P = p*P_Qp  
   p_times_Q = p*Q_Qp

   x_P,y_P = p_times_P.xy()  
   x_Q,y_Q = p_times_Q.xy()

   phi_P = -(x_P/y_P)  
   phi_Q = -(x_Q/y_Q)  
   k = phi_Q/phi_P  
   return ZZ(k)

# p = 235322474717419  
# E = EllipticCurve(GF(p), [0, 8856682])  
# P = E.point((185328074730054,87402695517612))  
# Q = E.point((184640716867876,45877854358580))

# Curve parameters --> Replace the next three lines with given values  
p = 235322474717419  
a = 0  
b = 8856682

# Define curve  
E = EllipticCurve(GF(p), [a, b])  
assert(E.order() == p)

# Replace the next two lines with given values  
pub_base = E(185328074730054 , 87402695517612)  
Q1 = E(184640716867876 , 45877854358580)

priv_key = SmartAttack(pub_base, Q1,p)

print(priv_key)

Q2 = E(157967230203538,128158547239620)

print(priv_key * Q2)  
```

And here is our flag!  

   uoftctf{(11278025017971:36226806176053:1)}

Original writeup (https://nightxade.github.io/ctf-writeups/writeups/2024/UofT-
CTF-2024/crypto/clever-thinking.html).