# Bilinear Evil

Challenge author: Diego Aranha (@dfaranha)

The challenge provides two files: chall.sage and data.txt.

### Description:

We know that HARPA is creating a cryptosystem which contains a backdoor. Their
plan is to force the users to use this system in their "end-to-end secure
instant message applications".

**Id**: bilinear_evil

**Total solves:** 0

**Score:** 500

**Categories:** Cryptography

### chall.sage

```  
import hashlib

m = 113  
F.<z> = GF(2^m, modulus=x^113 + x^9 + 1)  
Fx.<t> = F.extension(x^4 + x + 1)

b = 1  
E = EllipticCurve(F, [0, 0, 1, 1, b])  
Ex = EllipticCurve(Fx, [0, 0, 1, 1, b])  
h = 1  
r = E.cardinality() // h;

# Read master key for SOK authenticated key agreement  
flag = open("flag.txt").read().strip()  
assert len(flag) <= 64  
secret = flag[7:][:-1] # extract secret from CTF-BR{<secret>}  
msk = Integer(int(secret.encode("hex"), 16))

# Generate keys for Alice  
xa = F(Integer(int(hashlib.sha256("Alice").digest().encode('hex'),16) %
2^m).bits())  
while E.is_x_coord(xa) == false:  
	xa*=z;  
Pa = h*E.lift_x(xa)  
Sa = msk * Pa;

# Generate keys for Bob  
xb = F(Integer(int(hashlib.sha256("Bob").digest().encode('hex'),16) %
2^m).bits())  
while E.is_x_coord(xb) == false:  
	xb*=z;  
Pb = h*E.lift_x(xb)  
Sb = msk * Pb;

def pairing(P,Q):  
	Px = Ex((P.xy()[0]),(P.xy()[1]))  
	(x,y) = ((Q.xy()[0]),(Q.xy()[1]))  
	Qx = Ex(x+t^4+t^2,y+(t^2+t)*x+t)  
	return Px.tate_pairing(Qx,r,4,2^m)  
  
sk1 = pairing(Sa,Pb);  
sk2 = pairing(Sb,Pa);

# Make sure that the two shared keys are equal and the protocol works  
assert sk1 == sk2

out = open("data.txt","w")  
for p in sk1.list():  
	s = "".join(str(e) for e in p.polynomial().list()[::-1])  
	out.write(hex(Integer(s,2))+"\n")  
```

### data.txt

```  
158790302b3c765e6fe5c5412959  
950fa93f424ff98eb6fe39ce44aa  
1af8204256944023ef9030a493a03  
720d32d768310cd42b038233a117  
```

### Protocol

The sage code is a secret sharing protocol using bilinear symmetric paring,
defined as ```G x G -> Gt``` with public key for Alice calculated as ``` Pa =
HASH(IDa)``` and private key ```Sa = msk * Pa```, for any value ```msk``` and
```IDa = "Alice"```. Same for Bob (i.e., ```Pb = HASH("Bob")``` and ```Sb =
msk * Pb```). This is a [Sakai–Kasahara
scheme](https://en.wikipedia.org/wiki/Sakai%E2%80%93Kasahara_scheme), and the
protocol works because there is a bilinear map where Alice and Bob calculate a
shared secret ```sk = pairing(Sa, Pb) = pairing(Sb, Pa) = pairing(Pa, Pb) ^
msk```.

Using the same sage code above, we can compute ```g = pairing(Pa, Pb)``` and
confirm the protocol:

```  
sage: g = pairing(Pa, Pb)  
sage: g  
(z^111 + z^109 + z^107 + z^105 + z^99 + z^97 + z^96 + z^94 + z^93 + z^88 +
z^85 + z^84 + z^83 + z^73 + z^72 + z^69 + z^67 + z^66 + z^65 + z^64 + z^61 +
z^59 + z^58 + z^57 + z^55 + z^54 + z^53 + z^52 + z^51 + z^49 + z^44 + z^42 +
z^40 + z^37 + z^36 + z^34 + z^32 + z^31 + z^30 + z^28 + z^25 + z^24 + z^23 +
z^21 + z^20 + z^18 + z^16 + z^14 + z^13 + z^12 + z^11 + z^10 + z^5 + z^4 + z^3
+ 1)*t^3 + (z^112 + z^107 + z^106 + z^103 + z^100 + z^99 + z^98 + z^95 + z^94
+ z^93 + z^92 + z^91 + z^89 + z^88 + z^87 + z^82 + z^81 + z^79 + z^78 + z^77 +
z^76 + z^74 + z^71 + z^70 + z^68 + z^66 + z^64 + z^62 + z^58 + z^54 + z^53 +
z^49 + z^47 + z^46 + z^45 + z^43 + z^42 + z^39 + z^37 + z^32 + z^31 + z^29 +
z^28 + z^26 + z^24 + z^20 + z^19 + z^14 + z^13 + z^10 + z^8 + z^7 + z^2 + z +
1)*t^2 + (z^112 + z^111 + z^110 + z^106 + z^105 + z^103 + z^101 + z^100 + z^99
+ z^97 + z^93 + z^92 + z^90 + z^88 + z^87 + z^84 + z^80 + z^79 + z^78 + z^77 +
z^75 + z^74 + z^72 + z^71 + z^69 + z^68 + z^67 + z^66 + z^65 + z^64 + z^62 +
z^61 + z^50 + z^47 + z^45 + z^43 + z^41 + z^40 + z^39 + z^36 + z^29 + z^26 +
z^24 + z^23 + z^22 + z^19 + z^17 + z^15 + z^14 + z^13 + z^11 + z^8 + z^6 + z^5
+ z^4 + z^3 + z + 1)*t + z^112 + z^107 + z^105 + z^102 + z^101 + z^96 + z^95 +
z^94 + z^92 + z^90 + z^89 + z^85 + z^84 + z^83 + z^80 + z^79 + z^76 + z^74 +
z^69 + z^68 + z^67 + z^66 + z^63 + z^56 + z^55 + z^52 + z^51 + z^50 + z^49 +
z^48 + z^46 + z^42 + z^41 + z^36 + z^35 + z^34 + z^31 + z^30 + z^29 + z^28 +
z^26 + z^25 + z^22 + z^21 + z^19 + z^18 + z^16 + z^13 + z^12 + z^10 + z^9 +
z^8 + z^7 + z^5 + z^3 + z^2 + 1  
sage: assert sk1 == sk2 == g ^ msk  
```

### Solver

From the last part of the sage code, it's clear that data.txt contains the
coefficients (```a0, a1, a2, a3```) of ```sk```, so we can reconstruct that.
Given ```sk``` and ```g```, all we need to do is to compute the discrete
logarithm of ```sk = g ^ msk``` and that should not be hard for finite fields
of small characteristic. For example, Antoine Joux proposes an asymptotically
optimal algorithm with quasi-polinomial complexity. The state of the art can
be found
[here](https://link.springer.com/content/pdf/10.1007%2F978-3-642-55220-5_1.pdf).

Luckly, one doesn't need to implement an algorithm like that to solve the
challenge, as there are good enough available tools. E.g., MAGMA has the
following
[implementation](http://magma.maths.usyd.edu.au/magma/handbook/text/194):

> Let K be a field of cardinality q=p^k, with p prime.  
> ...  
> Small Characteristic, Non-prime:  
>  
> Since V2.19, if K is a finite field of characteristic p, where p is less
> than 2^30, then an implementation by Allan Steel of Coppersmith's index-
> calculus algorithm [Cop84], [GM93], [Tho01] is used. (Strictly speaking,
> Coppersmith's algorithm is for the case p=2 only, but a straightforward
> generalization is used when p>2.) A suite of external auxiliary tables boost
> the algorithm so that the precomputation stage computation to determine the
> logarithms of a factor base can be avoided for a large number of fields of
> very small characteristic. This means that logarithms of individual elements
> can be computed immediately if a relevant table is present for the specific
> field. By default, tables are included in the standard Magma distribution at
> least for all fields of characteristic 2, 3, 5 or 7 with cardinality up to
> 2^200. The user can optionally download a much larger suite of tables from
> the Magma optional downloads page
> http://magma.maths.usyd.edu.au/magma/download/db/ (files FldFinLog_2.tar.gz,
> etc.; about 5GB total).

Our field has 4*113 bits of cardinality (as the curve has embedding degree 4,
so the pairing maps the points to ```GF(2^{4*113})```), so this implementation
with external auxiliary tables should be good enough. The code below uses this
implementation.

```  
F<z> := ExtensionField<GF(2), z|z^113+z^9+1>;  
Fx<t> := ExtensionField<F, t  | t^4 + t + 1>;

fromhex := function(x)  
   S := Intseq(StringToInteger(x, 16), 2);  
   for i:=#S+1 to 113 do  
       S[i] := 0;  
   end for;  
   return Seqelt([GF(2) ! l : l in S], F);  
end function;

a0 := fromhex("158790302b3c765e6fe5c5412959");  
a1 := fromhex("950fa93f424ff98eb6fe39ce44aa");  
a2 := fromhex("1af8204256944023ef9030a493a03");  
a3 := fromhex("720d32d768310cd42b038233a117");

sk := Fx!a3*t^3 + a2*t^2 + a1*t + a0;

g := Fx!(z^111 + z^109 + z^107 + z^105 + z^99 + z^97 + z^96 + z^94 + z^93 +
z^88 + z^85 + z^84 + z^83 + z^73 + z^72 + z^69 + z^67 + z^66 + z^65 + z^64 +
z^61 + z^59 + z^58 + z^57 + z^55 + z^54 + z^53 + z^52 + z^51 + z^49 + z^44 +
z^42 + z^40 + z^37 + z^36 + z^34 + z^32 + z^31 + z^30 + z^28 + z^25 + z^24 +
z^23 + z^21 + z^20 + z^18 + z^16 + z^14 + z^13 + z^12 + z^11 + z^10 + z^5 +
z^4 + z^3 + 1)*t^3 + (z^112 + z^107 + z^106 + z^103 + z^100 + z^99 + z^98 +
z^95 + z^94 + z^93 + z^92 + z^91 + z^89 + z^88 + z^87 + z^82 + z^81 + z^79 +
z^78 + z^77 + z^76 + z^74 + z^71 + z^70 + z^68 + z^66 + z^64 + z^62 + z^58 +
z^54 + z^53 + z^49 + z^47 + z^46 + z^45 + z^43 + z^42 + z^39 + z^37 + z^32 +
z^31 + z^29 + z^28 + z^26 + z^24 + z^20 + z^19 + z^14 + z^13 + z^10 + z^8 +
z^7 + z^2 + z + 1)*t^2 + (z^112 + z^111 + z^110 + z^106 + z^105 + z^103 +
z^101 + z^100 + z^99 + z^97 + z^93 + z^92 + z^90 + z^88 + z^87 + z^84 + z^80 +
z^79 + z^78 + z^77 + z^75 + z^74 + z^72 + z^71 + z^69 + z^68 + z^67 + z^66 +
z^65 + z^64 + z^62 + z^61 + z^50 + z^47 + z^45 + z^43 + z^41 + z^40 + z^39 +
z^36 + z^29 + z^26 + z^24 + z^23 + z^22 + z^19 + z^17 + z^15 + z^14 + z^13 +
z^11 + z^8 + z^6 + z^5 + z^4 + z^3 + z + 1)*t + z^112 + z^107 + z^105 + z^102
+ z^101 + z^96 + z^95 + z^94 + z^92 + z^90 + z^89 + z^85 + z^84 + z^83 + z^80
+ z^79 + z^76 + z^74 + z^69 + z^68 + z^67 + z^66 + z^63 + z^56 + z^55 + z^52 +
z^51 + z^50 + z^49 + z^48 + z^46 + z^42 + z^41 + z^36 + z^35 + z^34 + z^31 +
z^30 + z^29 + z^28 + z^26 + z^25 + z^22 + z^21 + z^19 + z^18 + z^16 + z^13 +
z^12 + z^10 + z^9 + z^8 + z^7 + z^5 + z^3 + z^2 + 1;

//Solve  
print "Calculating dlog..";  
msk := Log(g,sk);  
print msk;  
print sk eq g^msk;  
```

After about 25 minutes running on one core i7-4770 CPU @ 3.40GHz and consuming
no more than 3GB of RAM, it prints the msk result
```2279330310406276230060786764362615```. Converting the bytes to ASCII, and
as per the prefix and suffix shown in the sage code, the flag is ```CTF-
BR{pa1r__1s_4_f3w}```.  

Original writeup (https://github.com/epicleet/write-
ups/tree/master/2019/pwn2win/Bilinear%20Evil).