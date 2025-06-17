## ELEGANT CURVE  
### Challenge  
> Playing with
> [Fire](https://cr.yp.toc.tf/tasks/elegant_curve_ae8c3f188723d2852c9f939ba87d930398720a62.txz)!  
>  
> `nc 07.cr.yp.toc.tf 10010`

```python  
#!/usr/bin/env python3

from Crypto.Util.number import *  
import sys  
from flag import flag

def tonelli_shanks(n, p):  
   if pow(n, int((p-1)//2), p) == 1:  
           s = 1  
           q = int((p-1)//2)  
           while True:  
               if q % 2 == 0:  
                   q = q // 2  
                   s += 1  
               else:  
                   break  
           if s == 1:  
               r1 = pow(n, int((p+1)//4), p)  
               r2 = p - r1  
               return r1, r2  
           else:  
               z = 2  
               while True:  
                   if pow(z, int((p-1)//2), p) == p - 1:  
                       c = pow(z, q, p)  
                       break  
                   else:  
                       z += 1  
               r = pow(n, int((q+1)//2), p)  
               t = pow(n, q, p)  
               m = s  
               while True:  
                   if t == 1:  
                       r1 = r  
                       r2 = p - r1  
                       return r1, r2  
                   else:  
                       i = 1  
                       while True:  
                           if pow(t, 2**i, p) == 1:  
                               break  
                           else:  
                               i += 1  
                       b = pow(c, 2**(m-i-1), p)  
                       r = r * b % p  
                       t = t * b ** 2 % p  
                       c = b ** 2 % p  
                       m = i  
   else:  
       return False

def add(A, B, p):  
   if A == 0:  
       return B  
   if B == 0:  
       return A  
   l = ((B[1] - A[1]) * inverse(B[0] - A[0], p)) % p  
   x = (l*l - A[0] - B[0]) % p  
   y = (l*(A[0] - x) - A[1]) % p  
   return (int(x), int(y))

def double(G, a, p):  
   if G == 0:  
       return G  
   l = ((3*G[0]*G[0] + a) * inverse(2*G[1], p)) % p  
   x = (l*l - 2*G[0]) % p  
   y = (l*(G[0] - x) - G[1]) % p  
   return (int(x), int(y))

def multiply(point, exponent, a, p):  
   r0 = 0  
   r1 = point  
   for i in bin(exponent)[2:]:  
       if i == '0':  
           r1 = add(r0, r1, p)  
           r0 = double(r0, a, p)  
       else:  
           r0 = add(r0, r1, p)  
           r1 = double(r1, a, p)  
   return r0

def random_point(a, b, p):  
   while True:  
       x = getRandomRange(1, p-1)  
       try:  
           y, _ = tonelli_shanks((x**3 + a*x + b) % p, p)  
           return (x, y)  
       except:  
           continue

def die(*args):  
   pr(*args)  
   quit()

def pr(*args):  
   s = " ".join(map(str, args))  
   sys.stdout.write(s + "\n")  
   sys.stdout.flush()

def sc():  
   return sys.stdin.readline().strip()

def main():  
   border = "+"  
   pr(border*72)  
   pr(border, " hi talented cryptographers, the mission is decrypt a secret
message", border)  
   pr(border, " with given parameters for two elliptic curve, so be genius and
send", border)  
   pr(border, " suitable parameters, now try to get the flag!
", border)  
   pr(border*72)

   nbit = 160

   while True:  
       pr("| Options: \n|\t[S]end ECC parameters and solve the task \n|\t[Q]uit")  
       ans = sc().lower()  
       if ans == 's':  
           pr("| Send the parameters of first ECC y^2 = x^3 + ax + b like: a, b, p ")  
           params = sc()  
           try:  
               a, b, p = params.split(',')  
               a, b, p = int(a), int(b), int(p)  
           except:  
               die("| your parameters are not valid!!")  
           if isPrime(p) and 0 < a < p and 0 < b < p and p.bit_length() == nbit:  
               pr("| Send the parameters of second ECC y^2 = x^3 + cx + d like: c, d, q ")  
               pr("| such that 0 < q - p <= 2022")  
               params = sc()  
               try:  
                   c, d, q = params.split(',')  
                   c, d, q = int(c), int(d), int(q)  
               except:  
                   die("| your parameters are not valid!!")  
               if isPrime(q) and 0 < c < q and 0 < d < q and 0 < q - p <= 2022 and q.bit_length() == nbit:  
                   G, H = random_point(a, b, p), random_point(c, d, q)  
                   r, s = [getRandomRange(1, p-1) for _ in range(2)]  
                   pr(f"| G is on first  ECC and G =", {G})  
                   pr(f"| H is on second ECC and H =", {H})  
                   U = multiply(G, r, a, p)  
                   V = multiply(H, s, c, q)  
                   pr(f"| r * G =", {U})  
                   pr(f"| s * H =", {V})  
                   pr("| Send r, s to get the flag: ")  
                   rs = sc()  
                   try:  
                       u, v = rs.split(',')  
                       u, v = int(u), int(v)  
                   except:  
                       die("| invalid input, bye!")  
                   if u == r and v == s:  
                       die("| You got the flag:", flag)  
                   else:  
                       die("| the answer is not correct, bye!")  
               else:  
                   die("| invalid parameters, bye!")  
           else:  
               die("| invalid parameters, bye!")  
       elif ans == 'q':  
           die("Quitting ...")  
       else:  
           die("Bye ...")

if __name__ == '__main__':  
   main()  
```

The challenge is to supply two elliptic curves

$$  
E_p: y^2 = x^3 + ax + b \pmod p \\  
E_p: y^2 = x^3 + cx + d \pmod q  
$$

Where $0 < q - p < 2023$ and $0 < a,b < p$, $0 < c,d < q$.

Supplying these curves, you are given two pairs of points and the challenge is
to solve this discrete log for both pairs. Supplying the two private keys to
the server gives the flag.

### Solution

This challenge I solved in an identical way to [Tiny ECC](#tiny-ecc). I
generated an anomalpus curve $E_p$  and then used `q = next_prime(p)`. I then
searched for a pair $(c,d)$  where $\\#E_q$  was smooth. I think the intended
solution was to generate two singular elliptic curves with smooth primes $p,q$
so you could solve the discrete log in $F_p^{\star}$ , but seeing as the last
solution worked, this was already in my mind.

First I needed an anomalous curve with 160 bit prime. Luckily, this is in the
paper [Generating Anomalous Elliptic
Curves](http://www.monnerat.info/publications/anomalous.pdf) as an example, so
I can use their $m$  value.

Iterating over $c,d$ I found a curve

```python  
q = 730750818665451459112596905638433048232067472077  
aq = 3  
bq = 481  
Eq = EllipticCurve(GF(q), [aq,bq])

factor(Eq.order())  
2^2 * 3 * 167 * 193 * 4129 * 882433 * 2826107 * 51725111 * 332577589 *
10666075363  
```

Which is smooth, with a 34 bit integer as the largest factor.

Sending to the server:

```python  
p = 730750818665451459112596905638433048232067471723  
ap = 425706413842211054102700238164133538302169176474  
bp = 203362936548826936673264444982866339953265530166  
q = 730750818665451459112596905638433048232067472077  
aq = 3  
bq = 481  
```

I get my two pairs of points I can easily solve the dlog for

```python  
from random import getrandbits

# params from http://www.monnerat.info/publications/anomalous.pdf  
D = 11  
j = -2**15

def anom_curve():  
   m = 257743850762632419871495  
   p = (11*m*(m + 1)) + 3  
   a = (-3*j * inverse_mod((j - 1728), p)) % p  
   b = (2*j * inverse_mod((j - 1728), p)) % p  
   E = EllipticCurve(GF(p), [a,b])  
   G = E.gens()[0]  
   return p, a, b, E, G

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

p = 730750818665451459112596905638433048232067471723  
ap = 425706413842211054102700238164133538302169176474  
bp = 203362936548826936673264444982866339953265530166

Ep = EllipticCurve(GF(p), [ap,bp])  
G = Ep(126552689249226752349356206494226396414163660811,
559777835342379827315577715664975494598512818777)  
rG = Ep(190128385937465835164338802317889165657442536853,
604514027124204305317929024826237325074492980218)

print(SmartAttack(G,rG,p))

q = 730750818665451459112596905638433048232067472077  
aq = 3  
bq = 481  
Eq = EllipticCurve(GF(q), [aq,bq])

H = Eq(284866865619833057500909264169831974815120720320,
612322665682105897045018564282609259776516527853)  
sH = Eq(673590124165798818844330235458561515292416807353,
258709088293250578320930080839442511989120686226)

print(H.discrete_log(sH))  
```

Sending the two keys, I get the flag

##### Flag

`CCTF{Pl4yIn9_Wi7H_ECC_1Z_liK3_pLAiNg_wiTh_Fir3!!}`

Original writeup (https://blog.cryptohack.org/cryptoctf2021-hard#elegant-
curve).