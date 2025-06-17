<script  
 src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-
MML_HTMLorMML"  
 type="text/javascript">  
</script>

Author : mindFlayer02  

[source.sage](https://github.com/Nightxade/ctf-
writeups/blob/master/assets/CTFs/0xL4ugh-CTF-2024/source.sage)  
[out.txt](https://github.com/Nightxade/ctf-
writeups/blob/master/assets/CTFs/0xL4ugh-CTF-2024/out.txt)  

---

We are provided a sage source file and an output file. Here's the source:  

```py  
from random import *  
from Crypto.Util.number import *  
flag = b'REDACTED'  
#DEFINITION  
K = GF(0xfffffffffffffffffffffffffffffffeffffffffffffffff);a =
K(0xfffffffffffffffffffffffffffffffefffffffffffffffc);b =
K(0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1)  
E = EllipticCurve(K, (a, b))  
G = E(0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012,
0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811)

#DAMAGE  
def poison(val,index):  
	val = list(val)  
	if val[index] == '1':   
		val[index] = '0'  
	else:   
		val[index] = '1'  
	return ''.join(val)

my_priv = bin(bytes_to_long(flag))[2:]  
ms = []  
C1s = []  
C2s = []  
decs = []

count = 0

while count < len(my_priv):  
	try:   
		k = randint(2, G.order()-2)  
		Q = int(my_priv,2)*G  
		M = randint(2,G.order()-2)  
		M = E.lift_x(Integer(M));ms.append((M[0],M[1]))  
  
		C1 = k*G;C1s.append((C1[0],C1[1]))  
		C2 = M + k*Q;C2s.append((C2[0],C2[1]))

		ind = len(my_priv)-1-count  
		new_priv = poison(my_priv,ind)  
		new_priv = int(new_priv,2)  
		dec = (C2 - (new_priv)*C1);decs.append((dec[0],dec[1]))  
		count +=1   
	except:   
		pass

with open('out.txt','w') as f:  
	f.write(f'ms={ms}\n')  
	f.write(f'C1s={C1s}\n')  
	f.write(f'C2s={C2s}\n')  
	f.write(f'decs={decs}')  
```

This challenge looks intimidating (I was actually quite unsure at first if I
could solve this), but I personally found it to be easier than I expected.  

Let's first go through what's happening step-by-step.  

First, some parameters are given, in which an elliptic curve is constructed
and a generator point `G` is defined. Then, there is a `poison()` function,
which seems to flip the bit at a certain position in a string.  

`my_priv` is set to the binary representation of the flag. We then enter a
while loop, that iterates through `my_priv`.  

Two random integers are generated, `k` and `M`. Scalar multiplication of `G`
by the integer representation of the flag produces point `Q`. Meanwhile, after
looking up `lift_x()` in SageMath's documentation, I realized that it just
found a y-value corresponding to the x-value of `M`. `M` thus becomes a point
on the elliptic curve with the random value initially stored in `M` as its
x-coordinate.  

Now, `C1` is produced via scalar multiplication of `k` and `G`. `C2` is
produced via `M + kQ`, i.e. the scalar multiplication of `k` and `Q` and the
point addition of the resultant point with `M`.  

`ind` seems to be controlling the index of the bit of `my_priv` we're
accessing in the while loop, with the loop appearing to iterate through
`my_priv` backwards. Additionally, `new_priv` is set to the result of the
`poison()` function being called on `my_priv` and `ind`. If you refer back to
what's happening in the `poison()` function, it seems that, in `new_priv`, the
bit at position `ind` in `my_priv` will be flipped, and the rest stays the
same. Notably, `my_priv` also stays the same across all iterations. The above
two conclusions can easily be confirmed with some added print statements in
the source file.  Finally, `dec` is set to `C2 - (new_priv)*C1`.  

On a sidenote, it may be helpful for those of you that are not knowledgeable
regarding elliptic curve cryptography to read up on it. I suggest CryptoHack
as a great introduction! Reason being that you may not exactly understand
what's going on with the scalar multiplication and point addition, even though
you technically don't really need to.  

This problem comes down to a bunch of equations that actually turn out quite
nicely. We can write the following:  

$$Q = pG$$  
$$C_1 = kG$$  
$$C_2 = M + kQ = M + pkG$$  
$$p_m = new_priv$$  
$$dec = C_2 - p_m*C1 = M + pkG - p_m*kG = M + kG(p - p_m) = M + C1(p - p_m)$$  

It is known that  
$$p - p_m = 2^i$$  
or  
$$p - p_m = -2^i$$  
since the bit at the index changes from 0 to 1 or 1 to 0, and we change the
smallest bits first and the largest bits last. Note that changing the bit from
0 to 1 would make $$p - p_m$$ negative, and changing the bit from 1 to 0 would
make it positive. Therefore, based on the result of the subtraction, we know
whether or not the original bit was 0 or 1.  

Once we know that, it is trivial to simply write a short sage script to check
if the bit changed from 0 to 1 or 1 to 0. Here it is:  

```py  
from Crypto.Util.number import *

# out.txt not included here for readability

K = GF(0xfffffffffffffffffffffffffffffffeffffffffffffffff);a =
K(0xfffffffffffffffffffffffffffffffefffffffffffffffc);b =
K(0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1)  
E = EllipticCurve(K, (a, b))  
G = E(0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012,
0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811)

binstr = ''  
for i in range(len(ms)):  
   # Make each point a point on the elliptic curve  
   M = E(ms[i])  
   C1 = E(C1s[i])  
   C2 = E(C2s[i])  
   dec = E(decs[i])

   dec = dec - M

   res0 = -1 * (1<

Original writeup (https://nightxade.github.io/ctf-
writeups/writeups/2024/0xL4ugh-CTF-2024/crypto/poison.html).