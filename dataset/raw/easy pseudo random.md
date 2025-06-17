The PRNG is a [B.B.S.](https://en.wikipedia.org/wiki/Blum_Blum_Shub)-like
generator, with update function $F(v) = v^2 + b$ over
$\\mathbb{Z}/p\\mathbb{Z}$.

We're given 2/3 of higher-order bits of the first two outputs, and the FLAG is
Xor-ed with the next five outputs.

Denote the unknown parts as $x_1$, $x_2$, we have

$$\left\\{  
\begin{aligned}  
v_0 &= 2^{n-k} w_0 + x_0 \\\\  
v_1 &= 2^{n-k} w_1 + x_1 \\\\  
v_1 &\equiv v_0^2 + b \pmod{p}  
\end{aligned}  
\right.$$

Expand and rearrange, we get

$$  
2w_0 \times x_0 + (w_0^2-w_1+b) \times 1 - p\times k = x_1 - x_0^2,  
$$

(this $k$ is not that $k$, don't mind)

Here we *hide* the variable $x_1$ in the right term, and see it as a new
variable. Then we can solve it with LLL algorithm over 3-rank basis.

Write it in matrix form:  
$$\left(  
\begin{matrix}  
x_0 \\\\  
1 \\\\  
-k  
\end{matrix}  
\right)^T \times  
\left(  
\begin{matrix}  
1 &0 &2w_0 \\\\  
0 &1 &w_0^2-w_1+b\\\\  
0 &0 &p  
\end{matrix}  
\right) =  
(x_0, 1, x_1-x_0^2)$$

Next we need to adjust the scale to make the norm satisfy the Minkowski's
bound (also make sure the second element is $1$)

Here I choose $A = p / X$, $B = p$, $C = p / X^2$, then

$$norm < \sqrt{3} p \\\\  
det = p^4 / X^3$$

Since $X \\approx p^{1/3}$, it does.

After we found $x_0$, it's easy to get $x_1$. Then the PRNG is broken.

exp.sage :  
```python  
p =
86160765871200393116432211865381287556448879131923154695356172713106176601077  
b =
71198163834256441900788553646474983932569411761091772746766420811695841423780  
m =
88219145192729480056743197897921789558305761774733086829638493717397473234815  
w0 = 401052873479535541023317092941219339820731562526505  
w1 = 994046339364774179650447057905749575131331863844814

nbits = 256  
d = 2  
k = ceil(nbits * (d / (d + 1)))  
w0 <<= (nbits - k)  
w1 <<= (nbits - k)

AA = p >> (nbits-k)  
BB = p  
CC = p >> (2*(nbits-k))

M = Matrix(ZZ, [  
   [AA, 0, CC*2*w0],  
   [0, BB, CC*(w0^2-w1+b)],  
   [0, 0, CC*p]  
])

b1 = M.LLL()[0]  
if b1[0] < 0:  
   b1 *= -1  
assert b1[1] == BB

x0 = ZZ(b1[0] / AA)  
# x0 = 1319495720667326863431558  
x1 = ZZ(b1[2] / CC) + x0^2  
# x1 = 1811790233058988426434106

v0 = w0 + x0  
v1 = w1 + x1  
assert v1 == (v0^2 + b) % p  
```

task.sage :  
```python  
from Crypto.Util.number import*  
from flag import flag

nbits = 256  
p = random_prime(1 << nbits)  
Fp = Zmod(p)  
P.<v> = PolynomialRing(Fp)

b = randrange(p)  
d = 2  
F = v^2 + b

v0 = randrange(p)  
v1 = F(v0)

k = ceil(nbits * (d / (d + 1)))  
w0 = (v0 >> (nbits - k))  
w1 = (v1 >> (nbits - k))

# encrypt  
m = bytes_to_long(flag)  
v = v1  
for i in range(5):  
   v = F(v)  
   m ^^= int(v)

print(f"p = {p}")  
print(f"b = {b}")  
print(f"m = {m}")  
print(f"w0 = {w0}")  
print(f"w1 = {w1}")  
```