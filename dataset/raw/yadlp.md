# [DUCTF 2021] yadlp

## tl;dr

Solve the discrete log problem on a funny looking group described by points on
a hyperbolic  
curve, then solve the modular knapsack problem for the flag.

## Description

crypto/yadlp; 14 solves, 494 points

Challenge author: `joseph#8210`

Yet another discrete logarithm problem challenge...

[yadlp.sage](https://play.duc.tf/files/85c7911a3127752c188b8839b7edaeeb/yadlp.sage)  
[output.txt](https://play.duc.tf/files/bdfdc35ee7c0ada2987a3a40b53d897a/output.txt)

## Solving the problem

I started by looking at the files, and saw some familiar looking group
operations  
that looked like elliptic-curve cryptography (ECC).

```python  
def G_add(A, B):  
   print(A, B)  
   x1, y1 = A  
   x2, y2 = B  
   return ((x1*x2 + D*y1*y2) % p, (x1*y2 + x2*y1 + 2*y1*y2) % p)

def G_mul(A, k):  
   out = (1, 0)  
   while k > 0:  
       if k & 1:  
           out = G_add(out, A)  
       A = G_add(A, A)  
       k >>= 1  
   return out

def get_elem(x):  
   d = x**2 * (D + 1) - D  
   if (x & 1 == d & 1) and kronecker(d, p) == 1:  
       y = (x + sqrt(Zmod(p)(d))) * inverse_mod(D, p) % p  
       return (x, y)  
   else:  
       return -1  
```

The flag was encoded by splitting the 48 byte input into 6 segments of 8 bytes
long, and  
summed them together with the group operation.  
We need to first solve the discrete log problem to recover the coefficients of
the summands,  
then somehow recover the summands.

```python  
FLAG = open('flag.txt', 'rb').read().strip()  
assert len(FLAG) % 8 == 0  
M = [int.from_bytes(FLAG[i:i+8], 'big') for i in range(0, len(FLAG), 8)]  
print(f'{FLAG = }')  
print(f'{M = }')

G = [rand_element() for _ in M]  
c = (1, 0)  
for m, gi in zip(M, G):  
   c = G_add(c, G_mul(gi, m))  
```

### Solving the discrete log problem

I thought it was ECC but on closer inspection, the `get_element` function
looks a little funny.  
The equation suggests that we're working with some curve where $$y$$ satisfies  
the equation (over $$\mathbb{Z}_p$$):

$$y =\frac{1}{D}(x + \sqrt{(D+1)x^2  - D})$$

Simplifying and rearanging we get

$$Dy^2 - 2xy -x^2 + 1 = 0$$

This is not an elliptic curve, this is a hyperbola! I had no idea that you
could define  
a group structure over hyperbolas of this form, so as a sanity check, I  
wrote a short function to check that all operations done in the encoding were
on the curve.

```python  
def on_curve(A):  
   x, y = A  
   return (y*y*D -x*x - 2*x*y + 1)%p ==0  
```

Furthermore, $$(1, 0)$$ seemed to be the identity element.  
All the points were on the curve so all signs pointed towards this being some
funny  
group operation.  
Since this challenge was called yadlp, I assumed we needed to take discrete
logs  
in this group. Hopefully the group order would be relatively nice to take
discrete logs.  
However I had no idea what the order of group even was!

I couldn't get much further from staring at this curve and group law, so I  
started putting search terms in google like "hyperbolic curve encryption".  
After some digging around I found [this obscure
paper](https://doi.org/10.2991/icmt-13.2013.26)  
where they propose a cryptosystem based on Pell's equations ($$x^2 - Dy^2 =
1$$) with a  
very similar looking group addition operation to what was in the code.

Notably, they claim that if $$p\equiv 3\pmod 4$$, then the group order would
be $$p+1$$,  
which our prime is. I verified quickly that $$(p+1)G = (1,0)$$ for any group
element $$G$$  
I tested, so I could reasonably believe that this was the group order.

Throwing $$p+1$$ into factordb gave a very nice looking factorization with
small primes.  
(I learned afterwards this is called a smooth number, specifically a
$$2^{32}$$-smooth number.)

$$\begin{align*}  p+1  
= 2^4 &\cdot 3^3 \cdot 3271 \cdot 18119 \cdot 23857 \cdot 35923 \cdot 1505323
\cdot 3036643 \cdot 3878597 \cdot 7306661 \cdot 661850419  
\\ & \;\cdot 696183413 \cdot 737026033 \cdot 748888849 \cdot 764475661 \cdot
790916521 \cdot 1000657271  
\\ & \;\cdot 1016247923 \cdot 1213865039 \cdot 2090081803 \cdot 3882107087
\cdot 4012893277  
\end{align*} $$

Now we can solve the discrete log problem with [Pohlig-
Hellman](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm) in
time proportional to square root of the largest factor of $$p+1$$.  
We need a basepoint, but we can just pick a random point (which is already in
the code) and  
hope that it generates the group (it will likely be the case, we can restart
if we fail).  
Fortunately Sagemath had a generic version of discrete_log that implemented
this, all we needed  
was to pass in:

1. The group operation - `G_add`  
2. The identity element - $$(1, 0)$$  
3. The inverse function -  `lambda x: G_mul(p, x)`

Unfortunately, somebody changed the sage library function at some point and
made it not so  
generic. Took me a while to figure out why I kept getting python errors until
I looked at  
the source code and realized it didn't even try to use the operations I passed
in and instead  
tried to use the `**` operation (I should submit a ticket and maybe try to
submit a fix).  
Instead I searched elsewhere for a discrete_log method.  
I went and modified the commented out `old_discrete_log` method I found in [a
super outdated version of the sage
library](https://github.com/sagemath/sagelib/blob/master/sage/groups/generic.py)
that  
I stumbled across on Google. It worked!

### Solving the Modular Knapsack Problem  
Now we're still not done yet, we had to solve the following problem (which I
learned afterwards was called the Modular Knapsack Problem) where $$a, b, ...,
e$$ were known, and $$x_0, ... x_5$$ were  
numbers that were at most $$2^{64}$$ (pretty small compared to $$p$$).

$$ a x_0 + b x_1 + c x_2 + d x_3 + e x_4 + f x_5 \equiv e \pmod{p+1} $$

At first I thought you could choose a new generator to get a system of
equations with different  
coefficients and use Gaussian elimination, but after implementing that I
realized I was dumb.  
Choosing a new generator would just multiply all the coefficients by a
constant factor.

It was back to the drawing board for me  
until Robert suggested to "use lattices" and had some code handy  
that conveniently solved this exact problem  
(<https://github.com/nneonneo/pwn-stuff/blob/master/math/solvelinmod.py>).

(I really should learn how [LLL
reduction](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm)
works at some point by trying to code it myself)

It worked perfectly and spat out the flag!

```  
DUCTF{a_1337_hyp3rb0la_m33ts_th3_mult1pl3_DLP!!}  
```

Complete sage solve script:

```python  
import solvelinmod

def G_add(A, B):  
   x1, y1 = A  
   x2, y2 = B  
   return ((x1*x2 + D*y1*y2) % p, (x1*y2 + x2*y1 + 2*y1*y2) % p)

def G_mul(A, k):  
   out = (1, 0)  
   while k > 0:  
       if k & 1:  
           out = G_add(out, A)  
       A = G_add(A, A)  
       k >>= 1  
   return out

def get_elem(x):  
   d = x**2 * (D + 1) - D  
   if (x & 1 == d & 1) and kronecker(d, p) == 1:  
       y = (x + sqrt(Zmod(p)(d))) * inverse_mod(D, p) % p  
       return (x, y)  
   else:  
       return -1

def rand_element():  
   while True:  
       x = randint(1, p-1)  
       d = x**2 * (D + 1) - D  
       if (x & 1 == d & 1) and kronecker(d, p) == 1:  
           y = (x + sqrt(Zmod(p)(d))) * inverse_mod(D, p) % p  
           return (x, y)

def on_curve(A):  
   x, y = A  
   return (y*y*D -x*x - 2*x*y + 1)%p ==0

def inverse(A):  
   return G_mul(A,order-1)

D = 13337  
p =
17568142778435152362975498611159042138909402642078949814477371651322179417849164549408357464774644525711780515232117470272550677945089719112177956836141583  
G =
[(8249149405495350491346934933585109414510787432598250096114687570379053133508711862485128035174547571919256235441699899388417666835599315963507480727674285,
10151966144947987666795899106244951506314545969111450078363915090201899029695981970354886015549281568762501638756950135017679627954071369058817947706039379),
(10148658254415475588279956574772196898575718154643967163626694400363009168529645860280959810873028393970853643723425023678857408220330929116526467295542507,
3332426625916817700349475905733631656792492189677766534230576987725484499618918928882667666640821403823057239790395654518704427126712280655564669757208129),
(1839326681086939925214853980855626023120414606039474419455499625885357274275815189399880356995376514021329118829062071144818562457268892324773839713533977,
17502649671831125396398431215302241914145169143474764941575812028922929277656849105757332346628455059539582448544435155655055157181361580680672298566085040),
(3165955958968203879237344349962533642598441044481692770147807839372942715856047580766073222297692574025922260374409920417665600069665162502514403188432579,
9382092026348588885644924948782239369051861025018411316856012639637274661831713783735305424388410778778529413114167923397187236739639802371814632949741663),
(8500294063291124527108623281980255870507549734362604259645984044370658620385351338711051998886026260657132944353675335178871934798200163035190278483491633,
7641198814027309580920446604109217188703337221305342467525089149977505415741300885194767452232679123441594451455097533000754553745051816419202345186703390),
(12352685673550986453697035560006632628194788902921398545668828437339873544223895997440585227838919968929669738393535610103382084842900404005432007637193943,
2453949984320580417885537763124479618094084392655766673219227195157341323190069350175423869908524758510177197973709821798974003013596311361995273762475822)]  
c =
(5388567167658786935158413401674168420144429277172064721472662913563775670320298461949979362402157764272762755236320989018989446360740720072488623102776015,
7420389277336940268114831002964626027945367662485419944369852006741899961686908509331719915794976159062761271182318814519641566938538911041229521838799714)

order = p+1

factors = [2**4 , 3**3 , 3271 , 18119 , 23857 , 35923 , 1505323 , 3036643 ,
3878597 , 7306661 , 661850419 , 696183413 , 737026033 , 748888849 , 764475661
, 790916521 , 1000657271 , 1016247923 , 1213865039 , 2090081803 , 3882107087 ,
4012893277]  
assert(prod(factors) == order)

zero = (1,0)

multiplication_names = ( 'multiplication', 'times', 'product', '*')  
addition_names       = ( 'addition', 'plus', 'sum', '+')  
def old_discrete_log(a, base, ord=None, operation='*',  
                         identity=None, inverse=None, op=None):  
    b = base

    from operator import inv, mul, neg, add  
    Z = Integers()

    if operation in multiplication_names:  
        identity = b.parent()(1)  
        inverse  = inv  
        op = mul  
        if ord==None:  
            ord = b.multiplicative_order()  
    elif operation in addition_names:  
        identity = b.parent()(0)  
        inverse  = neg  
        op = add  
        if ord==None:  
            ord = b.order()  
    else:  
        if ord==None or identity==None or inverse==None or op==None:  
            print(ord, identity, inverse, op)

    if ord < 100:  
        c = identity  
        for i in range(ord):  
            if c == a:        # is b^i  
                return Z(i)  
            c = op(c,b)

    m = ord.isqrt()+1  # we need sqrt(ord) rounded up  
    table = dict()     # will hold pairs (b^j,j) for j in range(m)  
    g = identity       # will run through b**j      
    for j in range(m):  
        if a==g:  
            return Z(j)             
        table[g] = j  
        g = op(g,b)

    g = inverse(g)     # this is now b**(-m)  
    h = op(a,g)        # will run through a*g**i = a*b**(-i*m)  
    for i in range(1,m):  
        j = table.get(h)  
        if not j==None:  # then a*b**(-i*m) == b**j  
            return Z(i*m + j)  
        if i < m-1:  
            h = op(h,g)

def d_log(q):  
   print("dlogging: ", q)  
   dlogs = []  
   for f in factors:  
       t = order//f  
       qt = G_mul(q,t)  
       gent = G_mul(gen, t)  
       dlog = old_discrete_log(qt, gent, ord=f, operation='NONE',  
                           op=G_add, identity=zero, inverse=inverse)  
       dlogs.append(dlog)  
       if None in dlogs:  
           raise ValueError("oh no")  
   l = CRT_list(dlogs, factors)  
   return l

# This one worked  
gen =
(1306220711535023766817529329601851834684473168538006969205607217300581985606511824830746054324343087425816093230309507256982431519166958670991896717613121,
2753498082952557748021507097242652783238834762442333661230349459126933713491167991334695072154480164453278454296466352910947274843516626885289923809047182)  
ords = [d_log(g) for g in G]  
ordc = d_log(c)

x0 = var('x0')  
x1 = var('x1')  
x2 = var('x2')  
x3 = var('x3')  
x4 = var('x4')  
x5 = var('x5')  
eq = (ords[0]*x0 + ords[1]*x1 + ords[2]*x2 + ords[3]*x3 + ords[4]*x4 +
ords[5]*x5 == ordc)  
bounds = {x0: 2**64, x1: 2**64, x2: 2**64, x3: 2**64, x4: 2**64, x5: 2**64}

sol = solvelinmod.solve_linear_mod([(eq, order)], bounds)  
print(f'{sol = }')  
flag = b""  
for key in sol:  
   flag+=int(sol[key]).to_bytes(8, byteorder='big')  
print(flag)  
```  

Original writeup (https://davidzheng.web.illinois.edu/2021/09/27/ductf-
yadlp.html).