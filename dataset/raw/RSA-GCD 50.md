I think i might leaked something but i dont know what  

Author : Bebo07  

[chall2.txt](https://github.com/Nightxade/ctf-
writeups/blob/master/assets/CTFs/0xL4ugh-CTF-2024/chall2.txt)  
[chall2.py](https://github.com/Nightxade/ctf-
writeups/blob/master/assets/CTFs/0xL4ugh-CTF-2024/chall2.py)  

---

We're given a Python source file and its output. Here's the source:  

```py  
import math  
from Crypto.Util.number import *  
from secret import flag,p,q  
from gmpy2 import next_prime  
m = bytes_to_long(flag.encode())  
n=p*q

power1=getPrime(128)  
power2=getPrime(128)  
out1=pow((p+5*q),power1,n)  
out2=pow((2*p-3*q),power2,n)  
eq1 = next_prime(out1)

c = pow(m,eq1,n)

with open('chall2.txt', 'w') as f:  
f.write(f"power1={power1}\npower2={power2}\neq1={eq1}\nout2={out2}\nc={c}\nn={n}")  
```

For those have you that have done CryptoHack before, you may recognize that
this challenge is very very similar to a CryptoHack challenge, specifically
Mathematics/Modular Binomials. I immediately realized this, and went to
CryptoHack to refresh my memory on the past problem and read some solutions.
Note that, unless you have solved the problem, solutions may be unavailable to
you. If you have solved the problem, see
[here](https://cryptohack.org/challenges/bionomials/solutions/). If you
haven't, I'll explain the solution anyways, so just keep reading.  

So, in this challenge, we are essentially provided the following equations:  

$$out_1=(p+5q)^{power_1}\;(mod\;n)$$  
$$out_2=(2p-3q)^{power_2}\;(mod\;n)$$  

Where p and q are the primes whose product is n. We of course need to find
these in order to break the RSA encryption, whose ciphertext is c.  

Notably, however, we are not provided `out1` in our output file! Instead, we
are provided `eq1`, which is the smallest prime after `eq1`. Well, before
figuring out if we can solve this problem without `out1` specifically, let's
first solve the case where we are given `out1`. How can we do this?  

As a sidenote, we are also provided the value of a variable `hint` in the
output file, but this is not referenced in the source file at all. It is not
necessary for the solution.  

Note that the following explanation is based entirely on `exp101t` Modular
Binomials solution on CryptoHack, and full credit goes to him for his writeup.  

First, I'll rewrite the variables to make it a little easier to read.  

$$o_1=(p+5q)^{p_1}\;(mod\;n)$$  
$$o_2=(2p-3q)^{p_2}\;(mod\;n)$$  

Let's now take our  equations, and raise each of them to the other's power,
i.e.:

$$o_1^{p_2}=(p+5q)^{p_1p_2}\;(mod\;n)$$  
$$o_2^{p_1}=(2p-3q)^{p_2p_1}\;(mod\;n)$$  

Because of Binomial Theorem, we know this will simplify to:  

$$o_1^{p_2}=(p)^{p_1p_2} + (5q)^{p_1p_2}\;(mod\;n)$$  
$$o_2^{p_1}=(2p)^{p_2p_1} + (-3q)^{p_1p_2}\;(mod\;n)$$  

Since all other terms have a `pq`, which is equal to `n`, in them.  

Let's now take both equations (mod q). Then, the q's will essentially cease to
exist in our equations. Note that the (mod n) does not affect this because q
is a factor of n.  

$$o_1^{p_2}=(p)^{p_1p_2}\;(mod\;q)$$  
$$o_2^{p_1}=(2p)^{p_2p_1}\;(mod\;q)$$  

Now, what if we do this:  

$$o_1^{p_2} \cdot 2^{p_1p_2} =(p)^{p_1p_2} \cdot 2^{p_1p_2} \;(mod\;q)$$  
$$o_2^{p_1}=(2p)^{p_2p_1}\;(mod\;q)$$  

Therefore:  

$$o_1^{p_2} \cdot 2^{p_1p_2} =(2p)^{p_1p_2}\;(mod\;q)$$  
$$o_2^{p_1}=(2p)^{p_2p_1}\;(mod\;q)$$  

Based on the definition of modular arithmetic, we can then write:  

$$o_1^{p_2} \cdot 2^{p_1p_2} =(2p)^{p_1p_2} + k_1q$$  
$$o_2^{p_1}=(2p)^{p_2p_1} + k_2q$$  

And thus,  

$$x = o_1^{p_2} \cdot 2^{p_1p_2} - o_2^{p_1} = (2p)^{p_1p_2} + k_1q -
((2p)^{p_2p_1} + k_2q) = (k_1 - k_2)q$$  

Hence, we have now produced a number that is a multiple of q. And thus `gcd(x,
n)` will return q.  

Perfect. So now we know how to factor n if we did know `out_1`. But
unfortunately, we don't. We only the know the smallest prime greater than it.
So how we can do this?  

I immediately thought of brute forcing `out_1` by just sequentially checking
numbers less than `eq1` until we find an `out_1` that works. But what if the
distance is really large? What if the next prime after `out_1` was millions
away?  

I decided to quickly test this out by just looking for the next prime after
`eq1`. This would tell me if the prime density was large enough for brute
forcing to work.  

```py  
from Crypto.Util.number import *

eq1=2215046782468309450936082777612424211412337114444319825829990136530150023421973276679233466961721799435832008176351257758211795258104410574651506816371525399470106295329892650116954910145110061394115128594706653901546850341101164907898346828022518433436756708015867100484886064022613201281974922516001003812543875124931017296069171534425347946706516721158931976668856772032986107756096884279339277577522744896393586820406756687660577611656150151320563864609280700993052969723348256651525099282363827609407754245152456057637748180188320357373038585979521690892103252278817084504770389439547939576161027195745675950581  
for i in range(10000):  
   if isPrime(eq1):  
       print(eq1)  
       break  
   eq1 += 1  
```

Turns out the next prime number was less than 10000 away! 10000 is already
easily brute forceable. We can quickly write a script to now brute force
`out1`.  

```py  
x1 = pow(2, power1*power2, n)  
x2 = pow(out2, power1, n)  
for i in range(10000):  
   # if i % 100 == 0: print(i)  
   diff = abs(pow(eq1, power2, n)*x1 - x2)  
   q = gcd(diff, n)  
   if q > 1:  
       # print(g)  
       break  
   eq1 -= 1  
   if is_prime(eq1):  
       break  
```

After this, once we have q, we can simply do standard RSA procedure and
decrypt the message. Here is my full implementation:  

```py  
from gmpy2 import next_prime, gcd, is_prime  
from Crypto.Util.number import *

power1=281633240040397659252345654576211057861  
power2=176308336928924352184372543940536917109  
hint=411  
eq1=2215046782468309450936082777612424211412337114444319825829990136530150023421973276679233466961721799435832008176351257758211795258104410574651506816371525399470106295329892650116954910145110061394115128594706653901546850341101164907898346828022518433436756708015867100484886064022613201281974922516001003812543875124931017296069171534425347946706516721158931976668856772032986107756096884279339277577522744896393586820406756687660577611656150151320563864609280700993052969723348256651525099282363827609407754245152456057637748180188320357373038585979521690892103252278817084504770389439547939576161027195745675950581  
out2=224716457567805571457452109314840584938194777933567695025383598737742953385932774494061722186466488058963292298731548262946252467708201178039920036687466838646578780171659412046424661511424885847858605733166167243266967519888832320006319574592040964724166606818031851868781293898640006645588451478651078888573257764059329308290191330600751437003945959195015039080555651110109402824088914942521092411739845889504681057496784722485112900862556479793984461508688747584333779913379205326096741063817431486115062002833764884691478125957020515087151797715139500054071639511693796733701302441791646733348130465995741750305  
c=11590329449898382355259097288126297723330518724423158499663195432429148659629360772046004567610391586374248766268949395442626129829280485822846914892742999919200424494797999357420039284200041554727864577173539470903740570358887403929574729181050580051531054419822604967970652657582680503568450858145445133903843997167785099694035636639751563864456765279184903793606195210085887908261552418052046078949269345060242959548584449958223195825915868527413527818920779142424249900048576415289642381588131825356703220549540141172856377628272697983038659289548768939062762166728868090528927622873912001462022092096509127650036  
n=14478207897963700838626231927254146456438092099321018357600633229947985294943471593095346392445363289100367665921624202726871181236619222731528254291046753377214521099844204178495251951493800962582981218384073953742392905995080971992691440003270383672514914405392107063745075388073134658615835329573872949946915357348899005066190003231102036536377065461296855755685790186655198033248021908662540544378202344400991059576331593290430353385561730605371820149402732270319368867098328023646016284500105286746932167888156663308664771634423721001257809156324013490651392177956201509967182496047787358208600006325742127976151  
e = eq1

x1 = pow(2, power1*power2, n)  
x2 = pow(out2, power1, n)  
for i in range(10000):  
   # if i % 100 == 0: print(i)  
   diff = abs(pow(eq1, power2, n)*x1 - x2)  
   q = gcd(diff, n)  
   if q > 1:  
       # print(g)  
       break  
   eq1 -= 1  
   if is_prime(eq1):  
       break  
  
p = n//q  
assert p*q == n  
phi = (p - 1)*(q - 1)  
# d = inverse(e, n)  
d = pow(e, -1, phi)  
print(long_to_bytes(pow(c, d, n)))  
```

Run the script for the flag!  

   0xL4ugh{you_know_how_factor_N!}

Original writeup (https://nightxade.github.io/ctf-
writeups/writeups/2024/0xL4ugh-CTF-2024/crypto/rsa-gcd.html).