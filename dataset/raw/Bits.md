# [CSAW CTF 2021] bits

## tl;dr

The flag is encrypted with a password of $a^d \pmod N$.  
Decrypt by solving the discrete logarithm problem to compute $d$ from
$g^d\pmod N$  
and an oracle that given a number $g^x \pmod n$ will return the 883rd bit of
$x$.  
Do the discrete log problem by factorizing $N$ with the oracle by getting  
the top bits with a binary search, the lower bits by interactively querying
the oracle  
and doing some number theory to factorize and compute the discrete log.

## Description

crypto/bits; 24 solves, 497 points  
Challenge authors: `Robin_Jadoul` and `jack`

I wrote this oracle in rust so that it can't sue companies over java stuff.

nc crypto.chal.csaw.io 5010  
  
[main.rs](https://ctf.csaw.io/files/cae893c9c0f0d7b488b3eddb1b99219a/main.rs)

## Solving the challenge

Interacting with the oracle gives:  
```  
+++++++++++++++++++++++++++++++++++++++++++++++  
+ I hear there's a mythical oracle at Delphi. +  
+++++++++++++++++++++++++++++++++++++++++++++++

N =
1264774171500162520522740123707654912813731191511600716918716574718457223687306654609462735310087859826053230623347849924104479609383350278302774436797213741150063894250655073009487778309401701437562813695437500274843520937515731255706515213415007999907839388181535469916350256765596422669114523648082369  
G = 2  
publ =
1212487202243646984386173446511282289931417044351458340480622092138117454231970360918091810951525920616364982248466162290051013120417592308811316654798136079145284397900865487961920243710196032048995386251362920330926430559242059799715206708168895458603215715146064914454925425870564649600485121538888979  
alice =
1024640601443471247332323755059540128989623988611561774565028170938628815764407641381833150460508942917290472170138094077448704053365256467287344121743320435086310199233461822424914222345675720038545559040111784145778223966348376549176125773372309112010889362453693591886310086077964503934892770669706366  
nbits = 1006  
FLAG =
c19eb80cb79e8e15e854db731190f514405670c9fd686775c235905a70293808b0506b42d62398aabe55bb949db56edd0c  
```

We can look at the code (all in rust) to explain some of this output.  
```rust  
   let mut rnd = RandState::new_custom(&mut sysrng);  
   let d = Integer::from(&*ORDER).random_below(&mut rnd);  
   let publ = Integer::from(&*G).pow_mod(&d, &*N).unwrap();  
   let nbits = ORDER.significant_bits();  
   let alice =
Integer::from(&*G).pow_mod(&Integer::from(&*ORDER).random_below(&mut rnd),
&*N).unwrap();  
   println!("N = {}\nG = {}\npubl = {}\nalice = {}\nnbits = {}",  
       *N,  
       *G,  
       publ,  
       alice,  
       nbits);  
   encrypt_flag(alice.pow_mod(&d, &N).unwrap());  
```  
Looking at `encrypt_flag()` we see:  
```rust  
fn encrypt_flag(shared: Integer) {  
   let mut hasher = Sha256::new();  
   hasher.update(shared.to_string());  
   let key = hasher.finalize();  
   let mut cipher = Aes256Ctr::from_block_cipher(  
       Aes256::new_from_slice(&key.as_slice()).unwrap(),  
       &GenericArray::clone_from_slice(&[;; 16])  
       );  
   let mut flag = FLAG.clone();  
   cipher.apply_keystream(&mut flag);  
   println!("FLAG = {}", flag.iter().map(|c| format!("{:02x}",
c)).collect::<String>());  
}  
```  
The code is a bit difficult to understand to someone who has never done any
rust, but  
the gist of it is clear, the function takes in an integer, does some
transformations,  
than encrypts the flag with it. If we knew the password we should be able to
easily  
decrypt the function.

So it looks like `FLAG` is encrypted with `alice.pow_mod(d, N)`, and we are
given `alice`,  
so it is enough to figure out what `d` is.  
We are given `publ = G.pow_mod(d, N)` and `G = 2`, so we need to solve the
discrete log problem  
to recover `d`.  
Normally this is very difficult without knowing the factorization of $N$, but
we also have access  
to an oracle.

```rust  
   for line in std::io::stdin().lock().lines() {  
       let input = line.unwrap().parse::<Integer>().unwrap();  
       match dlog(input.clone()) {  
           None => println!("-1"),  
           Some(x) => {  
               assert!(G.clone().pow_mod(&x, &*N).unwrap() == input % &*N);  
               assert!(x < *ORDER);  
               assert!(x >= 0);  
               println!("{}", x.get_bit(nbits - 123) as i32)  
           }  
       }  
   }  
```  
Checking `nbits=1006` we have that `nbits-123 = 883`.  
So we have access to an oracle which given an integer $m$, computes the
discrete log base $G$,  
the value $x$ which solves $G^x \equiv m\pmod{N}$,  
then returns the 883rd bit of $x$.

So if we send to the oracle $2^y\pmod N$, the oracle will spit out the 883rd
bit of  
$y\pmod{\texttt{ORDER}}$ where `ORDER` is the order of $2$ in $P$.  
If $y< \texttt{ORDER}$ this just gives us the 883rd bit, but if we query
larger numbers,  
we get the 883rd bit of $y-k\cdot \texttt{ORDER}$ for some $k$.  
Let's denote $m_k = k\cdot \texttt{ORDER}$.

Playing around with this, if the 883rd bit of $m_k$ of $1$,  
but that bit is $0$ for $m_i$ with $0\le i < k$,  
than we can actually find the exact value of the leading bits if  
we send queries with $y$ having the last 883 bit be all $1$s.

```python  
b = 883  
# pad the last b bits with 1s  
def pad(k):  
   return k*2**(b+1) | (2**(b+1)-1)

# do binary search for the most significant bits of  
hi = 2**124  
lo = 2**123

print("Binary searching for leading bits")  
# Technically I didn't verify that function is  0/1 in this range  
# (could have multiple flipping threshholds) but this works so ¯\_(ツ)_/¯  
while lo+1 < hi:  
   mid = (lo + hi)//2  
   if query(pad(mid)) == b'1':  
       lo = mid  
   else:  
       hi = mid

assert(query(pad(lo))!=query(pad(hi)))  
```

At this point we have the highest bits, we want to recover the lower bits  
Since now we have have a good estimate of $m_k$ (call that $y$),  
we can get the next bit by querying for $2y$,  
which we'll get a response of the 883rd bit of $2y-2m_k$,  
or equivalently the 882nd bit of $m_k$. This way we can recover the lower bits  
of $m_k$.  
```python  
# At this point, leading bits is hi, we should search for next bits  
hi = 2*hi+1  
for i in range(b+1):  
   if query(pad(hi)) == b'0': # bit is 0  
       hi = 2*hi + 1  
   else:  
       hi = 2*hi  
```

From here, we can guess that $m_1 = \texttt{ORDER}$ is $\phi(N)/2$,  
and use that to compute the factorization of $N$ into $p$ and $q$.  
```python  
# ok at this point, hi is k*phi/? where ? is 2 or 3, guess ? = 2  
qs = 2

k = (hi+N//qs)//(N//qs)  
# this should give approximately what we were looking for, round up because N
> qs  
assert(hi%k==0)  
phi = (hi//k)*qs

# integer sqrt  
def _sqrt(n):  
   lo = 0  
   hi = n  
   while lo+1<hi:  
       mid = (lo+hi)//2  
       if mid*mid <=n:  
           lo = mid  
       else:  
           hi = mid  
   return lo  
# use solution from  
# https://crypto.stackexchange.com/questions/5791/why-is-it-important-that-
phin-is-kept-a-secret-in-rsa  
pplusq = N - phi+1  
pminq = _sqrt(pplusq*pplusq-4*N)  
assert(pminq*pminq==pplusq*pplusq-4*N)  
q = (pplusq + pminq)//2  
p = pplusq - q  
assert(p*q==N)  
print(p, q)  
```

This gives us the factorization! Now we can run the following sage code and
use CRT to compute the discrete log of `publ`.  
```python  
# Note now we have G, N = p*q  
# We need to calculate x s.t. G^x == publ (mod N)

publ =
1212487202243646984386173446511282289931417044351458340480622092138117454231970360918091810951525920616364982248466162290051013120417592308811316654798136079145284397900865487961920243710196032048995386251362920330926430559242059799715206708168895458603215715146064914454925425870564649600485121538888979  
p =
26713395582018967511973684657814004241261156269415358729692119332394978760010789226380713422950849602617267772456438810738143011486768190080495256375003  
q =
47346065295850807479811692397225726348630781686943994678601678975909956314423885777086052944991365707991632035242429229693774362516043822438274496319123  
# Calculate G^x_1 == publ (mod p)  
x_1 = Mod(publ, p).log(2)  
# Calculate G^x_2 == publ (mod q)  
x_2 = Mod(publ, q).log(2)  
# => x = x_1 (mod p-1), x = x_2 (mod q-1)  
x = crt([x_1, x_2],  [p-1, q-1])  
print(x)  
```

Now that we have `d` all we need to do is decrypt it in rust:  
```rust  
fn decrypt_flag(shared: Integer) {  
   let mut hasher = Sha256::new();  
   hasher.update(shared.to_string());  
   let key = hasher.finalize();  
   let mut cipher = Aes256Ctr::from_block_cipher(  
       Aes256::new_from_slice(&key.as_slice()).unwrap(),  
       &GenericArray::clone_from_slice(&[;; 16]),  
   );  
   let mut flag =
b">\x0f\x13\x1c\x123\xe6\xbf\xccC\xf5*,bfs\x19}\xb5{\x1f\x05\xa7\xe3\xcaE\xedh\xef\x07\x99\xed@\xf1BL\xb1Y\xb7\xcaHg\xdc\xc2'\x93\xdf\xcc\x8a".clone();  
   cipher.apply_keystream(&mut flag);  
   println!(  
       "FLAG = {}",  
       flag.iter().map(|&c| c as char).collect::<String>()  
   );  
}  
```  
And by calling `decrypt_flag(alice.pow_mod(&d, &N).unwrap());` we get our
flag!  
```  
FLAG = flag{https://www.youtube.com/watch?v=uhTCeZasCmc}  
```

Original writeup (https://davidzheng.web.illinois.edu/2021/09/14/csawctf-
bits.html).