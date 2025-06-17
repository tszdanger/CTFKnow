# The Code  
```  
#!/usr/bin/env python3  
from math import gcd  
from Crypto.Util.number import getPrime,getRandomInteger

flag = "KITCTF{fake_flag}"

p = getPrime(512)  
q = getPrime(512)  
n = p*q  
phi = (p-1)*(q-1)  
e = getPrime(256)  
while gcd(e, phi) != 1:  
   e = getPrime(256)

d = pow(e, -1, phi)

def sign(m):  
   return pow(m, d, n)

def check(c, m):  
   return pow(c, e, n) == m

result = getRandomInteger(256)  
print(f"Number of pockets: {hex(n)}")  
print(f"The Manager told me, the roulette is crooked and will hit
{hex(result)}")  
base = 16  
m2 = int(input(f"What should I bet? "), base)  
if m2 % n == result:  
   print("It is too obvious if I bet that")  
else:  
   s2 = sign(m2)  
   print(f"My Signatur is {hex(s2)}")  
   message = int(input(f"What do you want to bet? "), base)  
   signature = int(input(f"Please sign your bet "), base)  
   if result == message and check(signature, message):  
       print(f"You Win: {flag}")  
   else:  
       print("You Lose")  
```

As we see, the program first generates a set of RSA parameters (modulo $n$,
public key $e$, private key $d$)

The signing process is as expected, we compute $m^d\ mod\ n$. This is
equivalent to encrypting with the private key. For Signature checking we
decrypt the value and check that it is the message we expect $c^e \equiv m\
mod\ n$.

Now in the main program, we get the number $n$ and a value we want to bet for
later on. Now we can send any number (that is not the randomly chosen result)
and get a signature of it. To get the flag, we now have to provide valid
signature for the randomly chosen result. Of course that's why we cannot let
the server sign the result itself, because then this would be too easy :D

# A short intro on RSA  
Why does this work? Well, the public key $e$ and the private key $d$ are
chosen such that $e \cdot d \equiv 1\ mod\ \phi(n)$. So what is $\phi$? It is
called [Euler's totient
function](https://en.wikipedia.org/wiki/Euler%27s_totient_function) and counts
the number of integers $< n$ which do not share a common factor with $n$.

But before we go into that, let's look at how modulo arithmetic works. Two
numbers $a$ and $b$ are called congruent mod n if and only if: $$a + k \cdot n
= b \qquad(k \in \mathbb{Z})$$ which means that if we can add or subtract a
multiple of our modulus to arrive at the same value on both sides, then they
are deemed equal.

Here are some examples:  
$$2 \equiv 17\ mod\ 5 \Leftrightarrow 2 + 3 \cdot 5 = 17 $$  
$$7 \equiv 2\ mod\ 5 \Leftrightarrow 7 + (-1) \cdot 5 = 2$$

Note that most of our basic arithmetic still works the same (+ - \*). Division
is more diffifcult, because we have to undo what multiplication did. If you've
heard some elementary number theory, you may remember that there is always
some neutral element and an inverse element for a given operation.

For multiplication the neutral element is $1$, because it does not change
anything. The inverse has the property such that $a * b = 1$. In normal
multiplication the inverse would be $\frac{1}{a}$, because $a * \frac{1}{a} =
1$, which is basically just another notation for division.

Note that we can define division by multiplicating with a number's inverse: $a
/ b \equiv a * b^{-1}\ mod\ n$. How do we compute the inverse? it can be done
with the [extended euclidian
Algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm). I will
not go into the details here, but you can compute it via python: `pow(a, -1,
n)`, which is equivalent to $a^{-1}\ mod\ n$. This is only possible if $gcd(a,
n) = 1$, e.g. $a$ and $n$ do not share a common factor. This will be important
later on. Also note that in the code, there e is chosen such that $gcd(e,
\phi(n)) = 1$. This ensures that there is a inverse element for $e$.

So, now what's the fuss with $\phi$? Remember, that RSA encryption/decrypton
was defined over exponentiation: $m^e\ mod\ n$...

Now, this works exactly like the normal exponentiaton ($a^b$ is just $a \cdot
\ldots \cdot a$ ($b$ times)). Except that the numbers will repeat after a
while. Indeed there are only $n$ possible results $mod\ n$, so this is
inevitable after at most $n$ steps. But we can prove even more, the numbers
will repeat after $\phi(n)$ steps. Therefore $m^{\phi(n)} \equiv m^0 \equiv 1\
mod\ n$. This is called [Euler's
Theorem](https://en.wikipedia.org/wiki/Euler%27s_theorem). I will not go into
proving this here, just believe me or take a look at the link ;)

Furthermore, if we have two numbers $a \equiv b\ mod\ \phi(n)$, then $x^a
\equiv x^b\ mod\ \phi(n)$. In other words, the exponents form a modular group
$mod\ \phi(n)$ themselves! So, what's the value of $\phi(n)$? Well $n$
consists of two (different!) primes $p$ and $q$. Because they do not share a
common factor $\phi(n) = \phi(p)\phi(q)$. And for a prime $p$ $\phi(p) = p-1$,
because by definition a prime is not divisible by anything other than $1$ and
$p$. Therefore $\phi(n) = (p-1)(q-1)$.

Remember that our arithmetic rules still hold. Now let's proof that decrypting
a message encrypted with the private key works:  
$$(m^d)^e \equiv m^{d \cdot e} \equiv m^1 \equiv m\ mod\ n$$

We used the exponentiation rule $(a^b)^c = a^{b \cdot c}$ and the fact that we
chose $e$ and $d$ such that $e \cdot d \equiv 1\ mod\ \phi(n)$. We showed that
we can decrypt with the public key $e$, a message that was encrypted with the
private key $d$. Proving the other way round works exactly the same.

I hope that you now have some basic understanding of how RSA works, so that we
can now look at why this challenge insecure.  
# Blinding Attack on Textbook RSA  
Wait, why is it called "Textbook RSA" all of a sudden? Well, I lied to you in
the previous section :) This is not RSA in practice (because it is insecure as
we will see). In practice RSA uses some padding scheme to change the message
$m$  before encryption/decryption. That's why RSA without padding is often
called "Textbook RSA" and you should never use it for something serious. Take
look at [this StackExchange
Question](https://crypto.stackexchange.com/questions/9106/rsa-padding-what-is-
it-and-how-does-that-work) or [the wikipedia page on
RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Padding) if you want to
know more.

So, let's get back to the "Blinding Attack". The idea is explained
[here](https://comp38411.jtang.dev/docs/public-key-cryptography/breaking-
textbook-rsa-signatures/), but I will summarize the key points again.

But before that, let's remind us about the challenge code. Remember that we
can send any number (other than the result) and get a valid signature for that
number. In the end we have to send a valid signature for $result$ to the
server.

Therefore we want to obtain a (valid) signature for the message $m$ (in our
case $m = result$). Do you still remember the properties of multiplication
from high school?  
$$(a \cdot b)^c = a^c \cdot b^c$$

We can use this here as well. If we let the server sign $m' \equiv a \cdot m$,
then:  
$$m'^d \equiv (a \cdot m)^d \equiv a^d \cdot m^d\ mod\ n$$

Now, all we have to do is divide by $a^d$ and we have a valid signature for
$m$! But the problem is we don't know $a^d$ and cannot compute it, because we
do not know $d$. (If we would know $d$, then we could just compute $m^d\ mod\
n$ as a valid signature. That's why it's called __private__ key after all...)

So, what do we do now? Can we get rid of that $d$ somehow? The answer is yes:
Remember that $(a^e)^d \equiv a^{e \cdot d} \equiv a\ mod\ n$!

So instead of signing $m' \equiv a \cdot m\ mod\ n$, we let the server sign
$m' \equiv a^e \cdot m\ mod\ n$, which yields $m'^d \equiv a \cdot m^d\ mod\
n$. Now we only need to divide by $a$, which we know because we chose that
number to begin with.

This is what you would normally do, but in this case we do not know the public
key $e$. Normally this is public knowledge as the name suggests, but I guess
the challenge author decided to make things more interesting ;) (Most of the
time $e=65537$, because this does not need to be secret or random at all)

So we need another idea for this...

Let's try the signatures of some special numbers:  
$$1^d \equiv 1\ mod\ n$$ Well if we send $m' \equiv 1 \cdot m\ mod\ n$, then
$m' \equiv m\ mod\ n$ and the server will not accept this.  
$$0^d \equiv 0\ mod\ m$$ This one is more interesting, but it ultimately
fails, because we cannot divide by $0$ (Furthermore, note that $m' \equiv 0 *
m \equiv 0\ mod\ n$) which just makes it impossible to get some information
back as the signature will always be $0$)  
$$(-1)^d \equiv (1\text{ if d is even else }-1)\ mod\ m$$ Now, this is
interesting. We send $m' \equiv (n-1) \cdot m\ mod\ n$ (Rember that $-1 \equiv
n-1\ mod\ n$) and get back either $m^d\ mod\ n$ or $(n-1) \cdot m^d\ mod\ n$.
Then we either have to divide by $1$ or $n-1$ to get a valid signature for
$m$.

__NOTE:__ You may notice that $d$ is never even. This is because $\phi(n) =
(p-1)(q-1)$, where $p$ and $q$ are prime. Because all primes $> 2$ are not
even, $p-1$ and $q-1$ will be even. Remember that $e$ and $d$ are the
multiplicative inverse elements of each other. To compute the inverse we have
noted that $gcd(e, \phi(n)) = 1$ and $gcd(d, \phi(n)) = 1$, both must be true.
But now that we know that $\phi(n) = (p-1)(q-1)$ is divisible by 2, then
neither $e$ nor $d$ can be even, because then they would share the common
factor of $2$ with $\phi(n)$ and there would be no inverse element for that
number!

So, to sum up:  
1. Let the server sign $m' \equiv (n-1) \cdot m\ mod\ n$ and obtain $sig(m') = (n-1) \cdot sig(m)$  
2. Now compute $sig(m) = sig(m') \cdot (n-1)^{-1}\ mod\ n$, where $(n-1)^{-1}$ is the multiplicative inverse of $n-1$ modulo $n$ (python: `pow(n-1, -1, n)`)  
3. Send the target $m$ along with the signature $sig(m)$ and get the flag!

In python it looks something like this:  
```python  
n = int(input("Give me n"), 16)  
result = int(inut("Give me the result"), 16)

print("Let the server sign this", hex(((n-1) * result) % n))  
sig = int(input("Signature: "), 16)

print("Forged signature:", hex((sig * pow(n-1, -1, n)) % n))  
```