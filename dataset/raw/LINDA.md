## LINDA  
### Challenge  
> Dan Boneh loves to improve cryptosystems, you should be loving breaking
> them?  
`nc 07.cr.yp.toc.tf 31010`  
- [linda.txz](https://cr.yp.toc.tf/tasks/linda_a26f6987ed6c630297c2df0847ef258ad3810ca2.txz)

```python  
#!/usr/bin/env python3

from Crypto.Util.number import *  
from math import gcd  
from flag import flag

def keygen(p):  
   while True:  
       u = getRandomRange(1, p)  
       if pow(u, (p-1) // 2, p) != 1:  
           break  
   x = getRandomRange(1, p)  
   w = pow(u, x, p)  
   while True:  
       r = getRandomRange(1, p-1)  
       if gcd(r, p-1) == 1:  
           y = x * inverse(r, p-1) % (p-1)  
           v = pow(u, r, p)  
           return u, v, w  
  
def encrypt(m, pubkey):  
   p, u, v, w = pubkey  
   assert m < p  
   r, s = [getRandomRange(1, p) for _ in '01']  
   ca = pow(u, r, p)  
   cb = pow(v, s, p)  
   cc = m * pow(w, r + s, p) % p  
   enc = (ca, cb, cc)  
   return enc

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
   pr(border, "  .:::::: LINDA Cryptosystem has high grade security level
::::::.  ", border)  
   pr(border, "  Can you break this cryptosystem and find the flag?
", border)  
   pr(border*72)

   pr('| please wait, preparing the LINDA is time consuming...')  
   from secret import p  
   u, v, w = keygen(p)  
   msg = bytes_to_long(flag)  
   pubkey = p, u, v, w  
   enc = encrypt(msg, pubkey)  
   while True:  
       pr("| Options: \n|\t[E]xpose the parameters \n|\t[T]est the encryption \n|\t[S]how the encrypted flag \n|\t[Q]uit")  
       ans = sc().lower()  
       if ans == 'e':  
           pr(f'| p = {p}')  
           pr(f'| u = {u}')  
           pr(f'| v = {v}')  
           pr(f'| w = {w}')  
       elif ans == 's':  
           print(f'enc = {enc}')  
       elif ans == 't':  
           pr('| send your message to encrypt: ')  
           m = sc()  
           m = bytes_to_long(m.encode('utf-8'))  
           pr(f'| encrypt(m) = {encrypt(m, pubkey)}')  
       elif ans == 'q':  
           die("Quitting ...")  
       else:  
           die("Bye ...")

if __name__ == '__main__':  
   main()  
```

### Solution  
By interacting with the challenge, we can get public key parameters by sending
`e`, get encrypted flag with `s`,  encrypt our own messages with `t` and quit
with `q`. Only the first two options will be relevant to the solution.

Encryption here works like this: $p, u, v, w$ are public key parameters,
message $m$ is encrypted as  
follows:

$$  
ca \equiv u^r \mod p \\  
cb \equiv v^s \mod p$ \\  
cc \equiv mw^{r + s} \mod p  
$$

where $r, s$ are uniformly random numbers from $[1;p]$.

We can notice that despite $p$ being new on each connection, $p - 1$ is always
smooth. Example:

```python  
p =
31236959722193405152010489304408176327538432524312583937104819646529142201202386217645408893898924349364771709996106640982219903602836751314429782819699  
p - 1 = 2 * 3 * 11 * 41 * 137 * 223 * 7529 * 14827 * 15121 * 40559 * 62011 *
429083 * 916169 * 3810461 * 4316867 * 20962993 * 31469027 * 81724477 *
132735437 * 268901797 * 449598857 * 2101394579 * 2379719473 * 5859408629 *
11862763021 * 45767566217  
```

This is the key for solving this challenge, because after getting public key
paramters and encrypted flag we can factor $p - 1$ by using trial division and
[ECM](https://en.wikipedia.org/wiki/Lenstra_elliptic-curve_factorization),
then use [Pohlig-Hellman
algorithm](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm) to
compute $r, s$ as discrete logarithms of $ca, cb$ with bases $u, v$
respectively even without trying to find weaknesses in the keygen process.
Then we can compute $m \equiv ccw^{-(r + s)} \mod p$ and get the flag.

```python  
#!/usr/bin/env sage  
from minipwn import remote # mini-pwntools library to connect to server  
from Crypto.Util.number import long_to_bytes

rem = remote("07.cr.yp.toc.tf", 31010)  
for _ in range(10):  
   rem.recvline()  
rem.sendline('e')  
p = int(rem.recvline()[6:])  
u = int(rem.recvline()[6:])  
v = int(rem.recvline()[6:])  
w = int(rem.recvline()[6:])  
for _ in range(5):  
   rem.recvline()  
rem.sendline('s')  
ca, cb, cc = map(int, rem.recvline()[7:-2].split(b', '))  
r = discrete_log(Mod(ca, p), Mod(u, p)) # sage has built-in discrete logarithm
function, which uses Pohlig-Hellman  
s = discrete_log(Mod(cb, p), Mod(v, p)) # algorithm and automatically
determines and factors group order, which divides p - 1  
m = cc * power_mod(w, -(r + s), p) % p  
print(long_to_bytes(m).decode())  
```

##### Flag  
`CCTF{1mPr0v3D_CrYp7O_5yST3m_8Y_Boneh_Boyen_Shacham!}`

Original writeup (https://blog.cryptohack.org/cryptoctf2021-medium#linda).