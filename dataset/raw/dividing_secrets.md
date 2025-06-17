#
<https://git.lain.faith/BLAHAJ/writeups/src/branch/writeups/2021/corctf/dividing_secrets>  
# dividing\_secrets

by [haskal](https://awoo.systems)

crypto / 434 pts / 121 solves

>I won't give you the secret. But, I'll let you divide it.  
>  
>`nc crypto.be.ax 6000`

provided files:
[server.py](https://git.lain.faith/BLAHAJ/writeups/src/branch/writeups/2021/corctf/dividing_secrets/server.py)

## solution

inspecting the server script... it seems to be using a 512 bit prime `p` and
taking a random number  
`g` to the power of the secret flag message `x` mod `p`. in order to crack
this you'd need to come  
up with an efficient solution for the [Discrete Log  
Problem](https://en.wikipedia.org/wiki/Discrete_logarithm#Algorithms)

luckily, the server also lets you divide the exponent by an arbitrary input
number up to 64 times  
(that's `512/8` for those who are paying attention, which suggests taking a
character-by-character  
approach). the exploit concept is to use the division to shift `x` all the way
to 8 bits, then try  
to guess what those 8 bits are by trying all 256 possible values. then, once
that is known, move on  
to the next 8 bits using the known segment and combining it with another round
of 256 guesses

it looks kinda like this

```python  
# start by doing x >> 504  
# (this is the same as x / (2**504))  
position = 504  
top_bits = 0

while True:  
   # send off the next guess  
   r.recvuntil("number> ")  
   r.sendline(str(2**position))  
   h = int(r.recvline().decode())  
   # guess every possible character  
   for i in range(256):  
       if pow(g, (top_bits << 8) | i, p) == h:  
           # once it is found, move on  
           sys.stdout.write(chr(i))  
           top_bits = (top_bits << 8) | i  
           position -= 8  
           break  
```

running the `exploit.py` script should produce

```  
[+] Opening connection to crypto.be.ax on port 6000: Done  
g
3163314640353309966974084350140065528835797402483351605270276213160985733919488025191658477221550585332241782718778635951464919000972247044376608291073497  
p
9937890065686116796205186685937536971919686769106263396090623316690565375989826956720662974087853527508968612312091794142094431426690835778526649323968253  
enc
5829222177042077791091257368279368382423357539393247444397252396260207162571334610710294330374985463989052071335431112395334343144642068220012344459731980  
corctf{qu4drat1c_r3s1due_0r_n0t_1s_7h3_qu3st1on8852042051e57492}[*] Closed
connection to crypto.be.ax port 6000  
Traceback (most recent call last):  
.....  
...  
 File "/usr/lib/python3.9/site-packages/pwnlib/tubes/sock.py", line 58, in
recv_raw  
   raise EOFError  
EOFError  
```  

Original writeup
(https://git.lain.faith/BLAHAJ/writeups/src/branch/writeups/2021/corctf/dividing_secrets).