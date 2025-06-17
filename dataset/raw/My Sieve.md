## My Sieve  
### Challenge  
> We have captured one of the most brilliant spies who successfully broke a
> private key! All the
> [information](https://cr.yp.toc.tf/tasks/recovered_54f706f7fb8fc9718a4600d0000987ea4bcb03d8.txz)
> gathered and we believe they are enough to reconstruct the way he used to
> break the key. Now, can you help us to find the secret message?

We are given the encrypted flag:

```  
enc =
17774316754182701043637765672766475504513144507864625935518462040899856505354546178499264702656639970102754546327338873353871389580967004810214134215521924626871944954513679198245322915573598165643628084858678915415521536126034275104881281802618561405075363713125886815998055449593678564456363170087233864817  
```

A corrupted pem file:

```  
-----BEGIN PUBLIC KEY-----  
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB*QKBgQCkRgRCyTcSwlBKmERQV/BHkurS  
5QnYz7Rm18OjxuuWT3A*Ueqzq7fHISey2NEEtral/*E7v2Dy59DYHoRAAouWQd03  
ZYWnvU5mWoYRcpNmHIj8q*+FOtBWcCGzMZ8uxOxaV74vqqerjxyRI14rXZ+QOcNM  
/TMM84h0rl/IKqqWsQIDAQAB  
-----END PUBLIC KEY-----  
```

and a `msieve.dat` file, which is a file outputted while using msieve
https://github.com/radii/msieve.

### Solution

#### Msieve

Looking at the data file, we see that a `~350` bit number

```  
0x1dabd3bb8e99101030cd7094eb15dd525cb0f02065694604071c2a8b10228f30cc12d08fc9caa8d97c65ff481  
```

was factored. We can recover the factors using the command:

```  
./msieve
17012713766362055606937340593828012836774345940104644978558327325254454345526470012917476548051189037528193  
```

where we must ensure the data file is in the correct directory. Looking into
the log file we find:

```  
Fri Jul 30 19:34:05 2021  Msieve v. 1.46  
Fri Jul 30 19:34:05 2021  random seeds: 98cfb443 69ab82cc  
Fri Jul 30 19:34:05 2021  factoring
17012713766362055606937340593828012836774345940104644978558327325254454345526470012917476548051189037528193
(107 digits)  
Fri Jul 30 19:34:06 2021  no P-1/P+1/ECM available, skipping  
Fri Jul 30 19:34:06 2021  commencing quadratic sieve (106-digit input)  
Fri Jul 30 19:34:06 2021  using multiplier of 11  
Fri Jul 30 19:34:06 2021  using generic 32kb sieve core  
Fri Jul 30 19:34:06 2021  sieve interval: 39 blocks of size 32768  
Fri Jul 30 19:34:06 2021  processing polynomials in batches of 6  
Fri Jul 30 19:34:06 2021  using a sieve bound of 4223251 (149333 primes)  
Fri Jul 30 19:34:06 2021  using large prime bound of 633487650 (29 bits)  
Fri Jul 30 19:34:06 2021  using double large prime bound of 6968329308179250
(45-53 bits)  
Fri Jul 30 19:34:06 2021  using trial factoring cutoff of 53 bits  
Fri Jul 30 19:34:06 2021  polynomial 'A' values have 14 factors  
Fri Jul 30 19:34:06 2021  restarting with 35905 full and 2217078 partial
relations  
Fri Jul 30 19:34:06 2021  149536 relations (35905 full + 113631 combined from
2217078 partial), need 149429  
Fri Jul 30 19:34:07 2021  begin with 2252983 relations  
Fri Jul 30 19:34:07 2021  reduce to 393304 relations in 11 passes  
Fri Jul 30 19:34:07 2021  attempting to read 393304 relations  
Fri Jul 30 19:34:08 2021  recovered 393304 relations  
Fri Jul 30 19:34:08 2021  recovered 385553 polynomials  
Fri Jul 30 19:34:08 2021  attempting to build 149536 cycles  
Fri Jul 30 19:34:08 2021  found 149535 cycles in 5 passes  
Fri Jul 30 19:34:08 2021  distribution of cycle lengths:  
Fri Jul 30 19:34:08 2021     length 1 : 35905  
Fri Jul 30 19:34:08 2021     length 2 : 25563  
Fri Jul 30 19:34:08 2021     length 3 : 24612  
Fri Jul 30 19:34:08 2021     length 4 : 20585  
Fri Jul 30 19:34:08 2021     length 5 : 15651  
Fri Jul 30 19:34:08 2021     length 6 : 10638  
Fri Jul 30 19:34:08 2021     length 7 : 6982  
Fri Jul 30 19:34:08 2021     length 9+: 9599  
Fri Jul 30 19:34:08 2021  largest cycle: 19 relations  
Fri Jul 30 19:34:08 2021  matrix is 149333 x 149535 (43.3 MB) with weight
10166647 (67.99/col)  
Fri Jul 30 19:34:08 2021  sparse part has weight 10166647 (67.99/col)  
Fri Jul 30 19:34:09 2021  filtering completed in 3 passes  
Fri Jul 30 19:34:09 2021  matrix is 143467 x 143531 (41.8 MB) with weight
9815366 (68.38/col)  
Fri Jul 30 19:34:09 2021  sparse part has weight 9815366 (68.38/col)  
Fri Jul 30 19:34:09 2021  saving the first 48 matrix rows for later  
Fri Jul 30 19:34:09 2021  matrix is 143419 x 143531 (24.4 MB) with weight
7565741 (52.71/col)  
Fri Jul 30 19:34:09 2021  sparse part has weight 4961307 (34.57/col)  
Fri Jul 30 19:34:09 2021  matrix includes 64 packed rows  
Fri Jul 30 19:34:09 2021  using block size 57412 for processor cache size
65536 kB  
Fri Jul 30 19:34:09 2021  commencing Lanczos iteration  
Fri Jul 30 19:34:09 2021  memory use: 24.2 MB  
Fri Jul 30 19:34:10 2021  linear algebra at 4.2%, ETA 0h 0m  
Fri Jul 30 19:34:34 2021  lanczos halted after 2270 iterations (dim = 143416)  
Fri Jul 30 19:34:34 2021  recovered 16 nontrivial dependencies  
Fri Jul 30 19:34:35 2021  p2 factor: 11  
Fri Jul 30 19:34:35 2021  prp53 factor:
37517726695590864161261967849116722975727713562769161  
Fri Jul 30 19:34:35 2021  prp53 factor:
41223455646589331474862018682296591762663841134030283  
Fri Jul 30 19:34:35 2021  elapsed time 00:00:30  
```

and so we have the three factors of the number:

```  
Fri Jul 30 19:34:35 2021  p2 factor: 11  
Fri Jul 30 19:34:35 2021  prp53 factor:
37517726695590864161261967849116722975727713562769161  
Fri Jul 30 19:34:35 2021  prp53 factor:
41223455646589331474862018682296591762663841134030283  
```

Now the question was, how does this 350 bit integer relate to the corrupted
public key?

#### Corrupted Key

Looking at the corrupted key, we see 4 `*` though the file. This means naively
we have `64**4` different `N` which are valid. The assumption was that one of
these `N` would share factors the factored number from msieve.

Looking into the pem format, we actually find the first character must be `i`
and so only three chr remain to be searched through. To try and find the
correct `N` we looked for `gcd(X,N)!=0` for all possible keys:

```python  
from math import gcd

corrupt_N =
0xa4460442c93712c2504a98445057f04792ead2e509d8cfb466d7c3a3c6eb964f700051eab3abb7c72127b2d8d104b6b6a5fc013bbf60f2e7d0d81e8440028b9641dd376585a7bd4e665a86117293661c88fca80f853ad0567021b3319f2ec4ec5a57be2faaa7ab8f1c91235e2b5d9f9039c34cfd330cf38874ae5fc82aaa96b1  
X =
0x1dabd3bb8e99101030cd7094eb15dd525cb0f02065694604071c2a8b10228f30cc12d08fc9caa8d97c65ff481  
offsets = [356, 620, 752]

for a in range(64):  
   for b in range(64):  
       for c in range(64):  
           N = corrupt_N | (a<<offsets[0]) | (b<<offsets[1]) | (c<<offsets[2])  
           if gcd(N, X) > 2**32:  
               print("w00t")  
               print(a, b, c)  
               print(N)  
               print(gcd(N, X))  
```

However, running this script we found no values of `N` which had `X`, or a
factor of `X` as a common divisor. The rest of the CTF we tried guessing other
things, but nothing worked out.

During the CTF, this was solved once, by HXP, who solved it by using `X//11`
as the public key:

```python  
from Crypto.Util.number import *  
p = 37517726695590864161261967849116722975727713562769161  
q = 41223455646589331474862018682296591762663841134030283  
N = p*q  
phi = (p-1)*(q-1)  
e = 0x10001  
d = pow(e,-1,phi)  
enc =
17774316754182701043637765672766475504513144507864625935518462040899856505354546178499264702656639970102754546327338873353871389580967004810214134215521924626871944954513679198245322915573598165643628084858678915415521536126034275104881281802618561405075363713125886815998055449593678564456363170087233864817  
flag = long_to_bytes(pow(enc,d,N))  
print(flag)  
# b'CCTF{l34Rn_WorK_bY__Msieve__A5aP}'  
```

This was an unintended solution, and worked as the flag was small enough.
Seeing this, it's dissapointing that we didnt try this guess, but we were so
sure the .pem was needed for the solve, I guess this didnt occur to any of us.

### True Solution

After the CTF ended, the real pem was released.

```  
$ cat pubkey.pem  
-----BEGIN PUBLIC KEY-----  
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkRgRCyTcSwlBKmERQV/BHkurT  
5QnYz7Rm18OjxuuWT3AhUeqzq7fHISey2NEEtral/jE7v2Dy59DYHoRAAouWQd02  
ZYWnvU5mWoYRcpNmHIj8qk+FOtBWcCGzMZ8uxOxaV74vqqerjxyRI14rXZ+QOcNL  
/TMM84h0rl/IKqqWsQIDAQAB  
-----END PUBLIC KEY-----

$ cat pubkey_corrupted.pem  
-----BEGIN PUBLIC KEY-----  
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB*QKBgQCkRgRCyTcSwlBKmERQV/BHkurS  
5QnYz7Rm18OjxuuWT3A*Ueqzq7fHISey2NEEtral/*E7v2Dy59DYHoRAAouWQd03  
ZYWnvU5mWoYRcpNmHIj8q*+FOtBWcCGzMZ8uxOxaV74vqqerjxyRI14rXZ+QOcNM  
/TMM84h0rl/IKqqWsQIDAQAB  
-----END PUBLIC KEY-----  
```

It turns out that `N` was corrupted not only in the four `*` throughout the
file, but additionally the chracaters at the end of the first three lines were
also modified... Using the correct pem we find:

```python  
x =
17012713766362055606937340593828012836774345940104644978558327325254454345526470012917476548051189037528193  
n =
115356776450250827754686976763822189563265178727141719602571509315861796708491086355344129261506721466097001689191320289269213116060519988849918021824941560396659801251826221296538423055226122464968459205865316769204109964482429845998764457962631301677585992875791654646257335269595789163018282966936558671537  
print(gcd(x, n))  
#
1546610342396550509721576417620728439706758721827694998050757029568586758684224546628861504368289912502563  
```

and so our idea was right, but we didnt not understand all the changes.
Essentially after factoring `X` with msieve, the challenge was to replace all
`*` and also know to modify the end of each line. If you have any intuition on
why this is the case, I would love to know.

##### Flag

`CCTF{l34Rn_WorK_bY__Msieve__A5aP}`

Original writeup (https://blog.cryptohack.org/cryptoctf2021-hard#my-sieve).