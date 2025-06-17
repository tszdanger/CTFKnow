## Task

"We caught two WPI students sending illegal secrets on our network... can you
find out what they said?"

Also we are given pcapng file.

## Solution

There are five packets with any data in this pcapng:  
* STARTING KEY EXCHANGE PROTOCOL  
* g: 10| mod: 667247790729629168801868651264033309682519458519152541737787866083418205742829005514311734375000001| pub: 490305926196059599023102212147002263206141591048662034088541405656196275339142044588265256800520651  
* pub: 395845978879527614395747015710220346649266534299630917403355837833474281961610537213685243037337675| enc_key: 212772881309582973820829804871086196222372777546441069077968628884317585160442388385222503910529273  
* 32 bytes of binary data  
* v=h_D3VFfhvs4   
  
If you are new to pcap's I used wireshark.

So as it says "Key exchange" in the first packet I instantly thought about
Diffie-Hellman key exchange. It makes sense cause then we have generator `g`,
modulus `mod` and two public values.  
  
In D-H `pub = pow(g, random_number, mod)`, so if we wanna break it we gotta
find discrete logarithm.  

My first attempt was to use sagemath.  
Assuming I got all variables set the code is just.  
```python  
K = GF(mod)  
discrete_log(K(pub1), K(g), mod)  
```  
It returns `2100` and as we can check in python/sage `pow(10, 2100, mod) -
pub1 == 0`.  
As for `discrete_log(K(pub1), K(g), mod)` it doesn't want to end counting.

But stop.  
  
I added third argument because that's how it is on the sagemath page, but
that's actually really strange. The third argument should be `ord - integer
(multiple of order of base, or None)` and the order of the base is actually
`mod - 1` but that doesn't work. Maybe I don't get the documentation or sth.
BUT if we drop the third argument (cause it's optional) both
`discrete_log(K(pub1), K(g))` and `discrete_log(K(pub1), K(g))` count without
a problem. My only guess is that setting `ord` which is actually moultiple of
order makes something worse?  
  
But that's me sidetracking, I didn't realize this until writing this writeup.

Also given the logarithm is so small if one would just try bruteforcing his
way e.g. counting powers of `g` until `1e10` he would also find it with no
problem.

So we know discrete logarithm of one of the secrets and that allows us to
count shared secret which is `secret = pow(pub2, discrete_log(pub1), mod)`.  
  
Actuall number is
`470025532326429509257190794699658985614265142446015884571648783710068051626363138484599386732557854`.  
  
So then we gotta decode the enc_key (the guess is that's key to symmetric
block cipher).

My first idea was that `enc_key = secret * key % mod`, but to not go in blind
I checked on
[Wikipedia](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange).  
  
I looked for use in encryption and here we find in [paragraph
5.1](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange#Encryption)
link to [ElGamal Encryption](https://en.wikipedia.org/wiki/ElGamal_encryption)
and it says the exact thing I just proposed.

At this point I was sure that I was right so into decrypting we go.  
  
We just have to get `enc_key / secret` and as we are in Z<sub>mod</sub> it's
`key = enc_key * pow(secret, mod - 2, mod) % mod`.  
  
The result is `key = 128009196690239019135781346654390395054`.  
  
That's a pretty small number compared to `mod` so it must be a hit.  
  
Then I used `Crypto.Util.number.long_to_bytes()` to convert it to byte-like
object. It's exactly 16 bytes so it's perfect.

So I copied data from fourth packet as hexstream and did:  
```python  
>>> cipher =
'8daa192c19dc4037b58def2935623704856779cefe83ff9042677b9b62661c59'  
>>> cipher = int(cipher, 16)  
>>> cipher = long_to_bytes(cipher)  
```

Now we have 16-byte key and 32-byte data to decrypt. The obvious guess is AES
as the most popular symmetric key algorithm AFAIK.  
  
There are multiple modes but the simplest one is ECB it also gives us full
32-byte of data (e.g. CBC has 16-byte IV).  
  
So the last thing to do is:  
```python  
>>> from Crypto.Cipher import AES  
>>> aes = AES.new(key, mode = AES.MODE_ECB)  
>>> aes.decrypt(cipher)  
b'WPI{sTRuk_byA_$m0otH_cR!mIn@1}\x00\x00'  
```

## Other stuff

So after the competition ended we were chatting with the task author.  
  
He explained what was the last packet about (notice I didn't use it).  
  
Notice that YT links are in format `https://www.youtube.com/watch?v=<video
id>`.  
  
That gives us the [video](https://www.youtube.com/watch?v=h_D3VFfhvs4).  
  
That's a hints a fact that `mod - 1` is extremely smooth integer (highly
divisible):  
  
`factor(mod - 1) == 2^6 * 3^13 * 5^12 * 7^14 * 11^2 * 13^13 * 17^10 * 19^4 *
23^14 * 29^12`  
  
Prime numbers that are highly divisible integers plus one are actually really
unsafe cryptographically, that's why offen `modulus = 2 * q + 1` where q is
prime. Those primes are called "safe primes".  
  
Given `mod - 1` is highly divible one can efficiently count discrite logarithm
using this
[algorithm](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm).  
  
I didn't notice that, but my guess is sagemath uses this or similar algorithm
since it can count `discrete_log(pub2, g)`.  

Original writeup (https://github.com/miszcz2137/ctf-
writeups/blob/master/WPICTF2019/Crypto/Backtalk.md).