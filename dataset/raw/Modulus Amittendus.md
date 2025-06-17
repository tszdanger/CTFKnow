# TSG CTF 2020 Writeups

- [Beginners Crypto](#beginnerscrypto)  
 - Category : Crypto  
 - Files : [beginner.py](TSG%20CTF%202020/Beginners%20Crypto/beginner.py)  
 - Points : 107  
 - Solves : 86  
- [Modulus Amittendus](#Modulus_Amittendus)  
 - Category : Crypto  
 - Files : [rsa.rb](TSG%20CTF%202020/Modulus%20Amittendus/rsa.rb), [pubkey.json](TSG%20CTF%202020/Modulus%20Amittendus/pubkey.json), [output.txt](TSG%20CTF%202020/Modulus%20Amittendus/output.txt)   
 - Points : 365  
 - Solves : 5  
 - solution code : [solve.py](TSG%20CTF%202020/Modulus%20Amittendus/solve.py)  
---  
#  Beginners Crypto challenge writeup [Crypto]

We were given a single file (beginner.py) which contains two assert
conditions.  
```python  
assert(len(open('flag.txt', 'rb').read()) <= 50)  
assert(str(int.from_bytes(open('flag.txt', 'rb').read(), byteorder='big') <<
10000).endswith('1002773875431658367671665822006771085816631054109509173556585546508965236428620487083647585179992085437922318783218149808537210712780660412301729655917441546549321914516504576'))  
```  
First condition checks that length of the flag is less than or equal to `50`.  
  
Second condition reads and converts the flag to an integer then left shifts it
to 10000, and then converts the resultant to string and checks that strings
ends with given value.

Rephrasing the two conditions :  
  
`len(flag) <= 50` implies when converted to integer it will be less than
`2**(8*50) = 2**400`  
  
left shift in the second condition can be written as `flag * 2**10000` as
`str` function represents the integer in base 10 and endswith parameter
contains number of `175` digits.  
So,  
```  
flag <= 2**400  
flag * 2**10000 % 10**175 =
1002773875431658367671665822006771085816631054109509173556585546508965236428620487083647585179992085437922318783218149808537210712780660412301729655917441546549321914516504576  
```  
multiplying the inverse of `2**10000` modulo `10**175` would give the `flag`
modulo `10**175` which would give original flag value but the problem is that
inverse doesn't for `2**10000` modulo `10**175`  
as `gcd of both values is not equal to 1`.  
  
In order to get the flag we can use `5**175` as the modulus as it is a factor
of `10**175`.  
```  
((flag * 2**10000) % 10**175) % 5**175 == (flag * 2**10000) % 5**175  
(flag * 2**10000) * inverse(2**10000, 5**175) == flag  
As 5**175 > 2**400 resultant of above computation will give us the Original
Flag.  
```  
**Flag :: TSGCTF{0K4y_Y0U_are_r3aDy_t0_Go_aNd_dO_M0r3_CryPt}**  
---  
#  Modulus Amittendus challenge writeup [Crypto]

Luckily, I got First Blood for this Challenge.  
  
In this challenge we were given
[rsa.rb](TSG%20CTF%202020/Modulus%20Amittendus/rsa.rb),
[output.txt](TSG%20CTF%202020/Modulus%20Amittendus/output.txt),
[pubkey.json](TSG%20CTF%202020/Modulus%20Amittendus/pubkey.json).  
  
`rsa.rb` contains the implementation of Textbook rsa encryption.  
  
`rsa.rb` generates two random primes `p` and `q` each 1024 bits long.  
  
`output.txt` contains rsa encrypted flag with e = 65537.  
  
`pubkey.json` contains json data with keys `e, n, cf`.  

Even though `pubkey.json` contains `n` as key but its value is d.  
```ruby  
 def pubkey  
   privkey.to_a[..2].to_h  
 end

 def privkey  
   {  
     e: @e,  
     n: @d,  
     cf: @cf,  
     p: @p,  
     q: @q,  
     exp1: @exp1,  
     exp2: @exp2,  
   }  
 end  
```  
In order to solve the challenge we have to calculate the value of `n = p * q`.  
so, we have values of e, d and cf.  
```  
e = 65537  
d =
27451162557471435115589774083548548295656504741540442329428952622804866596982747294930359990602468139076296433114830591568558281638895221175730257057177963017177029796952153436494826699802526267315286199047856818119832831065330607262567182123834935483241720327760312585050990828017966534872294866865933062292893033455722786996125448961180665396831710915882697366767203858387536850040283296013681157070419459208544201363726008380145444214578735817521392863391376821427153094146080055636026442795625833039248405951946367504865008639190248509000950429593990524808051779361516918410348680313371657111798761410501793645137  
cf = q**-1 mod p =
113350138578125471637271827037682321496361317426731366252238155037440385105997423113671392038498349668206564266165641194668802966439465128197299073392773586475372002967691512324151673246253769186679521811837698540632534357656221715752733588763108463093085549826122278822507051740839450621887847679420115044512  
```  
As  
```  
e * d = 1 mod phi(n)  
e * d - 1 = k * phi(n) , k < min(e, d)  
phi(n) = (e * d - 1) // k  
phi(n) < (n = p*q) < 2**2048  
```  
Trying the k values from `2 to e - 1` and checking two conditions `(e * d - 1)
% k == 0` and  
`phi(n) < 2**2048` gives only single possible value for k, `k = 62676`.  
Calculating `(e * d - 1) // k` gives us the value of `phi(n)`

Using the values of `cf = q**-1 mod p`, `phi(n)` and their formulas gives us  
```  
cf = q**-1 mod p  
cf * q = 1 mod p  
cf * q - 1 = 0 mod p  
phi(n) = (p - 1) * (q - 1) = p * q - p - q + 1 = n - p - q + 1  
cf * phi(n) = cf * (n - p - q + 1) = cf * n - cf * p - cf * q + cf  
cf * phi(n) mod p = (cf * n - cf * p - cf * q + cf) mod p  
                 = 0 - 0 - (cf * q) + cf mod p  
                 = - (1) + cf mod p  
                 = cf - 1 mod p  
cf * phi(n) - cf + 1 = 0 mod p  
cf * phi(n) - cf + 1 = kp * p  
```  
`cf * phi(n) - cf + 1` gives us a multiple of p.  
let `pmul = cf * phi(n) - cf + 1`.

And  
```  
from fermat theorem  
r**(p-1) = 1 mod p , r is a random integer.  
r**phi(n) = (r**(p-1))**(q-1) = (1)**(q-1) mod p = 1 mod p  
```  
For any random integer r, k1, k2  
  
```r mod k2 == (r mod k1) mod k2``` is `True` if k2 is a factor of k1.

Therefore,  
  
`r**phi(n) mod p = (r**phi(n) mod pmul) mod p = 1`  
  
we cannot calculate `r**phi(n)` directly but we can calculate `r**phi(n) mod
pmul` using square and  
multiply algorithm.  
  
`(r**phi(n) mod pmul) mod p = 1 mod p`  
  
`pow(r, phi(n), pmul) - 1 = k * p`  
  
In this way we can obtain any number of `p` multiples. Calculating the `gcd`
of multiples of `p` gives the value of `p`.  
  
Given `p` we can calculate the value of `q` using `cf (qInv mod p)`.  

After obtaining the value of `n = p * q`, decrypting the `ciphertext` gives us
the `flag`.  

Solution Script :: [solve.py](TSG%20CTF%202020/Modulus%20Amittendus/solve.py)

FLAG ::
TSGCTF{Okay_this_flag_will_be_quite_long_so_listen_carefully_Happiness_is_our_bodys_default_setting_Please_dont_feel_SAd_in_all_sense_Be_happy!_Anyway_this_challenge_is_simple_rewrite_of_HITCON_CTF_2019_Lost_Modulus_Again_so_Im_very_thankful_to_the_author}  

Original writeup (https://github.com/S3v3ru5/CTF-
writeups/tree/master/TSG%20CTF%202020).