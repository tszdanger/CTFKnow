# Santa's public key factory (Crypto)  
Description:  
> Santa wanted this factory built ASAP, but we think he got a bit careless and
> didn't take everything into consideration when it comes to security.

> Take a look for yourself, maybe you find something.

> Target: nc challs.xmas.htsp.ro 1000

> Author: Gabies

Files:  
- [server.py](server.py)  
- [chall.py](chall.py)  
- [PoW.py](PoW.py)

Try to netcat into it:  
```  
Provide a hex string X such that sha256(unhexlify(X))[-5:] = 4d9f2  
```  
Write a python script using pwntools to bruteforce the hash:  
```py  
from pwn import *  
p = remote("challs.xmas.htsp.ro" ,1000)  
p.recvuntil("= ")  
h = p.recvuntil("\n")[:-1]  
ans = pwnlib.util.iters.mbruteforce(lambda x:
hashlib.sha256(x.encode()).hexdigest()[-5:] == h.decode() ,
string.ascii_lowercase, length = 10)  
p.sendline(ans.encode().hex())  
```  
Result:  
```  
python solve.py  
[+] Opening connection to challs.xmas.htsp.ro on port 1000: Done  
[+] MBruteforcing: Found key: "acczi"  
[*] Switching to interactive mode

Good, you can continue!  
Welcome to Santa's public key factory, here we create the world's highest
quality keys.  
Since this is an annanounced visit you can look through at most 256 keys.  
As a bonus, try to use those keys to find what Santa's secret message for you
is.  
Choose what you want to do:  
1. get encrypted secret message  
2. guess the secret message  
3. exit

```  
As you can see, we can do 2 actions:  
- Get a encrypted secret  
- Guess the secret

If we choose first one, it will give us ciphertext of the secret and the
public key (n,e):  
```  
Here is the encrypted secret message:
21bde22a91729748fedfe2894c0f7f6b429f6fc5e7d22d1e1c1874d2f290b20232d36a04f278f0c633eda023849b7559080571825366db1c74aacd7e7ea72c03c9456b5ee35a7b3a468a74da5025bf3b2a9de06ddef78743bce166a68dc644f153fe8a21d7940a18178c9a0a24f5f091fd08e81f7f3e862692e3bae1fde4e56b1e4d3d47d1f35dae2aa2973df25c9598111e9eaef2de1728542948160b209c6c92831c9a4556c828ea6af0c77f5977e80c2cf2f2e1630d40fed8ce2f0654b0e05228cca2a77acb9efa2bde42de9c8c7d4738f6922bc744339c8396c6483e28dfb99d471b52b96297ebe7bbb946c4bde1285f0dfccf05e14a5eff1d9f58dffa31.  
Ah, and also here's the public key with which it was encrypted:  
n:
8079251517827751825178719172167487990111025667428873707275844282252086857366991220792422638728205580457168821830720446109151553849503665293191590680021304257703941827528479346437735874924962135492265873751311516610347417680678799212385606079881568852047668753251886773957685411856341109171125195436198060552791609361474280174813748322387475934233174243647432818420527251220486025779441205444896721842028775004810914665584328461829716956450781949380729278880412728798144151876198188092253891223631713243698620872053722596377917656181846754058075274949023762424661690837101140487272809470567668583959162471811693799833  
e: 65537  
```  
Looks like it using RSA to encrypt the secret!

If choose 2nd one, you need enter the secret, if wrong it just exit:  
```  
$ 2  
Let's see what you've got.

$ test  
That was not the secret message. Aborting!

[*] Got EOF while reading in interactive  
```  
## Analyse the source code  
### server.py  
```py  
import os  
import sys  
from hashlib import sha256  
from text import *  
from chall import *  
from PoW import *  
import binascii

if not PoW(5):  
   exit()

action_cnt = 256  
secret_message = os.urandom(8).hex()  
cipher = chall(1024, 16)

print (intro.format(action_cnt))

for i in range(action_cnt):  
	print (menu)  
	x = input()  
	if not x in ["1", "2", "3"]:  
		print (invalid_input)  
		exit()

	if x == "1":  
		msg = int(secret_message, 16)  
		pubkey, privkey = cipher.get_key()  
		ct = hex(cipher.encrypt(msg, pubkey))[2:]  
		n, e = pubkey  
  
		print (enc_flag.format(ct, n, e))

	elif x == "2":  
		print (guess_msg)  
		guess = input()  
		if guess == secret_message:  
			print (win.format(FLAG))  
			exit()  
		else:  
			print (bad_input)  
			exit()

	else:  
		print (goodbye)  
		exit()

sys.stdout.flush()  
```  
As the script says, we only allow to do 256 actions (1 or 2)

And the `secret_message` is 8 random bytes, we need to guess/decrypt it
correctly to get the flag

### chall.py  
```py  
import os  
from random import SystemRandom  
from Crypto.Util.number import inverse  
from gmpy2 import next_prime

class chall:  
   def __init__(self, size, bits):  
       self.rnd = SystemRandom()  
       self.bits = bits  
       self.size = size  
       self.exp = self.rnd.sample(range(32, size - 1), bits)

   def get_rand_int(self):  
       res = 2** (self.size - 1)  
       for i in range(self.bits):  
           if self.rnd.randint(0, 1) == 1:  
               res += 2**self.exp[i]  
       return res

   def get_prime(self):  
       return int(next_prime(self.get_rand_int()))

   def get_key(self):  
       p = self.get_prime()  
       q = self.get_prime()  
       e = 0x10001  
       n = p * q  
       phi = (p - 1) * (q - 1)  
       d = inverse(e, phi)

       pubkey = (n, e)  
       privkey = (n, e, d, p, q)

       return (pubkey, privkey)

   def encrypt(self, pt, pubkey):  
       n, e = pubkey  
       return pow(pt, e, n)

   def decrypt(self, ct, privkey):  
       n, e, d, p, q = privkey  
       return pow(ct, d, n)  
```  
All functions looks fine except the `get_rand_int` function

In the script it create the object like this:  
```  
cipher = chall(1024, 16)  
```  
That means it:  
1. Generate a 16 random numbers between 32 and 1022 put in `exp`  
2. Declare `res` = 2^1023  
3. Loop 16 times, if randint == 1 then add 2^exp[i] into `res`  
4. Return `res`

Notice how `p` and `q` is generated, it get the next prime from the
`get_rand_int` function!  
```py  
def get_prime(self):  
   return int(next_prime(self.get_rand_int()))

def get_key(self):  
   p = self.get_prime()  
   q = self.get_prime()  
```  
Therefore, if we know what exponent it added, then we know the factor of n!

Then we can calculate the private key to decrypt the `secret_message`!

## Find the exponent  
Since the 16 exponent only generate once

If we find all the 16 random exponent, then we can brtue force to find the
factor of n!

But how we find it?

By calculate the `p` and `q` in base 2, we can kind of guess what exponent is
inside `n`:

![image1](image1.gif)

Using python to calculate an example:  
```py  
>>> from gmpy2 import next_prime  
>>> p = next_prime(2**1023 + 2**32)  
>>> q = next_prime(2**1023 + 2**64)  
>>> n=p*q  
>>> bin(n)  
'0b1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000100000000000000000000010011011010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000100001011010000000000000000000000001010110100000000000000101101001001101001'  
```  
You can see there are many 0s in the binary, because only few bits is added

If we ignore the lower bits, we will find out the remaining exponent is 1055
and 1087

Then minus 1023 to get the added exponent:  
```  
1055-1023 = 32  
1087-1023 = 64  
```  
Then we can calculate the `p` and `q`

But the generated `n` not only 2 exponent, it has 16 exponent

If the got 2 exponent sum is more than 1055 (lowest is 32, 1023+32=1055), then
got an extra exponent. (Because of 2^(x+y))

Therefore, we need to count the frequency for each exponent 255 times (Max
request 255 times, 1 left for guess secret message)

Then we sort the frequency more to less, only use the top 20 exponent.

Then we choose the most less exponent public key to filter the exponent, and
bruteforce the exponent

## Proof of Concept  
Before we solving in the real server, we solve it locally first

Written a python script for Poc:  
```py  
from chall import *

cipher = chall(1024, 16)  
keys = []  
# Get 255 different keys  
for i in range(255):  
	pubkey, privkey = cipher.get_key()  
	n, e = pubkey  
	n,e,d,p,q = privkey  
	keys.append([n,[p,q]])

key_exp = []  
freq = []  
for k in keys:  
	exp = []  
	# Get exponent from 1055 to 2045  
	for i in range(1055,2045):  
		if (k[0]>>i)&1:  
			exp.append(i-1023)  
			freq.append(i-1023)  
	key_exp.append([k[0],k[1],exp])

# Get the top 20 exponent  
freq = sorted(set(freq), key=freq.count)[::-1]  
# Get the most less exponent key  
key_exp = sorted(key_exp, key = lambda kv: len(kv[2]))  
print(f"Top 20 exponent: {sorted(freq[:20])}")  
print(f"Actual exponent: {sorted(cipher.exp)}")  
print(f"Most less key: {key_exp[0][0]}")  
print(f"Key p: {key_exp[0][1][0]}")  
print(f"Key q: {key_exp[0][1][1]}")  
print(f"Key exp: {key_exp[0][2]}")  
```  
Result:  
```  
Top 20 exponent: [47, 48, 95, 214, 253, 262, 263, 309, 424, 552, 585, 606,
646, 657, 665, 680, 806, 808, 856, 987]  
Actual exponent: [214, 253, 262, 309, 424, 552, 585, 606, 646, 657, 665, 680,
806, 808, 856, 987]  
Most less key:
8079251517827751825178719172167487990111025667428871008032586356919522324778255772239699723858179939417560110065044611851556574487402107032299197743402392141932054247686699329103141717465089371568625055391278593727207514687901138514719107507580588948894586422923433004438761396962848647558718220008436613555927661783039866123053666626248082865140727911684864205526673220664183149912653250273146092734444369440402812837548963469256931995366954299206480403924032906920658784271024507723630466087075045904032508909470546389456552317197328178611823116568252052989661344217398580131783748164956959961227557488199685401671  
Key p:
89884656743115795386465259539451236680898848947115328636715040579293090826454792239895349175809928509577321472563914801094755384360233327632306397418547700335425480681278244166870657651195930650309744220440301987760493423884561229147390650162873000948780644196095028741778471638545777079553679254792930591469  
Key q:
89884656743115795386465259539451236680898848947115328636715040578866337902750481566354238661203768010560056940533704895462371521673940364332336386690967544471188052302449513285561691785549132023765001375736338282524666244446879484369365007445900774203216682737625702378439195633858734196295717787305007645059  
Key exp: [45, 92, 114, 168, 207, 219, 263, 310, 335, 389, 424, 440, 552, 585,
606, 657, 806]  
```  
As you can see, the top 20 exponent contains all the actual 16 exponent!

Now is the bruteforcing part!

In testing, I notice some key exponents increase by 1 compare to the actual
exponents

You can see it in the previous result:  
```  
Key exp: [45, 92, 114, 168, 207, 219, 263, 310, 335, 389, 424, 440, 552, 585,
606, 657, 806]  
Actual exponent: [214, 253, 262, 309, 424, 552, 585, 606, 646, 657, 665, 680,
806, 808, 856, 987]  
```  
Key | Actual  
--- | ---  
310 | 309  
263 | 262

Maybe some of the exponents is repeated so the exponent increase 1 (2^x + 2^x
= 2(2^x) = 2^(x+1))

Added another script to bruteforce it:  
```py  
import gmpy2  
from itertools import combinations  
import sys  
n = key_exp[0][0]  
exp = key_exp[0][2]  
freq = freq[:20]  
filtered = []  
for i in exp:  
	# if exponent is in the top  
	if i in freq:  
		filtered.append(i)  
	# if repeated exponent is in the top  
	if i-1 in freq:  
		filtered.append(i-1)  
	if i-2 in freq:  
		filtered.append(i-2)  
print(f"Filtered exponent: {filtered}")

# Loop from 1 to length of filtered  
for i in range(1,len(filtered)+1):  
	# Brute force each combination of exponent  
	comb = combinations(filtered,i)  
	for c in list(comb):  
		num = 2**1023  
		for c_i in c:  
			num += 2**(c_i)  
		if n % gmpy2.next_prime(num) == 0:  
			p = gmpy2.next_prime(num)  
			q = n // p  
			print("Factor found!")  
			print(f"p = {p}")  
			print(f"q = {q}")  
			sys.exit()  
```  
Result:  
```  
Top 20 exponent: [132, 150, 179, 281, 289, 302, 340, 360, 387, 399, 552, 595,
607, 644, 648, 705, 717, 783, 815, 1016]  
Actual exponent: [150, 194, 281, 302, 340, 360, 552, 595, 607, 644, 648, 705,
717, 783, 815, 1016]  
Most less key:
8079251517827751825178719172167487990111025667428871008032586356881163784716972723299300352880743495698497340326301158879460499919667754393582483838921244931302683153695581330445763780377518365831641367609072389101218503605982064340020004303854739880503741321720339505556285179305619455995277574704147404062004064383999794878604729476877530388381971298814625934592369650672840240773674128382901187977968894151751752971068487912720177325942701898927812655483049407431481803330386713230039320864031063052186953767982506595774265809152440008644941788958339301931434961047334729242887355502821722366807659411875653787753  
Key p:
89884656743115795386465259539451236680898848947115328636715040578866337902750481566354238661203768010560056939935769677879276839530706569992114919980935353844999923671322009718437498203298385897910636081023580826815541766268314289198272648328709263102291503796984795539680905405708098202787506993849174065367  
Key q:
89884656743115795386465259539451236680898848947115328636715040578866337902750481566354238661203936334908906487887928390505647579662498738887212746471447559646409475734487976256381946573922130293725665783290879494630334996499463654070631336122211470845446124741910085215751020627905319541991521930494678663359  
Key exp: [151, 228, 302, 326, 340, 607, 644, 705]  
Filtered exponent: [150, 302, 340, 607, 644, 705]  
Factor found!  
p =
89884656743115795386465259539451236680898848947115328636715040578866337902750481566354238661203768010560056939935769677879276839530706569992114919980935353844999923671322009718437498203298385897910636081023580826815541766268314289198272648328709263102291503796984795539680905405708098202787506993849174065367  
q =
89884656743115795386465259539451236680898848947115328636715040578866337902750481566354238661203936334908906487887928390505647579662498738887212746471447559646409475734487976256381946573922130293725665783290879494630334996499463654070631336122211470845446124741910085215751020627905319541991521930494678663359  
```  
As you can see, we successfully found the factor of n!!

Now we can solve the actual challenge!

## Solving

Just using the same code as the poc:  
```py  
from pwn import *  
import hashlib  
import re  
from itertools import combinations  
import gmpy2

p = remote("challs.xmas.htsp.ro" ,1000)  
p.recvuntil("= ")  
h = p.recvuntil("\n")[:-1]  
ans = pwnlib.util.iters.mbruteforce(lambda x:
hashlib.sha256(x.encode()).hexdigest()[-5:] == h.decode() ,
string.ascii_lowercase, length = 10)  
p.sendline(ans.encode().hex())  
# p.interactive()  
msg = []  
keys = []  
for i in range(255):  
	p.sendlineafter("exit\n\n","1")  
	result = p.recvuntil("e: 65537")  
	msg.append(re.findall(b"message: ([0-9a-f]+)",result)[0])  
	keys.append(re.findall(b"n: ([0-9]+)",result)[0])

key_exp_msg = []  
freq = []  
for j in range(len(keys)):  
	exp = []  
	for i in range(1055,2045):  
		if (int(keys[j])>>i)&1:  
			exp.append(i-1023)  
			freq.append(i-1023)  
	key_exp_msg.append([keys[j],exp,msg[j]])  
freq = sorted(set(freq), key=freq.count)[::-1][:20]  
n,exp,ciphertext = sorted(key_exp_msg, key = lambda kv: len(kv[2]))[0]  
print(f"Top exp = {freq}")  
print(f"exp = {exp}")

filtered = []  
for i in exp:  
	if i in freq:  
		filtered.append(i)  
	if i-1 in freq:  
		filtered.append(i-1)  
print(f"Filtered exp: {filtered}")

n = int(n)  
for i in range(1,len(filtered)+1):  
	comb = combinations(filtered,i)  
	for c in list(comb):  
		num = 2**1023  
		for c_i in c:  
			num += 2**(c_i)  
		if n % gmpy2.next_prime(num) == 0:  
			print("Factor found!")  
			# Calculate the decryption key to  
			# decrypt the message  
			P = gmpy2.next_prime(num)  
			Q = n // P  
			phi = (P-1)*(Q-1)  
			d = inverse(65537,phi)  
			c = int(ciphertext,16)  
			secret = hex(pow(c,d,n))[2:]  
			# Send the decrypted message  
			p.sendline('2')  
			p.sendlineafter("got.\n",secret)  
			p.interactive()  
```  
After sometime retrying, we got the flag!

*Note:the longer the filtered exp, the longer the bruteforce time*  
```  
python3 solve.py  
[+] Opening connection to challs.xmas.htsp.ro on port 1000: Done  
[+] MBruteforcing: Found key: "eooya"  
Top exp = [88, 67, 596, 530, 373, 99, 869, 210, 641, 490, 801, 70, 538, 37,
926, 965, 868, 693, 375, 152]  
exp = [37, 55, 63, 67, 160, 210, 335, 393, 441, 490, 538, 596, 693, 713, 771,
869, 926]  
Filtered exp: [37, 67, 210, 490, 538, 596, 693, 869, 868, 926]  
Factor found!  
[*] Switching to interactive mode

It seems you are a genius, we can't understand how you did it, but you did.  
Here's your flag: X-MAS{M4yb3_50m3__m0re_r4nd0mn3s5_w0u1d_b3_n1ce_eb0b0506}  
[*] Got EOF while reading in interactive  
$  
```  
## Flag  
> X-MAS{M4yb3_50m3__m0re_r4nd0mn3s5_w0u1d_b3_n1ce_eb0b0506}

## Better solution  
After the ctf ends, saw [a writeup by
lanthan](https://ctftime.org/writeup/25425) shows that this challenge can be
solved by finding common factors for each public key (Which more easier and
efficient way)

Original writeup (https://github.com/Hong5489/xmas2020/tree/main/public).