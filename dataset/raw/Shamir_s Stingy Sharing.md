# Task

I set up a secret sharing system with my friends, but now my friends all hate
me. Can you help me get the secret anyway?

*Attachment with the source code:*

```python  
import random, sys  
from crypto.util.number import long_to_bytes

def bxor(ba1,ba2):  
	return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

bits = 128  
shares = 30

poly = [random.getrandbits(bits) for _ in range(shares)]  
flag = open("/challenge/flag.txt","rb").read()

random.seed(poly[0])  
print(bxor(flag, long_to_bytes(random.getrandbits(len(flag)*8))).hex())

try:  
	x = int(input('Take a share... BUT ONLY ONE. '))  
except:  
	print('Do you know what an integer is?')  
	sys.exit(1)  
if abs(x) < 1:  
	print('No.')  
else:  
	print(sum(map(lambda i: poly[i] * pow(x, i), range(len(poly)))))  
```

# Task analysis

First thing that catches the eye is that this "secret sharing system" isn't
actually a polite one - it responses with a heartfelt insult if we dare to
send it something but integer. Maybe that's the real reason why all friends
hate you now, Shamir? Anyway, after hours of googling what an integer is and
overcoming a sudden impostor syndrom attack I was able to finally recover from
such a terrible assault and start investigating source code. Below is a
scratch of how it works:  
- 30 random numbers (`shares`) 128 bits long are generated when we connect to server and are put into array called `poly`  
- First `share` of `poly` is used as seed for a subsequent number generation  
- Each flag character is XOR ed with randomly generated bits and result is printed to us as a hex value  
- Then we are requested to enter aforementioned integer `x`  
- `x` is used to calculate sum `poly[i] * x ** i`, where `i = 0, 1 ... 29`. This sum is also printed

# Finding vulnerability

So far, we are given two values:  
1. Encrypted flag  
2. Some sum of `shares` that depends on our input `x`

To get the flag we need to decrypt it. To decrypt the flag we need to know the
key. Once we get it, we can simply XOR it with the encrypted flag for
decryption. Key is some randomly generated number. Fortunately for us, first
`share` of `poly` is used as a seed for key generation. So if we know the
`poly[1]` then we'll be able to replicate key generation.

We know that `poly[0]` along with other `shares` is used to calculated the sum
of shares. This sum also depends on `x`, our input. Let's investigate deeper
the relation between `x` and sum of `shares` and see what we can get out of
it.

For demonstration purpose, let's consider:  
`poly = [42, 33, 54]`  
for `x = 3`  
```  
42 * (3^0) = 42  
33 * (3^1) = 99  
54 * (3^2) = 486  
sum = 42 + 99 + 486 = 627  
```  
Hope that now it's clear how the sum is calculated. But `x = 3` is not that
useful for us - there's no way we can get `poly[1]` which is `42` from `627`.
Let's consider more interesting case where `x = 1000`  
```  
42 * (1000^0) =       42  
33 * (1000^1) =    33000  
54 * (1000^2) = 54000000  
sum = 42 + 33000 + 54000000 = 54033042  
```  
Bingo! You see it? Last two digits of sum is actually the first `share` that
we are looking for. So, by entering `x = 10^n` where `n > len(poly[0])` we are
able to easily extract first `share` from the resulting sum.

# Assembling exploit

Let's get `poly[1]` first. I am a lazy one, so I just did it manually:  
```  
f79ace6c50045d9617387178738bc492c8a36bce6f62065ffd1712060127af  
Take a share... BUT ONLY ONE.
1000000000000000000000000000000000000000000000000000000000  
34478190794372095687151499154929969606000000000000000000189455481892595731087980110991446798558000000000000000000114630140621231452731774690192563700399000000000000000000106632736526610982274784394939300666050000000000000000000291631389647804997343114057740596739647000000000000000000172012636010265165504878126886679875380000000000000000000336861561406951606841928859228335262394000000000000000000161848776124756622238036523550575234204000000000000000000206862146054773644222270964178367439926000000000000000000224747282815671094222821409187167038646000000000000000000167733096288035467315188096730334274378000000000000000000197540947692537841721737142231640993834000000000000000000255889694312681513731712154838030686397000000000000000000179179493363428125430318105043279961232000000000000000000042849152778181079831098138309449439970000000000000000000132016736123401412585347409983527651970000000000000000000128062869669623764825957631887084013359000000000000000000282823708958133194464944972998546961307000000000000000000258963511533578375727556494488139105966000000000000000000106113149607806035776895731827681332171000000000000000000317662669549313551440810288726726989624000000000000000000333094458583116878063642005820211993426000000000000000000323902500681250286825223845301590529386000000000000000000067066857889771218669374826568658446582000000000000000000213694534015072472486306685687034856088000000000000000000035020349875265934224376635827160468187000000000000000000323763878541563552432622617181982778364000000000000000000126141063774744186389048070631075055350000000000000000000121036704086086339233282037033529357567000000000000000000005071636503793964919135745354381215807  
```

now all that is left to do is to generate key using `poly[0]` and XOR it with
a given encrypted flag:

```python  
#!/usr/bin/python3

import random  
from Crypto.Util.number import long_to_bytes, bytes_to_long

def bxor(ba1, ba2):  
   return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

encrypted_flag =
'f79ace6c50045d9617387178738bc492c8a36bce6f62065ffd1712060127af'  
poly_0 = 5071636503793964919135745354381215807

random.seed(poly_0)  
key = long_to_bytes(random.getrandbits(len(encrypted_flag)*4))  
print(key)  
flag = bxor(long_to_bytes(int(encrypted_flag, 16)), key)  
print(flag.decode())  
```

After running this script we will get the flag:  
rarctf{n3v3r_trust_4n_1nt3g3r}

## Interesting fact  
Formula for sum calculation is very similar to the positional system formula
(https://en.wikipedia.org/wiki/Numeral_system#Positional_systems_in_detail)
but the latter one has some restrictions

Original writeup
(https://gist.github.com/KovalDS/e504655fddd2c4e1bd03a0814bdaad90).