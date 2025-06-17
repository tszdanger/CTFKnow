This time the flag is padded to a fixed length of 128 with random chars (both
leading and trailing).  
```php  
//For these 3 problems I'll only change these 2 lines:  
$flag = trim(file_get_contents("../../flag2.txt"));  
$key = pad_string($flag, 128);  
```

We know the flag format, also the plaintext consists of only uppercase
characters, so let's write a script to find the position of the flag in the
key  
```python  
from Crypto.Util.number import *  
from string import ascii_uppercase

KLEN = 128  
key = b'UDCTF{'  
ct =
[0xde1aaff3510601061a092e2a7b307e3e23100f643a1e27203a763c22763a1a35783a38a73de82037856d0e68a62d5fd23cc78e88c4c88ef8a307cd96d8d26d461ab0d4fa35c675befe312308972f1f1e7d0b9f536f5ba7c1ea43f5eebfb7a3ac756e4efd9053fd0b42df31c56cc175cd5c26afbfbc116a31b5d80c7c869a1617df12acef59061d0c01092924642b643929171966370b3b3b27742633763c192f652429b137e8202f9f781d6bbc3b4ec82bc78a95c0d490e2be1dc48ed4d9765b0db0cafa30dc63adf6272412942f1906640b9a4c7c52b4d0e45ae5e7b2b0b8ab767d5bfe9c52f5005fd020c063db75c45d35bda6ac0f6621b9cc1e789b9a100cd91aa0e8411d051511023423762d65212210167f26173a3a35702129633a1624622338a42bf5242e95630868bf2856d52eda8689c9cf99e8a41bce97d4d966521ba1cbeb31d464b5eb3738168c34131962058153665bbec1e346efe3a7b1b0ab76654af49c45fe175ed132dd6cc166ca5c35aca6ab0a6e38b1d20776899d1502c21caaed561c170e1b1233286137702c3e0c1075301a3f3d37652b34763b17277b313cbf37ef3b2891641363a73b42dc37ca9980d7df8ee2a21dc294c8d361461aa5d9fc3cd470ade8352b158e261d046416885e6f43b3cbf95bfbffaeb1a4a5727d5bee9152e80559da36c660d775cd5a3fada8bb0c7720a7c8057e9c9b180fde0fbbe65d1c0a041b083e22753079302016167f20093a2626662b34602016257f2038b337f4262f97680d72a22852ce31db8689c9c797e8a21ac596d4d1674701adddf627c168a9fc302f0797371e14790d8e566a54,
0xce1eb6ea5701050b01083f3f76206130220f14753b11273c33672c26633c13237c3938a03ef53b2c9e6a0873a33f4edd30da888dd1c991fab80ac595c9d66a4606a4cafa30da66b8f32723088028181e6300884d6a4eb0d6ee45ede6a5a1a5b07e654af49c41f20744d137d07ada78d15b34b3bbbc096d3db4d80f73879a1102db1da3ec4d1b001111022b287c347d303a1a0a752617363637673a22652e1034633f38b039f3273484671374b83458cf37ce8383c4c28cf7b51dc69fd3d665410da5ccf020dd69bff32d3f148c2902056f078c4a785fbad6e64af0e6b2b7b6ad736551fe9653e20d5ecd2dc67fc664d35623a1a7bc14633aaec9037486891d0ac40fabea5b0105011b132f246726642139171d7d3d0a213a37613d28713c1723643b3cbe36ee213a9a671166a03f5fd232c38e90c2ce82e3a41bce88d8c46c5c1fb4d9ec33da6fa8fd2d380f8f2b1002660f8c4c675ba0c3e346ece6b5a9b8b77f6e4cef984ee81758db27cc61db64d35622abbab1026e32b6d504689a9d1e0cd81faee54d120c06020329347e2b633b24110d74310a21313370262667290c31762430b633f32729936a187ead3545cf26df8790d6c086fbb501df92d8d674561aa1dffa39d46ea8f42c3e0a8a2c1319780b985d675fb4caef4be3e1a1a1a5ad786951f88054fa0a43ce2ac061d36dcc5534a7b0bd066326a3d50a699b80160dc41eacf75d010c0a1a01282572346130231d0d64251a313b30663e32793f1a2a743830b22ce83c2f9e781d75ae3458cf2fc09f90c9c791e7a500df98cfd2634700a9d6f83dc66eb8f72b3c0f8d20]  
ct = [long_to_bytes(x) for x in ct]

def xor(data, key):  
   out = []  
   for k in range(0, len(data), len(key)):  
       block = data[k : k + len(key)]  
       out.append(bytes([a ^ b for a, b in zip(block, key)]))  
   return b''.join(out)

def isupper(b):  
   return all(x in ascii_uppercase.encode() for x in b)

def try_decrypt(ct, key):  
   for i in range(0, len(ct), KLEN):  
       pt = xor(ct[i:i+len(key)], key)  
       print(str(i) + '-' + pt.decode(), end=' ')  
   print()

def try_kpos(ct, pos, key):  
   res = ''  
   for i in range(pos, len(ct), KLEN):  
       pt = xor(ct[i:i+len(key)], key)  
       #print(pt)  
       if not isupper(pt):  
           return False, None  
       res += pt.decode() + ' '  
   return True, res

def find_kpos():  
   for i in range(KLEN - len(key)):  
       res = [try_kpos(x, i, key) for x in ct]  
       if res[0][0] and res[1][0]:  
           print(i, res[0][1], res[1][1])

find_kpos()  
```

Output:  
```  
5 SEENOU SYOUOR HAVEDO ISMOTH INGONE  TAHUND NDREDP TABOUT GHEVER THINGS  
```

Now we try to figure out the next char  
```python  
def possible_chars(key, kpos):  
   ch = ct[0][kpos]  
   res = []  
   for c in ascii_uppercase:  
       res.append(ch ^ ord(c))  
   return res

def find_nextchar(key, kpos):  
   pchars = possible_chars(key, kpos + len(key))  
   print(pchars)  
   for c in pchars:  
       res = [try_kpos(x, kpos, key + bytes([c])) for x in ct]  
       if res[0][0] and res[1][0]:  
           print(chr(c), res[0][1], res[1][1])

find_nextchar(key, 5)  
```

Output:  
```  
[107, 104, 105, 110, 111, 108, 109, 98, 99, 96, 97, 102, 103, 100, 101, 122,
123, 120, 121, 126, 127, 124, 125, 114, 115, 112]  
n SEENOUD SYOUORJ HAVEDOM ISMOTHF INGONEL  TAHUNDQ NDREDPF TABOUTJ GHEVERZ
THINGSK  
l SEENOUF SYOUORH HAVEDOO ISMOTHD INGONEN  TAHUNDS NDREDPD TABOUTH GHEVERX
THINGSI  
m SEENOUG SYOUORI HAVEDON ISMOTHE INGONEO  TAHUNDR NDREDPE TABOUTI GHEVERY
THINGSH  
f SEENOUL SYOUORB HAVEDOE ISMOTHN INGONED  TAHUNDY NDREDPN TABOUTB GHEVERR
THINGSC  
g SEENOUM SYOUORC HAVEDOD ISMOTHO INGONEE  TAHUNDX NDREDPO TABOUTC GHEVERS
THINGSB  
r SEENOUX SYOUORV HAVEDOQ ISMOTHZ INGONEP  TAHUNDM NDREDPZ TABOUTV GHEVERF
THINGSW  
p SEENOUZ SYOUORT HAVEDOS ISMOTHX INGONER  TAHUNDO NDREDPX TABOUTT GHEVERD
THINGSU  
```

Continue and we recover the flag: `UDCTF{m3d1um_X0r_str3ng7h_f7w}`

Full script: [otp2_sol.py](https://github.com/CTF-STeam/ctf-
writeups/blob/master/2021/BlueHensCTF/OTP2/otp2_sol.py)

Original writeup (https://github.com/CTF-STeam/ctf-
writeups/tree/master/2021/BlueHensCTF#otp2-crypto---422-pts).