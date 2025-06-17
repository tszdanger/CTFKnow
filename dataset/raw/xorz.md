[中文](./README_zh.md) [English](./README.md)

# xorz

It is basically a transformed vigenere.

There is no original idea ,and all codes are my own.

## problem

```python  
from itertools import *  
from data import flag,plain

key=flag.strip("de1ctf{").strip("}")  
assert(len(key)<38)  
salt="WeAreDe1taTeam"  
ki=cycle(key)  
si=cycle(salt)  
cipher = ''.join([hex(ord(p) ^ ord(next(ki)) ^ ord(next(si)))[2:].zfill(2) for
p in plain])  
print cipher  
# output:  
#
49380d773440222d1b421b3060380c3f403c3844791b202651306721135b6229294a3c3222357e766b2f15561b35305e3c3b670e49382c295c6c170553577d3a2b791470406318315d753f03637f2b614a4f2e1c4f21027e227a4122757b446037786a7b0e37635024246d60136f7802543e4d36265c3e035a725c6322700d626b345d1d6464283a016f35714d434124281b607d315f66212d671428026a4f4f79657e34153f3467097e4e135f187a21767f02125b375563517a3742597b6c394e78742c4a725069606576777c314429264f6e330d7530453f22537f5e3034560d22146831456b1b72725f30676d0d5c71617d48753e26667e2f7a334c731c22630a242c7140457a42324629064441036c7e646208630e745531436b7c51743a36674c4f352a5575407b767a5c747176016c0676386e403a2b42356a727a04662b4446375f36265f3f124b724c6e346544706277641025063420016629225b43432428036f29341a2338627c47650b264c477c653a67043e6766152a485c7f33617264780656537e5468143f305f4537722352303c3d4379043d69797e6f3922527b24536e310d653d4c33696c635474637d0326516f745e610d773340306621105a7361654e3e392970687c2e335f3015677d4b3a724a4659767c2f5b7c16055a126820306c14315d6b59224a27311f747f336f4d5974321a22507b22705a226c6d446a37375761423a2b5c29247163046d7e47032244377508300751727126326f117f7a38670c2b23203d4f27046a5c5e1532601126292f577776606f0c6d0126474b2a73737a41316362146e581d7c1228717664091c  
```

## solve.py

```python  
#coding:utf8  
from itertools import cycle  
c="49380d773440222d1b421b3060380c3f403c3844791b202651306721135b6229294a3c3222357e766b2f15561b35305e3c3b670e49382c295c6c170553577d3a2b791470406318315d753f03637f2b614a4f2e1c4f21027e227a4122757b446037786a7b0e37635024246d60136f7802543e4d36265c3e035a725c6322700d626b345d1d6464283a016f35714d434124281b607d315f66212d671428026a4f4f79657e34153f3467097e4e135f187a21767f02125b375563517a3742597b6c394e78742c4a725069606576777c314429264f6e330d7530453f22537f5e3034560d22146831456b1b72725f30676d0d5c71617d48753e26667e2f7a334c731c22630a242c7140457a42324629064441036c7e646208630e745531436b7c51743a36674c4f352a5575407b767a5c747176016c0676386e403a2b42356a727a04662b4446375f36265f3f124b724c6e346544706277641025063420016629225b43432428036f29341a2338627c47650b264c477c653a67043e6766152a485c7f33617264780656537e5468143f305f4537722352303c3d4379043d69797e6f3922527b24536e310d653d4c33696c635474637d0326516f745e610d773340306621105a7361654e3e392970687c2e335f3015677d4b3a724a4659767c2f5b7c16055a126820306c14315d6b59224a27311f747f336f4d5974321a22507b22705a226c6d446a37375761423a2b5c29247163046d7e47032244377508300751727126326f117f7a38670c2b23203d4f27046a5c5e1532601126292f577776606f0c6d0126474b2a73737a41316362146e581d7c1228717664091c"

def getCipher(c):  
   codeintlist = []  
   codeintlist.extend(  
       (map(lambda i: int(c[i:i + 2], 16), range(0, len(c), 2))))  
   salt="WeAreDe1taTeam"  
   si=cycle(salt)  
   newcodeintlist = [ci ^ ord(next(si)) for ci in codeintlist]  
   return newcodeintlist

def getKeyPool(cipher, stepSet, plainSet, keySet):  
   ''' all inputs are like:  
           [0x11,0x22,0x33]  
       output is like:  
           {  
                   1:[[0x11]],  
                   3:[  
                       [0x11,0x33,0x46],  
                       [0x22,0x58],  
                       [0x33]  
                      ]  
               }  
   '''  
   keyPool = dict()  
   for step in stepSet:  
       maybe = [None] * step  
       for pos in xrange(step):  
           maybe[pos] = []  
           for k in keySet:  
               flag = 1  
               for c in cipher[pos::step]:  
                   if c ^ k not in plainSet:  
                       flag = 0  
               if flag:  
                   maybe[pos].append(k)  
       for posPool in maybe:  
           if len(posPool) == 0:  
               maybe = []  
               break  
       if len(maybe) != 0:  
           keyPool[step] = maybe  
   return keyPool

def calCorrelation(cpool):  
   '''input like:{'e':2,'p':3}  
       output: possibility ,which is between 0 and 1.  
       (correlation between the decrypted column letter frequencies and  
       the relative letter frequencies for normal English text)  
   '''  
   frequencies = {"e": 0.12702, "t": 0.09056, "a": 0.08167, "o": 0.07507, "i":
0.06966,  
                  "n": 0.06749, "s": 0.06327, "h": 0.06094, "r": 0.05987, "d": 0.04253,  
                  "l": 0.04025, "c": 0.02782, "u": 0.02758, "m": 0.02406, "w": 0.02360,  
                  "f": 0.02228, "g": 0.02015, "y": 0.01974, "p": 0.01929, "b": 0.01492,  
                  "v": 0.00978, "k": 0.00772, "j": 0.00153, "x": 0.00150, "q": 0.00095,  
                  "z": 0.00074}  
   relative = 0.0  
   total = 0  
   fpool = 'etaoinshrdlcumwfgypbvkjxqz'  
   total = sum(cpool.values())  # include all printable chars  
   for i in cpool.keys():  
       if i in fpool:  
           relative += frequencies[i] * cpool[i] / total  
   return relative

def analyseFrequency(cfreq):  
   key = []  
   for posFreq in cfreq:  
       mostRelative = 0  
       for keyChr in posFreq.keys():  
           r = calCorrelation(posFreq[keyChr])  
           if r > mostRelative:  
               mostRelative = r  
               keychar = keyChr  
       key.append(keychar)

   return key

def getFrequency(cipher, keyPoolList):  
   ''' input like: [1,2,3]  
       keyPoolList like:[[0x11,0x12],[0x22]]  
       output like:  
               [{  
                   0x11:{'a':2,'b':3},  
                   0x12:{'e':6}  
                },  
                {  
                   0x22:{'g':1}  
                }]  
   '''  
   freqList = []  
   keyLen = len(keyPoolList)  
   for i in xrange(keyLen):  
       posFreq = dict()  
       for k in keyPoolList[i]:  
           posFreq[k] = dict()  
           for c in cipher[i::keyLen]:  
               p = chr(k ^ c)  
               posFreq[k][p] = posFreq[k][p] + 1 if p in posFreq[k] else 1  
       freqList.append(posFreq)  
   return freqList

def vigenereDecrypt(cipher, key):  
   plain = ''  
   cur = 0  
   ll = len(key)  
   for c in cipher:  
       plain += chr(c ^ key[cur])  
       cur = (cur + 1) % ll  
   return plain

def main():  
   ps = []  
   ks = []  
   ss = []  
   ps.extend(xrange(32, 127))  
   ks.extend(xrange(0xff + 1))  
   ss.extend(xrange(38))  
   cipher = getCipher(c)

   keyPool = getKeyPool(cipher=cipher, stepSet=ss, plainSet=ps, keySet=ks)  
   for i in keyPool:  
       freq = getFrequency(cipher, keyPool[i])  
       key = analyseFrequency(freq)  
       plain = vigenereDecrypt(cipher, key)  
       print plain,"\n"  
       print ''.join(map(chr,key))

if __name__ == '__main__':  
   main()

# output: Wvlc0m3tOjo1nu55un1ojOt3q0cl3W   rectify output to get flag

# data.py content：  
# flag="de1ctf{W3lc0m3tOjo1nu55un1ojOt3m0cl3W}"  
# plain="In faith I do not love thee with mine eyes,For they in thee a
thousand errors note;But `tis my heart that loves what they despise,Who in
despite of view is pleased to dote.Nor are mine ears with thy tongue`s tune
delighted;Nor tender feeling to base touches prone,Nor taste, nor smell,
desire to be invitedTo any sensual feast with thee alone.But my five wits, nor
my five senses canDissuade one foolish heart from serving thee,Who leaves
unswayed the likeness of a man,Thy proud heart`s slave and vassal wretch to
be.Only my plague thus far I count my gain,That she that makes me sin awards
me pain."  
```

Original writeup (https://github.com/De1ta-
team/De1CTF2019/tree/master/writeup/crypto/Xorz).