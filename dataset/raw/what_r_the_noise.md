* Browser Try visit http://124.71.145.165:9999/, Can not open  
* So, Try nc, Success, return some mesage, a menu  
* Try In Python console:  
```  
>>>a=[101.675707, 108.104373, 99.44578, 119.753137, 103.825127, 123.795102,
113.940518, 112.825059, 119.928117, 100.072409, 110.66016, 112.893151,
119.509267, 120.783183, 99.383149, 118.112178, 118.08295, 98.985339,
101.026835, 97.877011, 101.01231, 93.011009, 111.948902, 115.130663, 116.7992,
92.919232, 101.367718, 103.783665, 100.882058, 99.945761, 95.911013,
114.825181, 98.854674, 110.959773, 116.05761, 112.636004, 95.454217,
108.25799, 96.539226, 108.040692, 113.843402, 105.545774, 123.853208,
96.72447, 97.942793, 124.169743, 124.625649]  
>>>[chr(int(round(i))) for i in a]  
['f', 'l', 'c', 'x', 'h', '|', 'r', 'q', 'x', 'd', 'o', 'q', 'x', 'y', 'c',
'v', 'v', 'c', 'e', 'b', 'e', ']', 'p', 's', 'u', ']', 'e', 'h', 'e', 'd',
'`', 's', 'c', 'o', 't', 'q', '_', 'l', 'a', 'l', 'r', 'j', '|', 'a', 'b',
'|', '}']  
```  
* what the "RANDOM" Noise, emmm:  
```  
from pwn import *

def readDat():  
 p.sendlineafter(":", "2", timeout=3)  
 ret = p.recvuntil("\n", timeout=1)  
 ret = ret.replace(",\n","")  
 return eval("["+ret+"]")

MAX_C=1000  
buf=readDat()  
L=len(buf)  
C=1  
for k in range(0,MAX_C):  
 a=readDat()  
 #print(a)  
 if len(a)!=L:  
   continue  
 C = C+1  
 for i in range(0,L):  
   buf[i] += a[i]

for i in range(0,L):  
 buf[i] = int(round(buf[i] / C))

buf_arr = [chr(i) for i in buf]  
#print("COUNT="+str(C))  
print("".join(buf_arr))

```

Original writeup (https://ctftime.org/task/12939/writeup/).