This time the flag is padded to a random length between 250 and 550 with
random chars (both leading and trailing).  
```php  
//For these 3 problems I'll only change these 2 lines:  
$flag = trim(file_get_contents("../../flag3.txt"));  
$key = pad_string($flag, mt_rand(250,550));  
```

Start with the same script as OTP2, we try to find the key length and position
of the flag.  
```python  
for klen in range(250, 550):  
   find_kpos(klen)  
```

Output:  
```  
354 245 LDBEAS  FICEAN  
355 245 LDBEAS  FICEAN  
356 245 LDBEAS  FICEAN  
...  
547 245 LDBEAS  FICEAN  
548 245 LDBEAS  FICEAN  
549 245 LDBEAS  FICEAN  
```

Looks like the key length doesn't matter, we really have an one time pad now.
Oh wait, the same key is used to encrypt 2 plaintexts, so two time pad
actually. We also got 1 important piece of information: flag position is 245.

Now continue using the same strategy as OTP2  
```python  
klen = 549  
kpos = 245  
find_nextchar(key, kpos, klen)  
```

Output:  
```  
[121, 122, 123, 124, 125, 126, 127, 112, 113, 114, 115, 116, 117, 118, 119,
104, 105, 106, 107, 108, 109, 110, 111, 96, 97, 98]  
y LDBEASA  FICEANJ  
z LDBEASB  FICEANI  
{ LDBEASC  FICEANH  
| LDBEASD  FICEANO  
} LDBEASE  FICEANN  
~ LDBEASF  FICEANM  
 LDBEASG  FICEANL  
p LDBEASH  FICEANC  
q LDBEASI  FICEANB  
r LDBEASJ  FICEANA  
t LDBEASL  FICEANG  
u LDBEASM  FICEANF  
v LDBEASN  FICEANE  
w LDBEASO  FICEAND  
i LDBEASQ  FICEANZ  
j LDBEASR  FICEANY  
k LDBEASS  FICEANX  
` LDBEASX  FICEANS  
a LDBEASY  FICEANR  
b LDBEASZ  FICEANQ  
```

With some trials and errors, eventually we recover the flag:
`UDCTF{wh3n_th3y_s4y_1_t1m3_th3y_mean_1t}`

Full script: [otp3_sol.py](https://github.com/CTF-STeam/ctf-
writeups/blob/master/2021/BlueHensCTF/OTP3/otp3_sol.py)

Original writeup (https://github.com/CTF-STeam/ctf-
writeups/tree/master/2021/BlueHensCTF#otp3-crypto---482-pts).