This is what we're given:

```  
from Crypto.Util.number import *  
n=166045890368446099470756111654736772731460671003059151938763854196360081247044441029824134260263654537  
e=65537  
msg=bytes_to_long(b'UDCTF{REDACTED}')  
ct=pow(msg,e,n)  
print(n)  
print(e)  
print(ct)  
```

n seems suspiciously small compared to the Grade 1... if you look it up in
[factordb.com](http://), n's factors are already known!  
Therefore the problem is now trivial -- reuse code from grade 1 to decrypt

	UDCTF{pr1m3_f4ct0r_the1f!}

```  
n=166045890368446099470756111654736772731460671003059151938763854196360081247044441029824134260263654537  
e=65537  
c=141927379986409920845194703499941262988061316706433242289353776802375074525295688904215113445883589653  
p = 51700365364366863879483895851106199085813538441759

q = n // p  
phi = (p - 1) * (q - 1)  
d = pow(e, -1, phi)  
m = pow(c, d, n)  
m = format(m, 'x')  
for i in range(0, len(m), 2):  
   print(chr(int(m[i:i+2], 16)), end='')  
```