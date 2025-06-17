## Description

```  
Put two and two together and make pi.

nc 35.221.81.216 30718

Hint for beginners: Open the terminal app of Linux or Mac, and run the command
described above (Windows user can use WSL for this). If you successfully
connected, then put the random text into it and press the enter. ...You got an
error, right? Here, the attached Python script is running, indeed. You will
win if you can hack the script and make them output the content of flag.txt.
I'm praying for your good fortune :)  
```

The following server scripts are given:

```python  
from base64 import b64encode  
import math

exploit = input('? ')

if eval(b64encode(exploit.encode('UTF-8'))) == math.pi:  
 print("flag")

```

We have to encode UTF-8 characters as base64 and make.pi.
`math.pi=3.141592653589793`.

The base64 encoding result string consists of the following, so we can use
expressions such as `division` and `addition` only and `1e4 = 10000` in the
formula.  
`"ABCDEFGHIJKLMNOPQRSVWXYZabcdeghiklmnopqrstuvxyz0123456789+/"`

Among them, you can find the results encoded as follows: We can use this to
calculate `pi` from 0.1.

```  
b64encode("㝿㝴") -> "452/4520"  
b64encode("{M>") -> "e00+"  
b64encode("{M~") -> "e01+"  
...  
b64encode("{Mw") -> "e013"  
```

### solve.py

```python  
from pwn import *

conn = remote("35.221.81.216", 30718)

table = {  
   '0.1/' : "㝿㝴",  
   'e00+': '{M>',  
   'e01+': '{M~',  
   'e04+': '{N>',  
   'e05+': '{N~',  
   'e08+': '{O>',  
   'e09+': '{O~',  
   'e10+': '{]>',  
   'e11+': '{]~',  
   'e013': '{Mw',  
   'e14+': '{^>',  
   'e15+': '{^~',  
}

payload  = "0.1/e00+"*31  
payload += "0.1/e01+"*4  
payload += "0.1/e04+"*159  
payload += "0.1/e05+"*2  
payload += "0.1/e08+"*653  
payload += "0.1/e09+"*5  
payload += "0.1/e10+"*8  
payload += "0.1/e11+"*9  
payload += "0.1/e14+"*807  
payload += "0.1/e013"

data = ""  
for i in range(0, len(payload), 4):  
   data+=table[payload[i:i+4]]

conn.sendlineafter("? ", data)  
conn.interactive()  
```

Original writeup
(https://github.com/wotmd/CTF_Exploit/tree/master/TSGCTF_2020/beginner-misc).