# Izzy  
**category:** reverse  
**points:** 66  
**solves:** 77

## Description  
Izzy was writing a novel based on Mayan culture. Will Tom finish her book so
that she could rest in peace?

## Solution  
The two files we have are :  
command.sh:  
```bash  
#!/bin/bash  
export i=99; grep -o . <<< cat flag.txt| while read letter;  do i=$((i+1));
printf '%02x'  "$(($(python3 -c "import os;import decimal; import time;
decimal.getcontext().prec = 2992; index=int(os.environ.get('i')); x =
str(decimal.Decimal(1) / decimal.Decimal((1010 -
int(time.strftime('%m')))*1000 +1))[2:]; print(int(x[3*index:3*index+3]))") ^
$(printf '%#x\n' '"'$letter)))">>result.txt; done;  
```  
and result.txt:  
```  
2855140337590c3434040c5b411346492b3113430c11254a49220a17b3def0b3b0e1f2b7d7bdfdb8%  
```

command.sh execute the following python code :  
```python  
import os;  
import decimal;  
import time;  
decimal.getcontext().prec = 2992;

for index in range(100,140):  
  x = str(decimal.Decimal(1) / decimal.Decimal((1010 -
int(time.strftime('%m')))*1000 +1))[2:];  
  print(int(x[3*index:3*index+3]))  
```  
and xor it with the letter.  
I made a simple script to get the flag from result.txt:  
```python  
import os;  
import decimal;  
import time;

with open("result.txt","r") as f:  
  content = f.read()  
content = bytes.fromhex(content)

flag = ""  
decimal.getcontext().prec = 2992;  
for index in range(100,140):  
  x = str(decimal.Decimal(1) / decimal.Decimal((1010 -
int(time.strftime('%m')))*1000 +1))[2:];  
  flag += chr(int(x[3*index:3*index+3])^content[index-100])  
print(flag)
-----------  
```

when I run it :  
```  
$ python decode.py  
L0rd_0f_Xib41b4:_De4th_15_th3_r04dt0_4w3  
```

The flag is **ASIS{L0rd_0f_Xib41b4:_De4th_15_th3_r04dt0_4w3}**  

Original writeup (https://github.com/Red-Knights-
CTF/writeups/tree/master/2020/asis_ctf/Izzy).