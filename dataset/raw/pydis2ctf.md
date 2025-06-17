Full [Writeup](https://github.com/DaBaddest/CTF-
Writeups/tree/master/Csisctf/pydis2ctf)  
# pydis2ctf

pydis2ctf was in the reversing catogory.

We get three files:  
1. C1cipher.txt  
2. C2cipher.txt  
3. encodedflag.txt

Both C1cipher.txt and C2cipher.txt were python disassembly and encodedflag.txt
contains the encoded flag.

For reversing python bytecode you will require
[this](https://docs.python.org/3/library/dis.html)

Reversing and reimplementing the first file was enough to solve the task

But I reverse engineered both the files which are present
[here](https://github.com/DaBaddest/CTF-
Writeups/blob/master/Csisctf/pydis2ctf/C1cipher.py) and
[here](https://github.com/DaBaddest/CTF-
Writeups/blob/master/Csisctf/pydis2ctf/C2cipher.py)

*I reverse engineered the [second file](https://github.com/DaBaddest/CTF-Writeups/blob/master/Csisctf/pydis2ctf/Reversed%20C2cipher.py) too but I reimplemented only the first one.*

My approach for reversing the first file:  
```  
 2           0 LOAD_CONST               1 ('')  
             2 STORE_FAST               1 (ret_text)     # ret_text = ''

 3           4 LOAD_GLOBAL              0 (list)  
             6 LOAD_FAST                0 (text)         ## list(text)  
             8 CALL_FUNCTION            1  
            10 GET_ITER  
       >>   12 FOR_ITER                42 (to 56)  
            14 STORE_FAST               2 (i)            # for i in list(text):

 4          16 LOAD_FAST                0 (text)  
            18 LOAD_METHOD              1 (count)  
            20 LOAD_FAST                2 (i)  
            22 CALL_METHOD              1  
            24 STORE_FAST               3 (counter)      # counter = count(i)

 5          26 LOAD_FAST                1 (ret_text)  
            28 LOAD_GLOBAL              2 (chr)  
            30 LOAD_CONST               2 (2)             
            32 LOAD_GLOBAL              3 (ord)  
            34 LOAD_FAST                2 (i)  
            36 CALL_FUNCTION            1                ## ord(i) * 2  
            38 BINARY_MULTIPLY  
            40 LOAD_GLOBAL              4 (len)  
            42 LOAD_FAST                0 (text)  
            44 CALL_FUNCTION            1                ## len(text)  
            46 BINARY_SUBTRACT                           ## (ord(i) * 2) - len(text)  
            48 CALL_FUNCTION            1                ## chr((ord(i) * 2) - len(text))  
            50 INPLACE_ADD  
            52 STORE_FAST               1 (ret_text)     # ret_text += chr((ord(i) * 2) - len(text))  
            54 JUMP_ABSOLUTE           12

 6     >>   56 LOAD_FAST                1 (ret_text)  
            58 RETURN_VALUE  
```  
Where # means it is still on the stack,  
And ## means that it was earlier on the stack and it is used now.

So the Original program is:  
```  
ret_text = ''

for i in text:  
 counter = text.count(i)  
 ret_text += chr((2 * ord(i)) - len(text))

```

We just need to reverse it.

The whole solution script is:  
```  
text = '¤Ä°¤ÆªÔ\x86$\xa04\x9cÌ`H\x9c¬>¼f\x9c¦@HH\xa0\x84¨\x9a\x9a¢vÐØ'  
ret_text = ''  
for i in list(text):  
 ret_text += chr((ord(i) + len(text))//2)  
print(ret_text)  
```

which gives us the flag:  
```  
csictf{T#a+_wA5_g0oD_d155aSe^^bLy}  
```