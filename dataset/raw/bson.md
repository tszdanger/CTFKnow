# bson

Info:  
- Category: misc  
- Points: 331  
- Solved by: 4cul, 01baf, crypt3d4ta

## Problem

This is the last time i'm asking, who the f is bson??  
Attached (bson.json)

```  
{"task_name":"bson",
"message_pack_data":"82a36b65795ca4666c6167dc003137372f27362f6c3203352f033f6c6c30033e292803343d2a6f0325332903282e35393803316f2f2f1c3b39032c3d3f3721"}  
```

### Writeup

We are provided with a JSON file, inside which there are 2 fields:  
- task_name, containing "bson" string;  
- message_pack_data, containing a hexadecimal string.

With high odds, the flag is stored inside the message_pack_data field.  
By doing a rapid research (and by exploiting the hint left by the
"message_pack_data" name) it's clear that the field message_pack_data holds
into a message formatted in MessagePack - an efficient binary serialization
format.  
Using one of the many online MessagePack-JSON conversion tools we obtain:

```  
{  
"key" = 92,  
"flag" = [55,55,47,39,54,47,108,50,3,53,47,3,63,108,108,48,3,62,41,40,  
          3,52,61,42,111,3,37,51,41,3,40,46,53,57,56,3,49,111,47,47,  
          28,59,57,3,44,61,63,55,33]  
}  
```  
  
What we have is a key and a flag, that consists of decimal numbers. We notice
that in a flag's array elements begins with 2 identical number then we can
imagine an association between the characters of the **ASCII** code and the
flag.

So the aim is to obtain the ASCII of each element of the flag in function of
key and the same element.  
  
Doing a **XOR decimale** between the key and each flag's array element, we
obtain what we've looking for: the ASCII encoding of the character expressed
in decimal.

```  
#!/bin/env/python3

key = 92  
flag = [55,55,47,39,54,47,108,50,3,53,47,3,63,108,108,48,3,62,41,40,  
       3,52,61,42,111,3,37,51,41,3,40,46,53,57,56,3,49,111,47,47,  
       28,59,57,3,44,61,63,55,33]  
ascii_flag = []

for item in flag:  
   xor_result = key^item  
   ascii_flag.append(chr(xor_result))

for item in ascii_flag: print(item, end="")  
```  
  
### Flag:  
```  
kks{js0n_is_c00l_but_hav3_you_tried_m3ss@ge_pack}  
```  

Original writeup
(https://github.com/r00tstici/writeups/tree/master/kksCTF_2020/bson).