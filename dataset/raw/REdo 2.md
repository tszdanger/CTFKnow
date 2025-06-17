REDo2 ended up being worth 152 points in the Reverse Engineering category in
TAMU CTF 2022!

![alt
text](https://github.com/Ale0x78/Ale0x78.github.io/raw/main/static/img/REdo2.png
"Challenge Description: Honestly, this is just a plain and simple ASM
challenge. Best of luck.")

## Step 1: I much rather read Pseudo-C

I can read assembly and have in the past when my disassemblers have lost track
of what is happening or if I am in gdb, but I’ve been spoiled by [Binary
Ninja](https://binary.ninja/) and [Ghidra](https://ghidra-sre.org/) so why not
just assemble the code ?

If you run  
```  
gcc -g -m32 -c redo2.s -o redo2  
```  
The assembler throws a bunch of error messages because the gnu assembler
[GAS]() expected At&t Syntax, so we switch it to intel by adding the
`.intel_syntax noprefix` line at the top of the file!

Compiling and running it through Binary Ninja, we get:  
```  
void* const var_4 = __return_addr  
int32_t* var_10 = &arg1  
int32_t eax_1  
if (arg1 != 2)  
   eax_1 = 1  
else  
   void* var_14_1 = nullptr  
   while (true)  
       if (var_14_1 s> 0x1c)  
           char* eax_7 = malloc(0x1d)  
           for (void* var_18_1 = nullptr; var_18_1 s<= 0x1c; var_18_1 = var_18_1 + 1)  
               *(eax_7 + var_18_1) = *(var_18_1 + *(arg2 + 4))  
               *(eax_7 + var_18_1) = *(eax_7 + var_18_1) - 0x31  
           if (*eax_7 != eax_7[2])  
               eax_1 = 1  
           else if (eax_7[1] != 0x38)  
               eax_1 = 1  
           else if (*eax_7 != 0x36)  
               eax_1 = 1  
           else if (eax_7[3] != 0x34)  
               eax_1 = 1  
           else if (sx.d(eax_7[0x1c]) != sx.d(eax_7[5]) + 2)  
               eax_1 = 1  
           else if (eax_7[5] != 0x4a)  
               eax_1 = 1  
           else if (eax_7[4] != 0x3c)  
               eax_1 = 1  
           else  
               int32_t var_1c_1 = 0  
               while (true)  
                   if (var_1c_1 s> 2)  
                       int32_t var_20_1 = 0  
                       while (true)  
                           if (var_20_1 s> 3)  
                               int32_t var_24_1 = 0  
                               while (true)  
                                   if (var_24_1 s> 4)  
                                       if (sx.d(eax_7[0x15]) != sx.d(eax_7[0xf]) + 1)  
                                           eax_1 = 1  
                                       else if (eax_7[9] != eax_7[0xe])  
                                           eax_1 = 1  
                                       else if (eax_7[9] != eax_7[0x14])  
                                           eax_1 = 1  
                                       else if (eax_7[9] != eax_7[0x16])  
                                           eax_1 = 1  
                                       else if (eax_7[9] != 0x2e)  
                                           eax_1 = 1  
                                       else if (eax_7[0x1b] != 1)  
                                           eax_1 = 1  
                                       else if (eax_7[0x1a] != 2)  
                                           eax_1 = 1  
                                       else if (eax_7[0x17] != 3)  
                                           eax_1 = 1  
                                       else if (eax_7[0x18] == 4)  
                                           eax_1 = sx.d(eax_7[0x19])  
                                       else  
                                           eax_1 = 1  
                                       break  
                                   if (eax_7[var_24_1 + 0xf] != 0x32)  
                                       eax_1 = 1  
                                       break  
                                   var_24_1 = var_24_1 + 1  
                               break  
                           if (eax_7[var_20_1 + 0xa] != 0x31)  
                               eax_1 = 1  
                               break  
                           var_20_1 = var_20_1 + 1  
                       break  
                   if (eax_7[var_1c_1 + 6] != 0x30)  
                       eax_1 = 1  
                       break  
                   var_1c_1 = var_1c_1 + 1  
           break  
       if (*(var_14_1 + *(arg2 + 4)) == 0)  
           eax_1 = 1  
           break  
       var_14_1 = var_14_1 + 1  
return eax_1  
```  
Let’s start with this for loop that gives 2 significant things away, the size
of our buffer is `0x1c`, and every character is shifted down by `0x31`. At the
time I had 0 clue what the `*(eax_7 + var_18_1) = *(var_18_1 + *(arg2 + 4))`
line is all about, but it didn’t seem to be relevant.  
  
```  
for (void* var_18_1 = nullptr; var_18_1 s<= 0x1c; var_18_1 = var_18_1 + 1)  
   *(eax_7 + var_18_1) = *(var_18_1 + *(arg2 + 4))  
   *(eax_7 + var_18_1) = *(eax_7 + var_18_1) - 0x31  
```  
Now, it’s clear that EAX_7 is our flag buffer, so I Command-F `!=` and
replaced it with `=` and then copied all of the conditions to a python file
and made the index being checked equal to the value being checked against.

```python  
flag = [0]*39

flag[0x1] = 0x38  
flag[0x0] = 0x36  
flag[0x3] = 0x34  
flag[0x5] = 0x4a  
flag[0x2] = flag[0]

flag[28] = flag[0x5] + 2  
flag[0x4] = 0x3c  
flag[0x15] = flag[0xf] + 1  
flag[9] = 0x2e  
flag[0xe] = flag[0x9]  
flag[0x14] = flag[0x9]  
flag[0x16] = flag[0x9]  
flag[0x1b] = 1  
flag[0x1a] = 2  
flag[0x17] = 3  
flag[0x18] = 4 # Tricky  
flag[0x19] = 0 # Tricky  
```  
`0x19` is tricky because it’s actually set as the return status, assuming the
return status is supposed to be 0 (pretty sure the assembler might have done
this). Also, I had to move the order of `0xe`, `0x14`, and `0x16` around after
`0x09` was defined.

Now the only thing is the while loops which are translated to python, look
like this:

```python  
for o in range(0, 3):  
  for k in range(0,4):  
    for j in range(0,5):  
      flag[j + 0xf] = 0x32  
    flag[k + 0xa] = 0x31  
  flag[o + 0x6] = 0x30  
```  
So all together along with our shift by `0x31`, the `solve.py` looks like
this:  
```  
flag = [0]*39

flag[0x1] = 0x38  
flag[0x0] = 0x36  
flag[0x3] = 0x34  
flag[0x5] = 0x4a  
flag[0x2] = flag[0]

flag[28] = flag[0x5] + 2  
flag[0x4] = 0x3c

for o in range(0, 3):  
  for k in range(0,4):  
    for j in range(0,5):  
      flag[j + 0xf] = 0x32  
    flag[k + 0xa] = 0x31  
  flag[o + 0x6] = 0x30  

flag[0x15] = flag[0xf] + 1  
flag[9] = 0x2e  
flag[0xe] = flag[0x9]  
flag[0x14] = flag[0x9]  
flag[0x16] = flag[0x9]  
flag[0x1b] = 1  
flag[0x1a] = 2  
flag[0x17] = 3  
flag[0x18] = 4 # Tricky  
flag[0x19] = 0 # Tricky

# Decode

for i in range(0, 39):  
 # flag[i] += i  
 flag[i] += 0x31

print(''.join(list(map(lambda x: chr(x), flag))))  
```  
After running the solver, it looks like the flag was shorter than the buffer,
but we can ignore the `1`’s in the end and submit the
`gigem{aaa_bbbb_ccccc_d_45132}`.  
```  
╭─alex at Howl in ⌁/Fold/TAMU22/redo2  
╰─λ python3 solve.py  
gigem{aaa_bbbb_ccccc_d_45132}1111111111  
╭─alex at Howl in ⌁/Fold/TAMU22/redo2  
╰─λ  
```  

Original writeup (https://ale0x78.github.io/2022/04/17/rEdo2.html).