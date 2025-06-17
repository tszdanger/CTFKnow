# Not so Ez Reversing

It was a reversing challenge in the 0xL4ugh CTF.

In this chall we get a **rar** file **NotEzRE.rar** which has two files inside
it **data.dat & rev_challenge**

## Basic Recon  
On running file cmd on both the files gives:  
1. rev_challenge  
```  
rev_challenge; ELF 64-bit LSB shared object, x86-64, version 1 (SYSV),
dynamically linked (uses shared libs), for GNU/Linux 3.2.0, not stripped  
```  
So it is a 64 bit ELF binary

2. data.dat  
```  
data.dat; data  
```  
It says data because it doesnt recognize the file format.

On looking at its hexdump, we see something strange  
```  
D:\CTF\0xL4ugh\Not so Ez Reversing>hexdump -C data.dat | head  
00000000  ff d9 ff e0 00 10 4b 47  49 46 01 01 00 01 00 79  |ÿUÿà..KGIF.....y|  
00000010  01 79 01 01 ff e0 03 52  44 79 68 66 00 00 4d 4c  |.y..ÿà.RDyhf..ML|  
00000020  01 2b 00 00 00 09 00 04  51 00 00 04 01 00 01 00  |.+...
..Q.......|  
00000030  00 01 00 01 51 00 01 03  01 01 01 01 00 01 01 00  |....Q...........|  
00000040  50 02 01 01 00 00 02 00  01 00 01 4a 50 02 00 00  |P..........JP...|  
00000050  00 01 01 00 01 01 00 00  50 04 01 00 01 01 00 00  |........P.......|  
00000060  fd 01 01 00 00 01 01 01  00 00 00 01 00 32 01 01  |y............2..|  
00000070  66 01 01 99 00 00 cd 00  01 ff 00 2b 00 00 2b 33  |f.....I..ÿ.+..+3|  
00000080  00 2b 66 01 2b 99 01 2b  cd 00 2b fe 01 55 01 00  |.+f.+..+I.+_.U..|  
00000090  55 33 01 54 67 00 54 99  01 55 cd 00 54 ff 00 80  |U3.Tg.T..UI.Tÿ..|  
```

Now here experience comes into play, the start of the file looks like a jpg
file but not fully, maybe it is encrypted.

If we compare it with a valid jpg, we can see the similarites  
```  
00000000  ff d8 ff e0 00 10 4a 46  49 46 00 01 01 01 00 78  |ÿOÿà..JFIF.....x|  
00000010  00 78 00 00 ff e1 02 6c  45 78 69 66 00 00 4d 4d  |.x..ÿá.lExif..MM|  
00000020  00 2a 00 00 00 08 00 08  01 00 00 04 00 00 00 01  |.*..............|  
00000030  00 00 07 7a 01 01 00 04  00 00 00 01 00 00 08 4c  |...z...........L|  
00000040  01 0f 00 02 00 00 00 08  00 00 00 6e 01 10 00 02  |...........n....|  
00000050  00 00 00 0e 00 00 00 76  01 12 00 03 00 00 00 01  |.......v........|  
00000060  00 01 00 00 01 32 00 02  00 00 00 14 00 00 00 84  |.....2.........,|  
00000070  87 69 00 04 00 00 00 01  00 00 00 98 88 25 00 04  |╪i...........%..|  
```

## Analyzing the binary

I mostly prefer static analysis so I opened the file in **binaryninja** &
noticed that it's a **C++ binary.**

Now, because I am not very proficient in reversing C++ binaries so I opened
**Ghidra** instead to use its decompiler and make my life easier.

On main function we see the following line, which i *guess* opens the data.dat
file

```  
std::ofstream::basic_ofstream(v14, "data.dat", v3);  
```

Then it initializes the seed for PRNG, which will be predictable  
```  
srand(0);  
```

Then it creates an dynamic array  
```  
std::vector<int>::vector(rand_arr);  
```

Then theres a loop,cleaned up the code  
```  
for ( i = 0; i <= std::vector<unsigned char>::size(data_file) ; ++i )  
{  
 std::vector<int>::push_back(rand_array, rand() % 4;);  
}  
```  
this runs for data_file size times and generates a pseudo random number, does
a modulo by 4 so that the value can be from 0-3 inclusive and stores it into
the rand_array

Then after that is another loop which after cleanup is  
```  
for ( j = 0; j <= std::vector<unsigned char>::size(data_file); ++j )  
{  
 rand_val = *std::vector<int>::operator[](rand_arr, j);  
 data_val = *std::vector<unsigned char>::operator[](data_file, j);  
 v8 = std::vector<unsigned char>::operator[](data_file, j);  
 *v8 = mystery(data_val, rand_val);  
}  
```  
In this loop, it takes a byte from data_file and rand_arr and calls the
mystery function.  
The python equivalent of the code would be  
```  
for i, j in zip(rand_arr, data_file):  
 tmp = mystery(i,j)  
```

Lets move to the mystery function which little obfuscated, after cleaning it
up it is becomes super simple code  
```  
ulong mystery(uchar data_val,int rand_val)  
{  
 result = data_val;  
 if ( rand_val == 3 )  
   return data_val;  
 if ( rand_val == 2 )  
   // result = mystery(data_val, 0);  
   result = data_val ^ 1;  
 if ( rand_val == 1 )  
   result = data_val;  
 if ( rand_val == 0 )  
   result = data_val ^ 1;  
 return result;  
}  
```  
So all the code does is that it takes the previously generated random value
and according to it returns the value.  
1. If the rand_val is 1 or 3, then it does nothing and simply returns the original file value  
2. If the rand_val is 0 or 2, then it xors the byte with 1

And after that it writes the returned value in the data.dat file and stores
it.

So the solution is simple  
1. Generate the random values  
2. If the rand_val is 1 or 3, write the byte as it is  
3. If the rand_val is 0 or 2, xor the byte with 1  
4. Write the result into a new file

## Solution

1. First step is to write the program in C to generate the random numbers

The program is as below  
```  
#include <time.h>  
#include <stdio.h>  
#include <stdlib.h>  
int main(void){  
 srand(0);  
 for(int i=0; i<23469; ++i){ // size of file entered manually  
   printf("%i,", rand()%4);  
 }  
 return 0;  
}  
```  
And redirect the output of the file into a file called **values**

2. Now we have the random values, we just need to implement the logic, I will use a python script for it

```  
import subprocess, os  
rand_vals = [int(i) for i in open("rand_values").read().split(',')]  
fname = "Photo.jpg"

with open("data.dat", "rb") as f:  
 fp = f.read()  
os.system(f'del {fname}')

o = ''  
for i in range(len(fp)):  
 tmp = rand_vals[i]  
 if tmp == 0 or tmp == 2:  
   o += chr(fp[i] ^ 1)  
 else:  
   o += chr(fp[i])

with open(f"{fname}", 'wb') as f:  
 f.write(o.encode('charmap'))

```

After executing this file, we should get our flag file, but when I tried to
open the "Photo.jpg", it was still encrypted.

At this point I was totally stuck, because the script was fine, the
implemented logic was fine, but still I didnt get the flag.

Then after like 10 hours I got an idea.

Again running the file command on the binary we got  
```  
rev_challenge; ELF 64-bit LSB shared object, x86-64, version 1 (SYSV),
dynamically linked (uses shared libs), for GNU/Linux 3.2.0, not stripped  
```  
So the file is **Linux binary** and I was running the decrypt file on
**Windows**. So I ran the decryption script on Linux and it worked correctly
and I got the flag.

```  
flag: 0xL4ugh{th4t_w4z_not_so_eazzzy_but_you_did_it}  
```

But theoretically it should be the same on both Linux and Windows so what was
the problem.

After digging more, it turns out that the problem was in the C program which
generates the random numbers. It turns out that the ```rand()``` function
works different under Linux and Windows, and I was running the script on
Windows, so I was getting different random numbers

I posted both random values which are generated on
[Windows](https://github.com/DaBaddest/CTF-
Writeups/blob/master/0xL4ugh%202021/Not%20so%20Ez%20Reversing/values_win) and
[Linux](https://github.com/DaBaddest/CTF-
Writeups/blob/master/0xL4ugh%202021/Not%20so%20Ez%20Reversing/values_linux)
and we can clearly see the difference in random numbers.  

Original writeup (https://github.com/DaBaddest/CTF-
Writeups/tree/master/0xL4ugh%202021/Not%20so%20Ez%20Reversing).