There are 3 files in challenge zip archive,  
```  
Archive:  chal.zip  
 Length      Date    Time    Name  
---------  ---------- -----   ----  
     256  2020-03-20 02:48   cipher.txt  
     193  2020-03-20 02:48   key.txt  
   21784  2020-03-20 02:48   main  
---------                     -------  
   22233                     3 files  
```

-  `main`, as the main binary  
-  `key.txt` and `cipher.txt`

At first glance the binary is rather confusing to look at, so I tried to use
blackbox approach first.  
To do that, patch the `system()` call that will remove `result.txt` and after
some light reversing we could know that input is 32 byte long (hint:
`sub_1366`).

```sh  
$ python -c "print('A' * 32)" | ./main  
... (snipped)  
$ hexdump -C result.txt  
00000000  da 0c 23 9b b5 f7 ef 03  da 0c 23 9b b5 f7 ef 03  |..#.......#.....|  
*  
00000020  
$ python -c "print('A' * 24 + 'B' * 8)" | ./main  
... (snipped)  
$ hexdump -C result.txt  
00000000  da 0c 23 9b b5 f7 ef 03  da 0c 23 9b b5 f7 ef 03  |..#.......#.....|  
00000010  da 0c 23 9b b5 f7 ef 03  65 8c af 5f 47 63 81 c4  |..#.....e.._Gc..|  
00000020  
$ python -c "print('A' * 24 + 'B' * 7 + 'C')" | ./main  
... (snipped)  
$ hexdump -C result.txt  
00000000  da 0c 23 9b b5 f7 ef 03  da 0c 23 9b b5 f7 ef 03  |..#.......#.....|  
00000010  da 0c 23 9b b5 f7 ef 03  5d 3e af ea ae 61 2a cf  |..#.....]>...a*.|  
00000020  
```

From the output we knew that the calculation done in a block of 8 byte. Well,
fair enough, maybe we could try to bruteforce this?

```  
$ python -c "print('A' * 24 + 'B' * 7 + 'C')" | time ./main  
...  
./main  0.01s user 0.00s system 10% cpu 0.065 total  
```

Acceptable enough(?), but I don't think this is a brute hash problem given
that it's an 8 byte block and there's `key.txt` file. At this point, I just
remembered that we have have `cipher.txt` and `key.txt`, so I try to identify
the enryption by known constants.

```  
$ wc -c key.txt  
193 # 192, -1 due to newline  
$ wc -c cipher.txt  
256  
```

Luckly, from `dword_208B60` there's a matching pattern from some website that
I've found mention about 3DES, (https://paginas.fe.up.pt/~ei10109/ca/des.html)  
```C  
int dword_208B60[56] = {57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26,
18,  
                       10, 2,  59, 51, 43, 35, 27, 19, 11, 3,  60, 52, 44, 36,  
                       63, 55, 47, 39, 31, 23, 15, 7,  62, 54, 46, 38, 30, 22,  
                       14, 6,  61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4};  
```

With 192 bits key and the challenge name is __"TRIPLE"__, this should be it.
The last step is just decrypt the `cipher.txt` with given `key.txt` using
3DES.MODE_ECB

Solver,  
```python  
#!/usr/bin/env python3  
from Crypto.Cipher import DES3  
from binascii import unhexlify

with open('key.txt') as f:  
   key = int(f.read()[:-1], 2) # trim new line  
   key = unhexlify(hex(key)[2:])

with open('cipher.txt') as f:  
   cipher = int(f.read(), 2)  
   cipher = unhexlify(hex(cipher)[2:])

des3 = DES3.new(key, DES3.MODE_ECB)  
print(repr(des3.decrypt(cipher)))  
```

Flag: `securinets{1_r34lly_do_b3l13v3_1n_y0u_rvrsr}`