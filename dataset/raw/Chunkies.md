# Chunkies

By [Siorde](https://github.com/Siorde)

## Description  
We could only retrieve only this file from the machine, but looks like this is
corrupted. Can you recover the file?

## Solution  
We got a file that should be a png. First i checked if it was right.  
```  
file file.png  
file.png: data  
```  
So something is wrong. I did an hexdump of the file and compared it with
another png file :  
```  
hexdump -C Sharfolder/file.png | head  
00000000  50 4e 47 0d 0a 1a 0a 00  00 00 0d 49 48 44 52 00  |PNG........IHDR.|  
00000010  00 02 00 00 00 01 34 08  06 00 00 00 5a 9b 8b dc  |......4.....Z...|  
00000020  00 00 20 00 49 41 44 54  78 5e ec 7d 07 94 1d c5  |.. .IADTx^.}....|  
00000030  95 f6 37 39 2b 27 84 24  44 90 10 20 b2 41 04 01  |..79+'.$D.. .A..|  
00000040  12 c1 24 63 1b 67 2f ce  61 9d d7 bb c6 61 1d 76  |..$c.g/.a....a.v|  
00000050  1d d6 bf 8d 31 b6 59 1b  7b 9d 23 b6 31 36 c1 e4  |....1.Y.{.#.16..|  
00000060  24 44 16 22 08 21 94 33  ca 28 8c c2 e4 f0 de fc  |$D.".!.3.(......|  
00000070  a7 42 f7 eb d7 d3 5d f7  56 77 bf 99 01 d5 9c 63  |.B....].Vw.....c|  
00000080  23 4d 57 57 dd fb dd 58  b7 6e b5 ca de 73 cd ba  |#MWW...X.n...s..|  
00000090  3e b8 1f 87 80 43 c0 21  e0 10 70 08 38 04 0e 2a  |>....C.!..p.8..*|  
```  
```  
hexdump -C chall.png | head  
00000000  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |.PNG........IHDR|  
00000010  00 00 01 08 00 00 00 bf  08 03 00 00 00 35 90 b2  |.............5..|  
00000020  b4 00 00 02 19 50 4c 54  45 ff ff ff 00 18 ff 49  |.....PLTE......I|  
00000030  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |.PNG........IHDR|  
00000040  00 00 04 b0 00 00 04 b0  08 06 00 00 00 eb 21 b3  |..............!.|  
00000050  cf 00 00 20 00 49 44 41  54 78 9c ec dd 79 90 a4  |... .IDATx...y..|  
00000060  77 79 d8 f1 5f 95 2c 4b  65 c5 32 32 84 68 b1 4c  |wy.._.,Ke.22.h.L|  
00000070  90 44 1c 12 c0 80 81 90  38 d8 c1 b1 02 21 c1 31  |.D......8....!.1|  
00000080  76 9c 0a 22 a4 b0 70 a9  62 0e 73 14 e2 b4 30 90  |v.."..p.b.s...0.|  
00000090  c3 50 36 f1 41 4c 5c b1  9d 14 04 23 83 01 05 e2  |.P6.AL\....#....|  
```  
It seems like it's missing an byte at the begining. I used https://hexed.it/
to edit the file and the "89" missing byte. Now the file is detected as a png,
but it doesn't display anything.  
```  
file file.png  
fix.png: PNG image data, 512 x 308, 8-bit/color RGBA, non-interlaced  
```  
Then I used the tool pngcheck to see what's wrong the the picture.  
```  
File: file.png (45357 bytes)  
 chunk IHDR at offset 0x0000c, length 13  
   512 x 308 image, 32-bit RGB+alpha, non-interlaced  
 CRC error in chunk IHDR (computed 5a7b8bdc, expected 5a9b8bdc)  
ERRORS DETECTED in file.png  
```  
I didn't know the compostion of a png file, so i did some research on the
error, and found this page that clarify the error for me :
https://hackmd.io/@FlsYpINbRKixPQQVbh98kw/Sk_lVRCBr  
I updated the value on the second line of the with the value expected and run
the command again (the picture would still not be display).  
```  
pngcheck -v file.png  
File: Sharfolder/file(3).png (45357 bytes)  
 chunk IHDR at offset 0x0000c, length 13  
   512 x 308 image, 32-bit RGB+alpha, non-interlaced  
 chunk IADT at offset 0x00025, length 8192:  illegal (unless recently
approved) unknown, public chunk  
ERRORS DETECTED in file.png  
```  
Their was another error. While looking for the previous error, I found that in
the composition of a png file, their was a IDAT chunk after IHDR that i alredy
updated. I spend more time that i would admit to find that that the message
error said IADT instead of IDAT. So I, again, updated the hex of the file.png
to change the value to IDAT.  
Then, same error, different line. The probleme was on the multiple occurence
of IIDAT in the file. I changed all of them.  
The last one was :  
```  
pngcheck -v Sharfolder/file\(6\).png  
File: Sharfolder/file(6).png (45357 bytes)  
 chunk IHDR at offset 0x0000c, length 13  
   512 x 308 image, 32-bit RGB+alpha, non-interlaced  
 chunk IDAT at offset 0x00025, length 8192  
   zlib: deflated, 32K window, fast compression  
 chunk IDAT at offset 0x02031, length 8192  
 chunk IDAT at offset 0x0403d, length 8192  
 chunk IDAT at offset 0x06049, length 8192  
 chunk IDAT at offset 0x08055, length 8192  
 chunk IDAT at offset 0x0a061, length 4280  
 chunk INED at offset 0x0b125, length 0:  illegal (unless recently approved)
unknown, public chunk  
ERRORS DETECTED in Sharfolder/file(6).png  
```  
But from now, i knew what type of error it was, so just change INED for IEND,
and here we go :  
```  
pngcheck -v Sharfolder/file\(7\).png  
File: Sharfolder/file(7).png (45357 bytes)  
 chunk IHDR at offset 0x0000c, length 13  
   512 x 308 image, 32-bit RGB+alpha, non-interlaced  
 chunk IDAT at offset 0x00025, length 8192  
   zlib: deflated, 32K window, fast compression  
 chunk IDAT at offset 0x02031, length 8192  
 chunk IDAT at offset 0x0403d, length 8192  
 chunk IDAT at offset 0x06049, length 8192  
 chunk IDAT at offset 0x08055, length 8192  
 chunk IDAT at offset 0x0a061, length 4280  
 chunk IEND at offset 0x0b125, length 0  
No errors detected in Sharfolder/file(7).png (8 chunks, 92.8% compression).  
```  
And there was the image with the flag : shaktictf{Y4YyyyY_y0u_g0t_1T}  

Original writeup (https://github.com/Nameshield-
CTF/WriteUps/tree/master/shakti-ctf-2021/forensics/chunkies).