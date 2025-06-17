# The Legend of the Chozo

This challenge is perfect to analyze in depth the different components that
PNG files have and learn how to reassemble these components to reconstruct the
evidence and process it (read the flag).  
  
Challenge Description:  
```bash  
The Legend of the Chozo  
100  
Medium  
Samus extracted this file from the site on the last expedition, but it appears
to have been corrupted! This may be the lead we've been looking for to bring
peace to the galaxy. Can you Identify what it once was and possibly restore
it?

Author: delphi  
```

We were given a file to download ([source
here](https://github.com/leonuz/CTFs/raw/main/stuff/CorruptedData.chr))

  
```bash  
┌──(leonuz㉿sniper)-[~/SpaceHeroesCTF/Forensics/The_Legend_of_the_Chozo]  
└─$ ls -l  
total 64  
-rw-r--r-- 1 leonuz leonuz 61816 Feb  6 18:48 CorruptedData.chr  
```  
Start by analyzing this file whit the unix/linux command
[`file`](https://linux.die.net/man/1/file)

```bash  
┌──(leonuz㉿sniper)-[~/SpaceHeroesCTF/Forensics/The_Legend_of_the_Chozo]  
└─$ file CorruptedData.chr  
CorruptedData.chr: data  
```  
`file` won't recognize it, but inspecting the header we can see strings which
are common in PNG files.

```bash  
┌──(leonuz㉿sniper)-[~/SpaceHeroesCTF/Forensics/The_Legend_of_the_Chozo]  
└─$ hd CorruptedData.chr | head   
00000000  50 47 89 0a 4e 0d 0a 1a  0d 48 44 00 52 00 00 49  |PG..N....HD.R..I|  
00000010  00 00 00 f0 00 00 01 39  08 06 00 00 00 ae c5 ad  |.......9........|  
00000020  5a 00 00 00 01 73 52 47  42 00 ae ce 1c e9 00 00  |Z....sRGB.......|  
00000030  00 04 67 41 4d 41 00 00  b1 8f 0b fc 61 05 00 00  |..gAMA......a...|  
00000040  00 20 63 48 52 4d 00 00  7a 26 00 00 80 84 00 00  |. cHRM..z&......|  
00000050  fa 00 00 00 80 e8 00 00  75 30 00 00 ea 60 00 00  |........u0...`..|  
00000060  3a 98 00 00 17 70 9c ba  51 3c 00 00 00 09 70 48  |:....p..Q<....pH|  
00000070  59 73 00 00 24 e8 00 00  24 e8 01 82 63 05 1c 00  |Ys..$...$...c...|  
00000080  00 f0 e1 49 44 41 54 78  5e ec fd 01 b4 66 59 76  |...IDATx^....fYv|  
00000090  d7 87 dd b1 1e 52 31 2a  0d 4f f0 92 55 8a 0b 5c  |.....R1*.O..U..\|  

```

According to the [PNG
Specification](http://www.libpng.org/pub/png/spec/1.2/PNG-Structure.html#PNG-
file-signature), the structure of the header is always represented by eight
fixed bytes, and the remaining parts consist of three or more chunks of PNG
data in a specific order.

**PNG header:** `89 50 4E 47 0D 0A 1A 0A` + chunk + chunk + chunk...

so let's go ahead and fix that. But first we make a copy of the file and
change the file extension to .png

```bash  
┌──(leonuz㉿sniper)-[~/SpaceHeroesCTF/Forensics/The_Legend_of_the_Chozo]  
└─$ cp CorruptedData.chr image.png  
```  
we use [printf](https://man7.org/linux/man-pages/man3/printf.3.html) and
[dd](https://man7.org/linux/man-pages/man1/dd.1.html) to modify the file, but
it can be done with any hexadecimal editor such as hexeditor or xxd  
```bash  
┌──(leonuz㉿sniper)-[~/SpaceHeroesCTF/Forensics/The_Legend_of_the_Chozo]  
└─$ printf '\x89\x50\x4E\x47\x0D\x0A\x1A\x0A' | dd of=image.png bs=1 seek=0 count=8 conv=notrunc  
8+0 records in  
8+0 records out  
8 bytes copied, 0.000204744 s, 39.1 kB/s  
```  
review the header... we see something odd in the chunk section.

```bash  
┌──(leonuz㉿sniper)-[~/SpaceHeroesCTF/Forensics/The_Legend_of_the_Chozo]  
└─$ hd image.png| head  
00000000  89 50 4e 47 0d 0a 1a 0a  0d 48 44 00 52 00 00 49  |.PNG.....HD.R..I|  
00000010  00 00 00 f0 00 00 01 39  08 06 00 00 00 ae c5 ad  |.......9........|  
00000020  5a 00 00 00 01 73 52 47  42 00 ae ce 1c e9 00 00  |Z....sRGB.......|  
00000030  00 04 67 41 4d 41 00 00  b1 8f 0b fc 61 05 00 00  |..gAMA......a...|  
00000040  00 20 63 48 52 4d 00 00  7a 26 00 00 80 84 00 00  |. cHRM..z&......|  
00000050  fa 00 00 00 80 e8 00 00  75 30 00 00 ea 60 00 00  |........u0...`..|  
00000060  3a 98 00 00 17 70 9c ba  51 3c 00 00 00 09 70 48  |:....p..Q<....pH|  
00000070  59 73 00 00 24 e8 00 00  24 e8 01 82 63 05 1c 00  |Ys..$...$...c...|  
00000080  00 f0 e1 49 44 41 54 78  5e ec fd 01 b4 66 59 76  |...IDATx^....fYv|  
00000090  d7 87 dd b1 1e 52 31 2a  0d 4f f0 92 55 8a 0b 5c  |.....R1*.O..U..\|  
```  
check the file...

```bash  
┌──(leonuz㉿sniper)-[~/SpaceHeroesCTF/Forensics/The_Legend_of_the_Chozo]  
└─$ file CorruptedData.chr  
CorruptedData.chr: data  
```  
`file` won't recognize it yet, so we need continue fix it.

We know that after the header come a series of
[chunks](http://www.libpng.org/pub/png/spec/1.2/PNG-Chunks.html). PNG contains
two types of chunks: one called critical chunks that are the standard chunks,
another called ancillary chunks that are optional.  

Each chunk starts with 4 bytes for the length of the chunk, 4 bytes for the
type, then the chunk content itself (with the length declared earlier) and 4
bytes of a checksum. The first chunk is IHDR and has the length of 0xD, so
let's fix that first.

```bash  
┌──(leonuz㉿sniper)-[~/SpaceHeroesCTF/Forensics/The_Legend_of_the_Chozo]  
└─$ printf '\x00\x00\x00\x0D\x49\x48\x44\x52' | dd of=image.png bs=1 seek=8 count=8 conv=notrunc  
8+0 records in  
8+0 records out  
8 bytes copied, 7.9847e-05 s, 100 kB/s  
```  
check the header, everything seems to be fine now...

```bash  
┌──(leonuz㉿sniper)-[~/SpaceHeroesCTF/Forensics/The_Legend_of_the_Chozo]  
└─$ hd CorruptedData.chr | head                                                             
00000000  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |.PNG........IHDR|  
00000010  00 00 00 f0 00 00 01 39  08 06 00 00 00 ae c5 ad  |.......9........|  
00000020  5a 00 00 00 01 73 52 47  42 00 ae ce 1c e9 00 00  |Z....sRGB.......|  
00000030  00 04 67 41 4d 41 00 00  b1 8f 0b fc 61 05 00 00  |..gAMA......a...|  
00000040  00 20 63 48 52 4d 00 00  7a 26 00 00 80 84 00 00  |. cHRM..z&......|  
00000050  fa 00 00 00 80 e8 00 00  75 30 00 00 ea 60 00 00  |........u0...`..|  
00000060  3a 98 00 00 17 70 9c ba  51 3c 00 00 00 09 70 48  |:....p..Q<....pH|  
00000070  59 73 00 00 24 e8 00 00  24 e8 01 82 63 05 1c 00  |Ys..$...$...c...|  
00000080  00 f0 e1 49 44 41 54 78  5e ec fd 01 b4 66 59 76  |...IDATx^....fYv|  
00000090  d7 87 dd b1 1e 52 31 2a  0d 4f f0 92 55 8a 0b 5c  |.....R1*.O..U..\|

```  
check the file again...

```bash  
┌──(leonuz㉿sniper)-[~/SpaceHeroesCTF/Forensics/The_Legend_of_the_Chozo]  
└─$ file image.png  
image.png: PNG image data, 240 x 313, 8-bit/color RGBA, non-interlaced  
```  
`file` already recognizes it!!!  

Let's try another tool called
[`pngcheck`](http://www.libpng.org/pub/png/apps/pngcheck.html), this tool
verifies the integrity of PNG files by checking the internal checksums, and
decompressing the image data.

```bash  
┌──(sniper㉿sniperkal)-[~/SpaceHeroesCTF/Forensics/The_Legend_of_the_Chozo]  
└─$ pngcheck -v  image.png  
File: image.png (61816 bytes)  
 chunk IHDR at offset 0x0000c, length 13  
   240 x 313 image, 32-bit RGB+alpha, non-interlaced  
 chunk sRGB at offset 0x00025, length 1  
   rendering intent = perceptual  
 chunk gAMA at offset 0x00032, length 4: 0.45455  
 chunk cHRM at offset 0x00042, length 32  
   White x = 0.3127 y = 0.329,  Red x = 0.64 y = 0.33  
   Green x = 0.3 y = 0.6,  Blue x = 0.15 y = 0.06  
 chunk pHYs at offset 0x0006e, length 9: 9448x9448 pixels/meter (240 dpi)  
 chunk IDAT at offset 0x00083, length 61665  
   zlib: deflated, 32K window, fast compression  
 chunk IEND at offset 0x0f170, length 0  
No errors detected in image.png (7 chunks, 79.4% compression).  
```  
`pngcheck` has No errors detected!!!

We fix the file and now its posible to open it to get the flag.

flag shctf{CH0Z0_rU1N5}

- - -  

### Final Notes.

All incident response teams should know the necessary techniques for file
reconstruction as well, as at least, know this
[NIST](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-86.pdf)
recommendations.

thanks, [FITSEC Team](https://research.fit.edu/fitsec/) for the excellent CTF.

For fun and knowledge, always think out of the box! :)  

Original writeup (https://leonuz.github.io/blog/The-Legend-of-the-Chozo/).