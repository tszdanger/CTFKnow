# File_size_matter_not

### Description  
Aye, aye captain! One of our rebel spaceships has retrieved a destroyed
satellite and was able to recover its hard drive.  
The Jedi researchers say that the data is scrambled in some parts. May the
force be with you as you try to decode it!

File given: hard_drive

Category: forensics. 495 points & 29 solves.

Author: bl4ckp4r4d1s3

## Solution

### Analysis  
We can first observe that the given file has no extension neither can it be
executed, so `binwalk` is the way to go. It is a Linux tool that can display
and extract embedded data from the given file. Using the command `binwalk -e`
gave the following output:

```  
$ binwalk -e hard_drive

DECIMAL       HEXADECIMAL     DESCRIPTION  
--------------------------------------------------------------------------------  
12781568      0xC30800        PEM RSA private key  
12783616      0xC31000        PEM RSA private key  
14620160      0xDF1600        PEM RSA private key  
14622208      0xDF1E00        PEM RSA private key  
14691328      0xE02C00        Zip archive data, at least v1.0 to extract,
name: .deleted_files/  
14691401      0xE02C49        Zip archive data, encrypted at least v2.0 to
extract, compressed size: 1345632, uncompressed size: 1352335, name:
.deleted_files/455  
16037125      0xF4B505        Zip archive data, encrypted at least v2.0 to
extract, compressed size: 1345939, uncompressed size: 1352335, name:
.deleted_files/12  
17383155      0x1093EF3       Zip archive data, encrypted at least v2.0 to
extract, compressed size: 1345848, uncompressed size: 1352335, name:
.deleted_files/212  
18729095      0x11DC887       Zip archive data, encrypted at least v2.0 to
extract, compressed size: 1345731, uncompressed size: 1352335, name:
.deleted_files/45  
20075352      0x1325358       End of Zip archive, footer length: 37, comment:
"baby_but_strong"  
```

Inside the extracted folder, we found an encrypted zip file containing folder
`.deleted_files` with 4 more hidden files. The zip password to extract those
files can be found in the binwalk analysis (or also metadata):
`baby_but_strong`.

### The 'sus' gif  
After all the extractions, there were these following 4 files, of which one
can be opened as a `gif`.

*cd to path ./_hard_drive.extracted/.deleted_files if you can't seem to find these files anywhere*

![four
files](https://github.com/PointerPioneers/CTFs/blob/main/Space%20Heroes%20CTF%202023/Write-
ups/forensics%20File_size_matter_not/_deleted_files.png?raw=true)

However, the gif is a little bit sus ඞ

More precisely, the stream of images ended too early, causing the gif to
appear discontinuous, or laggy. Combining this element with the hint from the
challenge description *the data is scrambled in some parts*, we can suspect
that some parts of the gif file were missing.

To further confirm this suspicion, we analyzed all 4 files in a hex editor and
saw that files `12`, `212`, and `455` don't have 'normal headers'. By that we
mean the typical file header signature(s) following with empty spaces as shown
in the comparison below:

![normal
header](https://github.com/PointerPioneers/CTFs/blob/main/Space%20Heroes%20CTF%202023/Write-
ups/forensics%20File_size_matter_not/normal_header.png?raw=true)  
![no
header](https://github.com/PointerPioneers/CTFs/blob/main/Space%20Heroes%20CTF%202023/Write-
ups/forensics%20File_size_matter_not/no_header.png?raw=true)

So, the next step would be to reassemble all the parts to get the complete gif
file.

### Concatenation

We concatenated the files by manually copying & pasting from one file to
another, which could have been done more efficiently by using `cat` command:
`cat file1 file2 > file3.gif`.

After getting the complete gif (`cat 45 12 212 455 > flag.gif`), we extracted
images of the gif to read all characters of the flag using `ffmpeg` tool:
`ffmpeg -i flag.gif out%d.png`.

![baby
yoda](https://github.com/PointerPioneers/CTFs/blob/main/Space%20Heroes%20CTF%202023/Write-
ups/forensics%20File_size_matter_not/flag.gif?raw=true)

Finally, we obtained the flag: `shctf{sm4LL_but_m1gh7y}`.

## Reflection

This was a relatively doable challenge. However, opening file `45` with Image
Viewer on Linux didn't clearly show that the gif file has some missing parts,
but rather just a normal gif. That delayed our progress significantly and we
only managed to confirm our suspicion after a team member opened the file with
a different application, which showed that the gif was indeed lagging.  

Original writeup
(https://github.com/PointerPioneers/CTFs/tree/main/Space%20Heroes%20CTF%202023/Write-
ups/forensics%20File_size_matter_not).