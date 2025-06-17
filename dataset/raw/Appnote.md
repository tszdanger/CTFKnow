# APPNOTE.txt - Google CTF 2022  
- **Source:** [GitHub](https://github.com/Ik0ri4n/google-ctf-22-write-ups/blob/main/appnotedottxt/writeup.md)  
- **Category:** misc  
- **Points:** 50pt  
- **Date:** Fri, 01 July 2022, 18:00 UTC - Sun, 03 July 2022, 18:00 UTC  
- **Attachments:** [dump.zip](https://github.com/Ik0ri4n/google-ctf-22-write-ups/blob/main/appnotedottxt/dump.zip)  
- **Write-Up author:** Dominik Waibel  
- **Description:**

> Every single archive manager unpacks this to a different file...

## Examining the archive

With regular extraction the challenge archive, dump.zip, contains a single
file, hello.txt, with the content:

> There's more to it than meets the eye...

Analyzing the archive with `strings` shows that the archive contains entries
for another text file, hi.txt, and for files with the names flag00 to flag18,
with 36 different versions each.  
**The flagXX file versions contain the letters a-z, {, C, T, F, 0, 1, 3, 7, }
and \_**.  
The file hi.txt however contains the text:

> Find the needle in the haystack...

Analyzing the file with `binwalk` confirms that the archive entries for all of
these files exist.  
However the zip format is obviously manipulated in such a way that they are
not extracted.

## Zip format

The documentation of the zip format is called
[APPNOTE.TXT](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT).  
According to it the regular structure of a zip file is:

- [local file header 1]  
- _[encryption header 1]_  
- [file data 1]  
- _[data descriptor 1]_  
- ...  
- [local file header n]  
- _[encryption header n]_  
- [file data n]  
- _[data descriptor n]_  
- _[archive decryption header]_  
- _[archive extra data record]_  
- [central directory header 1]  
- ...  
- [central directory header n]  
- _[zip64 end of central directory record]_  
- _[zip64 end of central directory locator]_  
- [end of central directory record]

The cursive parts are optional parts used for features like Zip64 or
encryption.

Analyzing dump.zip with a hex editor reveals that it uses the following
structure:

- [local file header 1]  
- [file data 1]  
- [central directory header 1]  
- ...  
- [local file header 686]  
- [file data 686]  
- [central directory header 686]  
- [end of central directory record 1]  
- ...  
- [end of central directory record 21]

While Local File Headers are usually not allowed in the Central Directory
Structure the archive is still valid because each Central Directory Entry
simply declares the rest of the file up to last End Of Central Directory
Record as its file comment.  
Thus only the first file, hello.txt, is extractable.  
**The remaining End Of Central Directory Records reference the correct Central
Directory Header for the remaining files** though using the offset to the
Central Directory Structure.  
It is possible (and relatively quick) to simply jump to all those positions
and read the flag characters from the File Data directly before that position.  
Since I already experimented with code manipulating zip archives while solving
the challenge I also provide a [script](https://github.com/Ik0ri4n/google-
ctf-22-write-ups/blob/main/appnotedottxt/solver.py) that copies all the
desired headers to a valid zip file and outputs **the flag
`CTF{p0s7m0d3rn_z1p}`**.

Original writeup (https://kitctf.de/writeups/appnote).