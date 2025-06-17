# CyberHeroines 2023

## Shannon Kent

> [Shannon Kent](https://en.wikipedia.org/wiki/Shannon_M._Kent): A specialist
> in cryptologic warfare and fluent in seven languages, Senior Chief Shannon
> Kent served multiple tours in Iraq, participating in numerous special
> operations that contributed to the capture of hundreds of enemy insurgents.
> She paved the way for greater inclusion of women in Special Operations
> Forces and was one of the first women to pass the Naval Special Warfare
> Direct Support Course. Kent was killed in action in Syria on Jan. 16, 2019,
> and posthumously promoted to senior chief petty officer. - [Navy.mil
> Reference](https://www.navy.mil/Women-In-the-Navy/Past/Display-Past-Woman-
> Bio/Article/2959760/senior-chief-shannon-kent/)  
>  
> Chal: Take the time to learn more about [Senior Chief Petty Officer Shannon
> Kent](https://www.youtube.com/watch?v=IlM-5FK0TL4) and unlock the
> cryptographic puzzle hosted at `0.cloud.chals.io 27572`  
>  
> Hint: Strongly recommended you build your solution in provided docker
> container.  
>  
>  Author: [TJ](https://www.tjoconnor.org/)  
>  
> [`distrib.tar.gz`](https://raw.githubusercontent.com/D13David/ctf-
> writeups/main/cyberheroines23/crypto/shannon_kent/distrib.tar.gz)

Tags: _crypto_

## Solution  
For this challenge we get a `Dockerfile` and a python script with only some
imports. The files are ment for local exploit development and the imports
really are a hint to find the solution.

When we connect to the service we get some information:  
```bash  
$ nc 0.cloud.chals.io 27572  
--------------------------------------------------------------------------------  
                         Flag Storage Safe v0.1337  
--------------------------------------------------------------------------------

                                  WWWWWWWWWW  
                             WNXK000000000000KXNW  
                          WNK0O0KKXNNWWWWNNXKK000KNW  
                        WX0O0XWW   WWWWWWWW   WWX0O0XW  
                      WXOOKNW WWXK0000000000KXW  WNKOOXW  
                     WKk0NW WNKOO0KXNWWWWNXK0OOKNW WN0kKW  
                    W0kKW  NKO0XW            WX0OKN  WKk0W  
                   WKkKW  NOOXW                WXOON  WKkKW  
                   NOON  W0kXW                  WXk0W  NOON  
                  WXk0W  Xk0W                    W0kX  W0kX  
                  WKkKW WKkKW                    WKkKW WKkKW  
                  WKkKW WKkKW                    WKkKW WKkKW  
                  WKkKW WKkKW                    WKkKW WKkKW  
                  WKkKW WKkKW                    WKkKW WKkKW  
                WNXOkKW WKkOKKKKKKKKKKKKKKKKKKKKKKOkKW WKkOXNW  
              WX0O00KN   NKKKKKKKKKKKKKKKKKKKKKKKKKKN   NK00O0XW  
             W0kKNW  WWWWWWNNNNNNWWWWWWWWWWWWNNNNNNWWWWWW  WNKk0W  
             Xk0W  NKOkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOKN  W0kX  
            WKkKWWNOddddddddddddddddddddddddddddddddddddddONWWKkKW  
            WKkKWWXkddddddddddddddddddddddddddddddddddddddkX WKkKW  
            WKkKW XkddddddddddddddxO000000OxddddddddddddddkX WKkKW  
            WKkKW Xkddddddddddddx0XW      WX0xddddddddddddkX WKkKW  
            WKkKWWXkdddddddddddxKW          WKxdddddddddddkXWWKkKW  
            WKkKW XkdddddddddddON            NOdddddddddddkXWWKkKW  
            WKkKW XkdddddddddddkX            XkdddddddddddkXWWKkKW  
            WKkKW XkdddddddddddxONW        WNOxdddddddddddkXWWKkKW  
            WKkKW XkdddddddddddddkKW      WKkdddddddddddddkXWWKkKW  
            WKkKW XkddddddddddddddkXW    WXkddddddddddddddkXWWKkKW  
            WKkKW XkddddddddddddddkXW    WXkddddddddddddddkXWWKkKW  
            WKkKW Xkddddddddddddddx0NW  WN0xddddddddddddddkXWWKkKW  
            WKkKW Xkdddddddddddddddxk0KK0kxdddddddddddddddkXWWKkKW  
            WKkKW XkddddddddddddddddddddddddddddddddddddddkXWWKkKW  
            WKkKW NOddddddddddddddddddddddddddddddddddddddONWWKkKW  
             Xk0WWWNKOkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOKNW W0kX  
             W0k0NWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW WWN0k0W  
              WX0O00KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK00O0XW  
                WNXKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKXNW

--------------------------------------------------------------------------------  
<<< Tying a Secure Knot Around the File  
<<< Started: 2023-09-10 09:57:51  
--------------------------------------------------------------------------------  
<<< XORing flag with random 6 byte key  
<<< GZIPing result (with gzip.compress with max compression)  
<<< XORing result with random 10 byte key  
<<< ZIPping result (with zipfile.ZipFile compression=ZIP_DEFLATED)  
<<< Flag is secure:
504b0304140000000800394f2a57106bae6a3e0000003900000008000000646174612e62696e013900c6ff1585e970e97250e4c1b30b2ce1ad09f3cd7746c4f60b81d758631996f8b69fbf0947a126140f2a5332f44fd542fed16938f78fda0952f6e1ad504b01021403140000000800394f2a57106bae6a3e00000039000000080000000000000000000000800100000000646174612e62696e504b0506000000000100010036000000640000000000  
```

The reciepe how the flag was *secured* is printed here also a starting time.
First I thought we had to retreive the correct seed to generate the same
random values for `xor`. But this was not the case, the length of the random
byte keys are also a hint. In both cases we know the exact amount of
information the reconstruct the keys.

For the first round we know the flag starts with the six chars `chctf{`. And
for the second round we have all the information the build the 10 byte [gzip
header](https://docs.fileformat.com/compression/gz/).

Let's get cracking, the first round is easy: convert the hex-string to bytes
and unzip the one file from this buffer:

```python  
#<<< ZIPping result (with zipfile.ZipFile compression=ZIP_DEFLATED)  
zip_buffer = bytes.fromhex(flag)  
with ZipFile(BytesIO(zip_buffer), 'r') as file:  
   print(file.namelist())  
   buffer1 = file.read("data.bin")  
```

For the second part we know it's a gzipped buffer. So it must start with a
gzip header which is 10 bytes long and exactly the length of our xor key
(perfect isn't it)?

```  
Offset  Size    Value       Description  
0       2       0x1f 0x8b   Magic number  
2       1                   Compression method  
3       1                   Flags  
4       4                   32 bit timestamp  
8       1                   Compression flags  
9       1                   Operating system ID  
```

From this we can retrieve the xor key and then retrieve the gzipped buffer.

```python  
#<<< XORing result with random 10 byte key  
t = datetime(2023, 9, 10, 9, 57, 51)  
ts = pack("

Original writeup (https://github.com/D13David/ctf-
writeups/blob/main/cyberheroines23/crypto/shannon_kent/README.md).