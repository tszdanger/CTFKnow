# UploadCenter  

Author: meh@Hitcon  

### Description  
```  
There's an upload server here.  
Upload whatever you want.  
nc 202.120.7.216 12345

binary  
```  
The main functions:  
```  
1 :) Fill your information  
2 :) Upload and parse File  
3 :) Show File info  
4 :) Delete File  
5 :) Commit task  
6 :) Monitor File  
```  
We can use **upload** function to upload a PNG image which is compressed with
zlib, or delete it.  
**commit** will create a thread and show the info of uploaded files.  
**monitor** will create a thread a thread to notify when a PNG is uploaded.  
I directly took a PNG generator made by my teammate Jeffxx which was used in
codegate qual. ;)

### Vulnerability  
The upload function is something like this:  
```c  
//...  
readn(&size, 4);  
infstream.avail_in = size;  
infstream.next_in = g_inputBuffer;  
infstream.avail_out = g_BufferLength;  
infstream.next_out = g_outputBuffer;  
inflate(&infstream, 0);  
length = g_BufferLength - infstream.avail_out;  
//...  
img = mmap(0, width*height, 3, 34, -1, 0);  
pngobj = calloc(1, 0x30);  
pngobj->content = img;  
pngobj->length = length;  
//...  
```  
But the delete function does:  
```c  
munmap(pngobj->content, pngobj->length);  
```  
We can see that the size of mmap is **width*height** and munmap is **png
length**. Apparently the size of **mmap** and **munmap** is mismatched.  

### Exploit  
* mmap a png upon outputBuffer    
I realized what this challenge want immediately. Because **pthread** uses mmap
to prepare stack for threads, and we can use this uaf vul to overwrite the
return address of thread.  
mmap pages usually located  the tls section if the gap is big enough,
otherwise it will find other gap above which is available. But the gap upon
tls is not big enough for a thread stack (generally 0x800000 with a protect
page), if we put our png there it would be hard to exploit. As a result, we
first upload a pretty big PNG to make the mmap page upon outputBuffer (mmapped
when the program start, it is bigger than the gap above tls so is located upon
library pages). Make memory layout like:  

```  
       +------------------+  
       |      binary      |  
       |------------------|  
       |  // big gap //   |  
       |------------------|  
       |       png        |  
       |------------------|  <- g_outputBuffer  
       |                  |  
       |   outputBuffer   |  
       |------------------|  
       |       libs       |  
       |      & ld        |  
       |      & gaps      |  
       |      & tls       |  
       |------------------|  
       |       stack      |  
       |------------------|  
       |                  |  
       +------------------+  
```  
* munmap the png    
Then we can munmap the png with a larger size, so that part of output Buffer
will be unmapped too.  
```  
       +------------------+  
       |      binary      |  
       |------------------|  
       |  // big gap //   |  
       |                  |  
       |------------------|  <- g_outputBuffer  
       |#### unmapped ####|  
       |   outputBuffer   |  
       |------------------|  
       |       libs       |  
       |      & ld        |  
       |      & gaps      |  
       |      & tls       |  
       |------------------|  
       |       stack      |  
       |------------------|  
       |                  |  
       +------------------+  
```  
* Create a thread    
After that, we create a thread for monitor.  
```  
       +------------------+  
       |      binary      |  
       |------------------|  
       |  // big gap //   |  
       |------------------|  
       |   thread stack   |  
       |                  |  <- g_outputBuffer  
       |------------------|  
       |   outputBuffer   |  
       |------------------|  
       |       libs       |  
       |      & ld        |  
       |      & gaps      |  
       |      & tls       |  
       |------------------|  
       |       stack      |  
       |------------------|  
       |                  |  
       +------------------+  
```

* Upload PNG and overwrite return address to ROP    
Now the outputBuffer and the stack is partially **overlapped** (The pointer
points to somewhere inside the bottom of thread stack). So we can overwrite
return address by uploading a PNG, then do ROP to leak libc and stack
migration to ROP again.  

Something need to be noticed is that when two threads are both reading a same
fd, the input will be receive by one thread **not in order**. It only depends
on which thread is served at that time. (just my observation, not very sure)  
After observing remote server, we found that the main thread is always the
first, so we sent a newline before payload to solve this problem.  

Original writeup
(https://github.com/mehQQ/public_writeup/tree/master/0ctf2017/UploadCenter).