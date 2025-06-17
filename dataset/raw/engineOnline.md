# engineOnline

Author: meh@HITCON  

### Description  
```  
we decide to make our engineTest online at 202.120.7.199:24680 (with command
"./engineTest none none none none")  
you can get the binary from the attachment of challenge engineTest

libc.so.6  
```  
I cannot understand what this program is doing until my teammates Lucas and
Lays solved the reverse part ... and still don't understand it clearly now.  
Briefly, this program writes memory according to **ip** and print memory
according to **op**, we didn't use cp so it is omitted.  
And I got the read/write functions from my teammate Lucas. :P  

### Exploit    
This program allows us to write everywhere **below** input memory, so we make
it big enough to be mapped above libc section.  
```  
       +------------------+  
       |      binary      |  
       |------------------|  
       |  // big gap //   |  
       |------------------|  
       |   input memory   |  
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
* Modify stderr with ip    
We modify the content of stderr and partial overwrite the vtable, make it
points to a fake vtable with gets_plt, so that we can use the libc address to
rewrite the stderr after we leak.  
* Leak with op    
After ip, we use op to leak libc address.  
* Exit and hijack control flow    
When exit, the _dl_fini will call _IO_flush_all_lockp, which will call
functions of stderr which is changed to gets.  
* Rewrite stderr    
We can rewrite the stderr with address we leaked, make the function pointer
points to system.  
* Get shell    
Finally, it will call system(stderr), and we make the stderr start with
'/bin/sh', so it will become system('/bin/sh').  

Original writeup
(https://github.com/mehQQ/public_writeup/tree/master/0ctf2017/engineOnline).