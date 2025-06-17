##  Generic Flag Checker 2  
![date](https://img.shields.io/badge/date-11.01.2020-brightgreen.svg) ![web
category](https://img.shields.io/badge/Category-Reverse%20Engineering-
lightgrey.svg) ![score](https://img.shields.io/badge/score-150-blue.svg)

### Description  
```  
Flag Checker Industries™ is back with another new product, the Generic Flag
Checker® Version 2℠! This time, the flag has got some foolproof math magic
preventing pesky players from getting the flag so easily.  
```  
```  
HINT: When static analysis fails, maybe you should turn to something else...  
```

### Files  
- gfc2 (ELF File)

### Solution  
Alright now this challenge needs a different approach as to the preceding
challenge. When we try catting the file, we just see a lot of data, but no
flag. There is no use scouring through the data because you won't find the
flag there. If you see the hint, they are asking us to take a different
approach of reverse engineering. So if static analysis (analysis without
running the executable) doesn't work, then the opposite alternative would be
dynamic analysis (analysis while running the executable). There are 2 command
line tools called "ltrace" and "strace" that you should know.

**ltrace vs strace**

strace is a *system call and signal tracer*. It is primarily used to trace
system calls (function calls made from programs to the kernel)

ltrace is a *libary call tracer* and it is primarily used to trace calls made
by programs to library functions. It can also trace system calls and signals,
like strace.

For more info: https://blog.packagecloud.io/eng/2016/03/14/how-does-ltrace-
work/#:~:text=strace%20is%20a%20system%20call%20and%20signal%20tracer.&text=As%20described%20in%20our%20previous,calls%20and%20signals%2C%20like%20strace%20.

In this challenge, we will use "ltrace" but it's good to understand both
(there is also another tool called ptrace!).  
> How to install ltrace: sudo apt-get install ltrace

Here are the results after running and tracing the executable  
```  
> ltrace ./gfc2  
puts("what's the flag?"what's the flag?  
)                                                                        = 17  
fgets(flag  
"flag\n", 64, 0x7fad1600c980)
= 0x7ffc03648310  
fmemopen(0, 256, 0x555fb9e4c015, 59)
= 0x555fbaf83c00  
fprintf(0x555fbaf83c00, "%0*o24\n%n", 28, 026602427217, 0x7ffc036481f8)
= 31  
fseek(0x555fbaf83c00, 0, 0, 0)
= 0  
__isoc99_fscanf(0x555fbaf83c00, 0x555fb9e4c022, 0x7ffc036481fc, 0)
= 1  
fclose(0x555fbaf83c00)
= 0  
strncmp("flag", "nactf{s0m3t1m3s_dyn4m1c_4n4lys1s"..., 56)
= -8  
puts("nope, not this time!"nope, not this time!  
)                                                                    = 21  
+++ exited (status 1) +++  
```  
We found the flag! But part of it is still obscured. So after looking through
the man page of ltrace, I used the "-s" parameter to specify the maximum
string size to print.

```  
> ltrace -s 123 ./gfc2  
puts("what's the flag?"what's the flag?  
)                                                                        = 17  
fgets(flag?  
"flag?\n", 64, 0x7f6ff99d9980)
= 0x7ffd2392a490  
fmemopen(0, 256, 0x55f000a7b015, 58)
= 0x55f001be8c00  
fprintf(0x55f001be8c00, "%0*o24\n%n", 28, 026602427217, 0x7ffd2392a378)
= 31  
fseek(0x55f001be8c00, 0, 0, 0)
= 0  
__isoc99_fscanf(0x55f001be8c00, 0x55f000a7b022, 0x7ffd2392a37c, 0)
= 1  
fclose(0x55f001be8c00)
= 0  
strncmp("flag?", "nactf{s0m3t1m3s_dyn4m1c_4n4lys1s_w1n5_gKSz3g6RiFGkskXx}",
56)                 = -8  
puts("nope, not this time!"nope, not this time!  
)                                                                    = 21  
+++ exited (status 1) +++  
```  
Nice!

### Flag  
```  
nactf{s0m3t1m3s_dyn4m1c_4n4lys1s_w1n5_gKSz3g6RiFGkskXx}  
```

Original writeup (https://github.com/JoshuEo/CTFs/tree/master/NACTF_2020).