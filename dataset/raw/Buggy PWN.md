# CTFZone 2018 -- Buggy PWN  
> **Category**: PWN  
  
> **Description**:  
  
> A disgruntled employee has recently left our team. Unfortunately, he took a  
> flag with him. We've discovered that there is strange buggy service
> currently  
> in development on his server. Maybe you can get the flag from there.  
  
> nc pwn-02.v7frkwrfyhsjtbpfcppnu.ctfz.one 1337  
  
> **Attachment**: buggy\_pwn.py

# Writeup  
We are given the address to connect and the source code of the application  
running on the server, so you can test all your exploits and scripts on your  
machine, which you are going to do.

When you connect to the server, you are asked to enter N lines. If you try to  
do this, you will most certainly get an exception. So there is no use talking  
to the server without exploring its source code. Upon opening it you see that  
it's a virtual machine with a made-up architecutre. If you were me you would  
probably go right to its opcode handling and commands which start at line 345.  
It's a good idea to walk through all commands and put some debug information  
into them like this:  
```  
def __command_xor(self,amplifier):  
   inreg=amplifier&0xf  
   outreg=amplifier>>4  
   stderr.print("xor %s %s\n" % (self.reg_names[inreg],
self,reg_names[outreg]))  
   #first define reg_names similarly to dataregs  
```  
You can then enhance this debug information with values of registers and  
constants etc.

You will then connect to your server with those prints everywhere and  
understand that it expects a you to send a line of length 16 exactly. You will  
try to send a line and will encounter the same exception. Now it's time to
dive  
into operations of the memory of the machine

## Memory  
The comment at the beginning gives you a clue that it's a 2d memory plane,  
where taking a value requires not one address, but two coordinates, which is a  
really cool idea. Reading and writing in memory take two (4) arguments: 2d  
coordinates of start and direction in form of vector that is added to  
coordinates on each next cell read. Also each cell is a pair of two C bytes,  
and numbers are C dwords with the same way of marking the sign on number. So  
when the program invited you to write 16 cells, you were supposed to send 32  
bytes of text. Also as you saw when you explored command operations, the
string  
you send must consist of **only** printable ascii characters.

## Program logic  
All this knowledge is enough to understand that the program is the following:  
invite you to write an arbitrary amount of 32 byte strings to memory, each  
going below the previous, then it will invite you to write a string of
supplied  
length to stack, which is an obvious set-up to exploit the following ret  
command. Using this you can overwrite the return address on stack and jump  
right into the memory you just filled up with strings of length 16. You then  
turn your attention to the 0x40 syscall which will print you the flag when
some  
conditions are met: `eax = ('f'.ord, 'l'.ord), ebx = ('a'.ord, 'g'.ord)`.

Let's reiterate some constraints: you can only send printable strings, so the  
shellcode must be printable. The strings must be of length 32 bytes. Even
more,  
when eip goes beyond one string, the machine halts, so you need to find a way  
to redirect execution to another string or in another direction. Oh, and you  
are limited vertically by 59 strings, but that won't be a problem.

## Exploit  
First let's form a payload to jump to controlled memory. After carefully
calculating bytes you arrive at something like this:  
```  
payload = "a"*32 + "\x40" + chr(0x45)  
sock.send(payload + "\n")  
print sock.recv(100500)  
```  
Notice that we only overwrite the least significant bytes of return address,
as  
the other bytes are already there and are not printable.

The shellcode will be something like this: we load the required values into
eax  
and ebx xorred with some printable string so that we get another printable  
string. We then load the xor-string into ecx, xor ecx with eax and ebx, and  
call the flagcall. The values we take are, for example, the following:  
```  
xorchar = chr(0b1000000)  
xorord = ord(xorchar)  
eax_val = chr(ord("f")^xorord) + chr(ord("l")^xorord) + xorchar*6  
ebx_val = chr(ord("a")^xorord) + chr(ord("g")^xorord) + xorchar*6  
ecx_val = xorchar * 8  
```  
Sounds nice. After calculating bytes, though, you understand that this  
shellcode is exactly 36 bytes, which is 4 above the limit, so we need to find
a  
way to redirect the execution after all. We will achieve this with rotip
command, which we can use to redirect execution to read cells not left to
right, but top to bottom.

Notice, however, that the pwn is buggy: after using rotip in this way, it will  
still read the next command to the right, and only after that it will go in
the  
desired direction, so be careful with positioning your shellcode in memory.
You  
can find my example script [here](./send.py). You can also send all strings by
hand, as they are not many. Congratulations, you got the flag!  

Original writeup
(https://github.com/sibears/writeups/tree/master/CTFZone%202018/Buggy-PWN).