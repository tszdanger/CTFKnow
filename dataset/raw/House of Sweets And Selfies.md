[https://github.com/x64x6a/ctf-
writeups/tree/master/SpamAndFlags_2020/house_of_sweets_and_selfies](https://github.com/x64x6a/ctf-
writeups/tree/master/SpamAndFlags_2020/house_of_sweets_and_selfies)

---

# House of Sweets And Selfies

Description:  
```  
Welcome to the house of sweets and selfies. Come on in, there'll be heaps of
fun!  
(Well technically you can't come on in right now, but our Customer Service
Team is available online 24/7 to relay all your service requests.) Server: nc
35.242.184.54 1337  
```

---

I actually didn't have a working solution by the end of the competition.  I
only found that we could overwrite a tcache entry 2 hours prior to competition
end.

The solution that I ended up finishing utilized a 64-byte heap overflow from
when you modify a selfie.  It will prepend a PNG header to your given input
and overflow into the next region

This challenge required a bit of reading on jemalloc.  There are a number of
slides and talks on the topic from Blackhat/Infiltrate that I went through to
solve this challenge.  I also recommend using
[shadow](https://github.com/CENSUS/shadow) with gdb when debugging.

---

To utilize the overflow to overwrite tcache, we need to allocate 10 selfies of
size 0x1c00 to fill up the 0x1c00-sized runs so that when a new tcache 0x1c00
is allocated, it can be written to by modifying the 10th selfie.  To force a
new tcache entry to be created, we create our first cake of any size.  This
new tcache entry will be allocated at the first region within the last 0x1c00
run, which our overflow can write to.  With shadow `jeruns` command, you can
view this.

The tcache header we overflow looks seems to be defined as the `tcache_s`
structure below:  
```C  
typedef struct tcache_bin_s tcache_bin_t;

struct tcache_bin_s {  
   tcache_bin_stats_t tstats;  
   int     low_water;  /* Min # cached since last GC. */  
   unsigned    lg_fill_div;    /* Fill (ncached_max >> lg_fill_div). */  
   unsigned    ncached;    /* # of cached objects. */  
   /*  
    * To make use of adjacent cacheline prefetch, the items in the avail  
    * stack goes to higher address for newer allocations.  avail points  
    * just above the available space, which means that  
    * avail[-ncached, ... -1] are available items and the lowest item will  
    * be allocated first.  
    */  
   void        **avail;    /* Stack of available objects. */  
};

struct tcache_s {  
   ql_elm(tcache_t) link;      /* Used for aggregating stats. */  
   uint64_t    prof_accumbytes;/* Cleared after arena_prof_accum(). */  
   ticker_t    gc_ticker;  /* Drives incremental GC. */  
   szind_t     next_gc_bin;    /* Next bin to GC. */  
   tcache_bin_t    tbins[1];   /* Dynamically sized. */  
   /*  
    * The pointer stacks associated with tbins follow as a contiguous  
    * array.  During tcache initialization, the avail pointer in each  
    * element of tbins is initialized to point to the proper offset within  
    * this array.  
    */  
};  
```

Our 64-byte overflow allows us to overwrite every byte until the
`tbins[0]->avail` pointer.  The size of regions stored at `tbins[0]` are the
smallest size, 0x8.  So when a `malloc(8)` is ran, it will first query this
tcache bin, before diving deeper into allocation.  This is typically performed
by checking if `ncached` is greater than 0 and if it is not, it will subtract
`ncached` from `avail` and return the value stored there while decrementing
`ncached` afterwards.

The reverse is also true, in that when a 0x8 size region is free'd it will be
pushed onto the `tbins[0]->avail` stack.  The push is performed by
incrementing the `ncached` value and storing the free'd address at the address
`avail - (ncached*sizeof(ptr))`.

Once we can overflow a tcache header, we can modify the `ncached` value so
that it extends into a buffer that we control.  We can also modify the
`ncached` value to control what `malloc(0x8)` will return as well as control
where a `free()` on a 0x8 size region is placed.

For our solution, utilized this control over `ncached` to obtain a heap leak,
a libc leak, a stack leak, and then program control. All selfies mentioned
below are modern and all cakes mentioned below are classic unless otherwise
specified.

To obtain a heap leak, we allocate two cakes of size 0x8.  We then modified
`ncached` so that the next free'd address would overwrite the 1st cake's
contents.  So when we free'd the 2nd cake, it's address would be stored as the
contents of the 1st cake.  When you "baked" the cake, this gave us a heap
leak.

To obtain a libc leak, we adjusted `ncached` so that `avail - (ncached *
sizeof(ptr))` would point to the 1st cake.  We then modifed the 1st cake's
content to be the address of a heap location that contained a libc pointer
minus 1 (`address - 1`).  This is due to classic cakes having their first
offset being set to NULL and we do not want our leak to be overwritten.  We
then have the next `malloc(0x8)` return the libc location minus minus 8 (`addr
- 8`).  For our next allocation, we allocate a hipster cake instead so that
there is no NULL padded byte.  This allows us to overwrite the NULL byte in
the previous cake.  After overwritting the NULL byte, when we `bake` the
previous cake we recieve a libc leak.

To obtain a stack leak, we did the same method as for the libc leak, except
our libc pointer was the `environ` pointer in libc.  We allocated a classic
cake at `environ_addr - 1` and a hipster cake at `environ_addr - 8`.  Once we
filled up the hipster cake with non-NULL bytes, we could `bake` the classic
cake and obtain a stack leak.

To gain shell, we calculated the offset on the stack that the `do_sweets()`
function would return to in `main()`.  We overwrote that by allowing the next
`malloc(0x8)` call to return a stack pointer to that return address.  We then
allocated a cake to get a pointer to this stack location and wrote the address
of a one gadget (0x662C4) to get a shell.

Output of our solution running on the remote server:  
```  
Finished challenge  
Heap leak: 0x79a622b0f8  
Libc leak: 0x79a6818420  
Libc base: 0x79a6787000  
One gadget: 0x79a67ed2c4  
Environ leak: 0x7ffb3135e8  
[*] Switching to interactive mode

$ cat /data/local/tmp/flag  
SaF{I_th1nk_1Ts_7h3_3xp3cTA7I0nS_4nd_As5uMp7I0n5_0f_0tH3r5_7hAT_c4u5E_H3ar74ch3}  
```

Original writeup (https://github.com/x64x6a/ctf-
writeups/tree/master/SpamAndFlags_2020/house_of_sweets_and_selfies).