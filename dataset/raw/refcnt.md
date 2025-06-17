# refcnt

## TLDR  
* Use after free   
* Tcache poisoning  
* File structure oriented program

## Challenge  
### Description  
result of file command  
* Arch    : x86-64  
* Library : Dynamically linked  
* Symbol  : Not stripped

result of checksec  
* RELRO  : Full RELRO  
* Canary : Enable   
* NX     : Enable  
* PIE    : Enable 

libc version: 2.31

This challenge is a simple notepad.  
The maximum number of note entries is 5.  
In this challenge, there is 3 important functions to understand how to
exploit.  
* RC\_new()    
Call malloc() and add 8 to the return value.  
* RC\_get()    
Inclement the number of that note being used which is managed at the top of
the chunk.  
* RC\_put()    
Declement the number of that note being used, and call free() if the number
equals to 0.  

We can make 5 note entrys, and use the following commands.  

1. new    
Create a new note entry, whose size can be between 1 to 0xff.  
Call RC\_put() if the entry has already been used.  
And Call RC\_new().  
2. edit    
Edit the content of a note.  
3. copy    
With the given indexes of the notes, copy entry from one to another.  
If the entry of copy destination has been used, call RC\_put().  
After copying, call RC\_get().  
4. print    
Print the content of a note.  
5. delete    
Call RC\_put().

Let's see some examples.  
The chunk status after the commands of new with size 10 and edit with the
content "AAAABBBB" is as follows.

```  
0x555555757290: 0x0000000000000000      0x0000000000000021  
0x5555557572a0: 0x0000000000000001      0x4242424241414141  
0x5555557572b0: 0x0000000000000000      0x0000000000020d51  
```  
The number of that note being used is managed in the top of the chunk.  
Next, copy the entry 1 to 2.  
```  
0x555555757290: 0x0000000000000000      0x0000000000000021  
0x5555557572a0: 0x0000000000000002      0x4242424241414141  
0x5555557572b0: 0x0000000000000000      0x0000000000020d51  
```  
You can see the number is incremented.

### Exploit  
Copy command has a valunerability. You can trigger use after free when giving
same index to copy command.  
My exploit flow is as follows.

1. Leak the address of heap    
2. Make overlapped chunks(Tcache poisoning)    
3. Leak the address of libc    
4. AAW

#### Leak the address of heap  
As explained above, this binary has use after free vulnerability.  
For example, following my exploit code,  
```  
add(1, 0x10)  
copy(1, 1)  
show(1) # use after free, heap address leak  
```  
you can get the address of heap.  
And it will be used for FSOP later.

#### Make overlapped chunks(Tcache poisoning)  
The vesion of libc is 2.31, so it can detect tcache double free.  
To avoid the check, we have to overwrite tcache->key of freed chunk.  

Following my exploit code again,  
```  
add(1, 0x10)  
copy(1, 1)  
edit(1, p64(heap_base+0x100)) #overwrite tcache->key  
copy(1, 1) #tcache doulbe free, inclement tcache->next  
copy(1, 2) #inclement tcache->next  
```

The status of heap after these commands,

```  
0x555555757290: 0x0000000000000000      0x0000000000000021  
0x5555557572a0: 0x00005555557572a2      0x0000555555757010

tcache_perthread:

0x555555757000: 0x0000000000000000      0x0000000000000291  
0x555555757010: 0x0001000100000002      0x0000000000000001  
0x555555757020: 0x0000000000000000      0x0000000400000000  
0x555555757030: 0x0000000000000000      0x0000000000000000  
0x555555757040: 0x0000000000000000      0x0000000000000000  
0x555555757050: 0x0000000000000000      0x0000000000000000  
0x555555757060: 0x0000000000000000      0x0000000000000000  
0x555555757070: 0x0000000000000000      0x0000000000000000  
0x555555757080: 0x0000000000000000      0x0000000000000000  
0x555555757090: 0x00005555557572a0      0x0000000000000000  
```  
We can link the address of 0x00005555557572a2 to tcache which can be used to  
overwrite the size of next chunk.  
Once you can edit the size of chunk, you could easily make overlapped chunk,
couldn't you?  

#### Leak the address of libc  
You have been already able to use after free ,make overlapped chunk and edit
the size of chunk.  
So you can also leak the address of libc changing the size of chunk into a
large enough to link unsorted bin.

#### AAW  
If you can make overlapped chunks, you can overwrite the value of arbitary
address using tcache poisoning.  
In this challenge, we can only free chunks whose value at the top is 0, so we
can't  
call system("/bin/sh") overwriting \_free\_hook to system().  
So I use FSOP(File Structure Oriented Program).  
I overwrote \_IO\_list\_all to the address of fake FILE structure, a entry of
vtable to the address of system().  
In order to call \_IO\_overflow, we must make fake file structure under the
following conditions

* fp->_mode <= 0  
* fp->IO\_write\_ptr \> fp-\>IO\_write\_base

And return from main, get a shell.

My exploit code is
[solve.py](https://github.com/kam1tsur3/2020_CTF/blob/master/asis_final/pwn/refcnt/solve.py).

## Reference

twitter: @kam1tsur3  

Original writeup
(https://github.com/kam1tsur3/2020_CTF/blob/master/asis_final/pwn/refcnt/README.md).