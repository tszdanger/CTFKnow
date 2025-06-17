# StudySim  
> We created a small program to help you keep track of your increasing
> workload.  
>  
> Connect to make use of our organizer at `nc pwn.hsctf.com 5007`.

> > Hint: You know, that stack looks awfully implemented. I wonder if you can
> get it to leak a little.

## Solution

### Outline  
1. The vulnerability is that we can change the `allocated_count` of worksheets to almost any value we want, which will write the pointer returned by `malloc` into `stack` anywhere we like.  
2. We leaked heap by writing `malloc`'s pointer into the `allocated_count` variable and then reading it out.  
3. We leaked libc by reading `stdout@GOT` next to the GOT.  
4. We gained arbitrary write by using the vulnerability to place the pointer `malloc` gave us directly onto the tcache freelist, which allows us to poison the freelist when tcache looks for the next freed chunk.  
5. We used arbitrary write to write a one_gadget to `__malloc_hook` to get shell.

### Vulnerability  
As always, we begin with a `checksec`.  
```  
$ checksec studysim  
[*] '/studysim'  
   Arch:     amd64-64-little  
   RELRO:    Full RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x3ff000)  
```  
As perhaps expected, there are a number of anti-stack protections, meaning
this might be a heap exploitation question. Worthy of note is the fact that
PIE is not enabled, so addresses in the program are fixed.

Reversing the binary is not very hard. Roughly, the vulnerability occurs
because there aren't any checks on the number of worksheets we can do, which
occurs in the `do_worksheets` function.  
```c  
void do_worksheets()  
{  
	puts("How many worksheets would you like to finish?");  
	unsigned long num_worksheets;  
	read_ulong(&num_worksheets);  
  
	allocated_count -= num_worksheets;  
	printf("You did %lu worksheets. Only %ld more to go!\n",num_worksheets,allocated_count);  
}  
```  
This allows us to make `allocated_count` almost any long-value we want. This
matters because `malloc` is regularly writing pointers into
`stack[allocated_count]` in the `new_worksheet` function.  
```c  
	char * book = (char *) malloc(length + 1);  
	if (book == NULL) {  
		exit(1);  
	}  
	puts("What's the content of your worksheet?");  
	read_str(book, length);  
	stack[allocated_count] = book;  
```  
Because PIE has been disabled and `stack` is a global variable, its location
is fixed. This means that we can write the heap pointer `malloc` gave us
anywhere in memory that we can get our hands on because
`stack[allocated_count]` can point roughly anywhere.

### Leaking the Heap  
The heap leak is somewhat clever. The program is quite conservative in what it
prints out, printing variables in very few locations. The `allocated_count` is
printed in the `do_worksheet` method, here.  
```c  
	allocated_count -= num_worksheets;  
	printf("You did %lu worksheets. Only %ld more to go!\n",num_worksheets,allocated_count);  
```  
Notice that because we can write `malloc`'s pointer anywhere in memory, we can
write `malloc`'s poitner into `allocated_count`; recall PIE means the location
of `allocated_count` is also fixed. Then reading out the value of
`allocated_count` from the `do_worksheet` method will leak this heap pointer.

### Exploiting the Vulnerability  
The key frustration in this challenge is that `free` is never called, which
means that no proper use-after-free bug can exist. So to get around this, we
simulate a `free` by just telling `malloc` that there's a freed chunk it
should give us. And of course, because we're using libc 2.29, we're going to
use the gloriously vulnerable tcache. So let's try to poison that freelist.

In order for tcache to give us a pointer, that pointer will need to be on its
freelist. Usually, this means that we have to free a chunk onto the freelist,
but as stated above, there is no `free` call. However, the vulnerability
allows us to write a heap address anywhere we can get our hands on, and thanks
to the heap leak, this includes the tcache freelist.

So we begin by setting `allocated_amount` so that `stack[allocated_amount]`
will be on the tcache freelist. Then, when we `malloc` a chunk, two things
happen. First, the call  
```c  
	stack[allocated_count] = worksheet_pointer;  
```  
will place the pointer we just allocated onto the tcache freelist. Second, we
write in some arbitrary pointer `0x7f00deadbeef` into our chunk. Now, the heap
looks something like the following.  
```  
tcache freelists : 00007fff31415900      0000000000000000 <-- pointer to heap
chunk  
                  ...  
00007fff31415800 : 0000000000000000      0000000000000101  
00007fff31415900 : 00007f00deadbeef      0000000000000000 <-- our heap chunk  
                  ...  
```  
As far as tcache is concerned, this looks like a perfectly valid linked list.
The next time we `malloc` a chunk of size `0x100`, `malloc` will check tcache
and find that `0x7fff31415900` is freed and ready to be returned. Then it
looks inside of the chunk for the pointer to the next freed chunk and finds
`0x7f00deadbeef` waiting for it. It writes this into tcache so that the heap
looks roughly like the following.  
```  
tcache freelists : 00007f00deadbeef      0000000000000000 <-- our pointer on
tcache  
                  ...  
00007fff31415800 : 0000000000000000      0000000000000101  
00007fff31415900 : 00007f00deadbeef      0000000000000000 <-- chunk returned
to program  
                  ...  
```  
Now, when we `malloc` one more time for a chunk of size `0x100`, `malloc` will
once again check the tcache freelist and find our pointer `0x7f00deadbeef`
waiting for it. Now we get to write to `0x7f00deadbeef`, which gives us
arbitrary write.

### Leaking Libc  
The libc leak we generated is quite interesting. A motivating idea is to again
use the fact PIE is disabled to read directly from the GOT. After all, even
full RELRO has to allow the program to read the GOT, and we not asking to
overwrite anything. However, the only way to read from an address is in the
`new_worksheet` method, here.  
```c  
	puts("What\'s the content of your worksheet?");  
	read_str(worksheet_pointer,worksheet_length);  
	stack[allocated_count] = book;  
	allocated_count++;  
	printf("You throw the worksheet '%s' on your stack of worksheets.\n", book);  
```  
This means that we need to get the contents of our worksheet next to the GOT
in order to leak its libc addresses. We can do this with the arbitrary write
we just described but only using it for a read. But there's a deeper problem:
the `read_str` method will write a null byte at the end of memory, which will
inevitably make RELRO mad.  
```c  
int read_str(char* str, unsigned int length) {  
	int c = 0;  
	char tmp;  
	while (c != length && read(0, &tmp, 1) > 0) {  
		if (tmp == '\n') break;  
		str[c++] = tmp;  
	}  
	str[length-1] = '\0'; // <-- *aggressive overwriting of GOT ensues*  
	return c;  
}  
```  
To fix this problem, it turns out that there's a writable area just after the
GOT which contains some libc poitners; we used `stdout@GOT`. Note that
overwriting this area will not create a weakness in the program, but that's
not what we're looking for. We escape with our libc pointer.

### Finishing Up  
With arbitrary write, the exploit is now routine. With our newfound libc
pointer, we chose to write a one_gadget to `__malloc_hook`, which made things
a bit annoying, but it was doable nonetheless. The constraints on the
one_gadget we used were the following.  
```  
$ one_gadget libc.so.6  
0xe2383 execve("/bin/sh", rcx, rdx)  
constraints:  
 [rcx] == NULL || rcx == NULL  
 [rdx] == NULL || rdx == NULL  
```  
Checking what the registers were before we executed `malloc`, we saw that
`rcx` was already set to `NULL`. To get `rdx` to `NULL` as well, we told the
program to `malloc` us a chunk of size `0`, which set the corresponding
register as the argument. With an exploitable one_gadget on `__malloc_hook`,
just calling `malloc` (here `malloc(0)`) with the `new_worksheet` method will
give us the shell and so give us the flag.

The full exploit, somewhat commented, can be found
[here](/StudySim/studyforce.py). The original `.c` file can be found
[here](/StudySim/studysim.c).

Original writeup
(https://github.com/AMACB/HSCTF-2020-writeups/blob/master/StudySim/StudySim.md).