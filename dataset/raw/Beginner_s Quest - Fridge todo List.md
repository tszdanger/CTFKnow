This time we got both binary and the source code. Unfortunately PIE is
enabled, so we don't know where our binary will be in the memory.

First interesting function is authenticate(). In fact it doesn't perform any
authentication, it just sets the username.  
It's also not vulnerable to path traversals as they check if our username
contains only [A-Za-z]. open_todos() opens the file in `todos/[username]` and
we know that wintermuted uses this application to store his password, so maybe
we could just guess his username and read his todos?

In menu we can select 6 options: `print all`, `print`, `add`, `remove`,
`admin` and `quit`. This time admin function does nothing, so it's not our
goal to get there.  
On `quit` our todos are written to file. But store_todo() and print_todo()
seem vulnerable. They both contains the following code.  
```c  
int idx = read_int();  
if (idx > TODO_COUNT) {  
	puts(OUT_OF_BOUNDS_MESSAGE);  
	return;  
}  
```  
In C int is signed, but they only check if it is greater than TODO_COUNT and
don't check if it's less than 0. We can enter any negative number and
read/write the memory before our todos.  
Our todos are in .bss section and before them there is username variable and
the file descriptor. Unfortunately the file is opened only once at the
beginning of the program and we can't use it for path traversal.  
.data section does not seem to contain anything useful eiter, but before .data
we have .got.plt and it can be useful.  
TODO_LENGTH is 0x30, so we can specify address we want to read/write only with
this precision. With python we can print the closest addresses we can get.  
```  
>>> for i in range(10):  
...  print(hex(0x203140-0x30*i))  
0x203140  
0x203110  
0x2030e0  
0x2030b0  
0x203080 (open)  
0x203050 (strncat)  
0x203020 (write)  
0x202ff0  
0x202fc0  
0x202f90  
```  
According to [this website](https://systemoverlord.com/2017/03/19/got-and-plt-
for-pwning.html) we'll have either the function address or the address in .plt
if it hasn't been resolved yet.

So if the function was called we get some address in libc and in other case we
get address of .plt section in our binary.  
We don't have the libc used on server, so it may cause some problems to find
something there. open() and strncat() are both called before we can input
anything, but write function is called on exit.

With the address of write() we can calculate of .plt entry for system. We can
use it address to overwrite atoi address. (atoi is the best, because it is
used every time when we enter our choice in menu and it gets the string with
our input).

[exploit](https://github.com/BOAKGP/CTF-
Writeups/blob/master/Google%20CTF%202018%20Quals%20Beginners%20Quest/Fridge%20todo%20list/exploit.py)

When we get shell on the server we can list all files in /todos directory. The
wintermuted nickname is `CountZero`. We can just log in as him to get all his
notes.

Flag: `CTF{goo.gl/cjHknW}`

Original writeup (https://github.com/BOAKGP/CTF-
Writeups/tree/master/Google%20CTF%202018%20Quals%20Beginners%20Quest/Fridge%20todo%20list).