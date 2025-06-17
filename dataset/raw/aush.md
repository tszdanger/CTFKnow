# aush  (pwn)  
Writeup by: [xlr8or](https://ctftime.org/team/235001)

As part of this challenge we get a binary and its source code (in c), that we
should exploit.  
The goal of this challenge is to successfully authenticate, since the binary
will open a shell by itself in that case.

However we have no knowledge of the username and password that is requested,
since they are read from `/dev/urandom`:  
```c  
int setup(char *passbuf, size_t passlen, char *userbuf, size_t userlen) {  
 int ret, fd;

 // TODO: change it to password/username file  
 if ((fd = open("/dev/urandom", O_RDONLY)) == -1)  
   return 1;  
 ret  = read(fd, passbuf, passlen) != passlen;  
 ret |= read(fd, userbuf, userlen) != userlen;  
 close(fd);  
 return ret;  
}  
```

Let's look at what kinds of data we can expect on the stack, as it will be
helpful moving on:  
```c  
#define LEN_USER 0x10  
#define LEN_PASS 0x20

char *args[3];  
char inpuser[LEN_USER+1] = { 0 };  
char inppass[LEN_PASS+1] = { 0 };  
char username[LEN_USER] = { 0 };  
char password[LEN_PASS] = { 0 };  
```

* `args` is going to be used to as an argument to pass to `execve`  
* `username` and `password` contain the randomized username and password  
* `inpuser` and `inppass` will receive the username and password that we input

Continuing on, the username is read, let's see how that looks like:  
```c  
 /* Check username */  
 write(STDOUT_FILENO, "Username: ", 10);  
 if (read(STDIN_FILENO, inpuser, 0x200) <= 0)  
   return 1;

 if (memcmp(username, inpuser, LEN_USER) != 0) {  
   args[0] = "/usr/games/cowsay";  
   args[1] = "Invalid username";  
   args[2] = NULL;  
   execve(args[0], args, envp);  
 }  
```

This is a clear case of a buffer overflow, since `inpuser` is only 17 bytes
large.  
At this point one may think that it is enough to write some `A`s, since that
will then fill the `username` and the `password` buffers that contain random
bytes now.  
However in order to work around buffer overflows and for optimization
purposes, the compiler usually reorders stack variables, and this is also the
case here.  
Analyzing this with either GDB, or loading the binary into Ghidra, we can
notice that the actual order of the buffers ends up being:  
```c  
char username[LEN_USER] = { 0 };  
char inpuser[LEN_USER+1] = { 0 };  
char password[LEN_PASS] = { 0 };  
char inppass[LEN_PASS+1] = { 0 };  
```

Thus the username check will fail, since we can' overwrite the randomly
generated `username`.  
However notice that we read quite a bit more data, than the buffers can hold,
`0x200`.  
Filling out the allowed number of characters allows us to overwrite many
things, by passing `0x1ff` we overwrite the maximum amount of bytes.

At this point we can inspect what happens to the argument of `execve`, after
all if we could overwrite `args[0]`, we could launch a shell already at this
point.  
Unfortunately we can't touch `args`, however if we look at `envp` we do manage
to overwrite data, that it points to with `0x414141...`.  
Since `envp` is an array of pointers to strings, whoever would try to read it
would segfault, since it would try to read a string at address `0x414141` when
parsing the first environment variable.

Now because we pass a corrupted `envp` array, `execve` would fail to execute,
meaning the control is transferred back to our binary.  
However the binary assumes that `execve` will always succeed, in which case it
would never return, since out binary would be replaced with `cowsay` in
memory.  
Because of this assumption, we can continue to the password check if we
corrupt `envp`, as discussed above.

```c  
 /* Check password */  
 write(STDOUT_FILENO, "Password: ", 10);  
 // FIXME: Reads more than buffer  
 if (read(STDIN_FILENO, inppass, 0x200) <= 0)  
   return 1;

 if (memcmp(password, inppass, LEN_PASS) != 0) {  
   args[0] = "/usr/games/cowsay";  
   args[1] = "Invalid password";  
   args[2] = NULL;  
   execve(args[0], args, envp);  
 }  
```

Since `inpuser` lies before `password` we are able to overwrite the randomly
generated password with any arbitrary bytes we want.  
Because of this the password check is bypassed, however `envp` is still in a
corrupted state from the previous buffer overflow.  
This is problematic, because after authenticating `execve` is used with `envp`
to spawn our shell:  
```c  
 /* Grant access */  
 args[0] = "/bin/sh";  
 args[1] = NULL;  
 execve(args[0], args, envp);  
```

Because of this, we need to undo our changes to `envp`, but we have no idea
what was there before we overwrote it.  
This is not an issue, because the `envp` array is NULL-terminated, i.e it
contains a `NULL` element, once there are no more environment strings.  
Therefore, since we don't care about the environment variables, we can just
use the buffer overflow on the `inppass` field, to first write 32 `A`s to
match the `password` buffer, then all `0x00` to NULL terminate the `envp`
array.

This way the password check passes, and `envp` becomes valid again, our shell
gets spawned.

`solve.py` automates the process of exploiting this challenge.  

Original writeup
(https://github.com/sbencoding/zer0pts_ctf_2023_writeups/tree/main/pwn/aush).