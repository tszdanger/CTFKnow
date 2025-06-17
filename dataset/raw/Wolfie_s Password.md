# Wolfie's Password  
> Points: 424

## Description  
> We have found another device which is password protected but he uses same
> password everywhere find his password.  
  
Note: Use the same file provided in Wolfie's Contacts  
Flag Format: darkCTF{password}

## Solution  
I found a password protected RAR file in a directory.  
```bash  
⚡ root@ignite  ~/Documents/darkCTF/mountpoint/not important files  unrar e
readme.rar  

UNRAR 5.61 beta 1 freeware      Copyright (c) 1993-2018 Alexander Roshal  
Extracting from readme.rar

Enter password (will not be echoed) for readme:

The specified password is incorrect.  
```  
As the question suggests I need to find a password somewhere. Browsing through
the directory I got to se this  
```bash  
⚡ root@ignite ~/Documents/darkCTF/mountpoint/Program
Files/Windows/system32/config> ls -la  
total 47865  
drwxrwxrwx 1 root root     8192 Sep 21 01:31 .  
drwxrwxrwx 1 root root        0 Sep 21 01:31 ..  
-rwxrwxrwx 1 root root    65536 Jul 10  2015 BBI{c7a35797-26e2-11e5-80da-e41d2d741090}.TM.blf  
-rwxrwxrwx 1 root root   524288 Jul 10  2015 BBI{c7a35797-26e2-11e5-80da-e41d2d741090}.TMContainer00000000000000000001.regtrans-ms  
-rwxrwxrwx 1 root root   524288 Jul 10  2015 BBI{c7a35797-26e2-11e5-80da-e41d2d741090}.TMContainer00000000000000000002.regtrans-ms  
-rwxrwxrwx 1 root root    28672 Sep 20 14:25 BCD-Template  
-rwxrwxrwx 1 root root    28672 Jul 10  2015 BCD-Template.LOG  
-rwxrwxrwx 1 root root        0 Jul 10  2015 BCD-Template.LOG1  
-rwxrwxrwx 1 root root        0 Jul 10  2015 BCD-Template.LOG2  
-rwxrwxrwx 1 root root 33030144 Sep 20 13:26 COMPONENTS  
-rwxrwxrwx 1 root root  1048576 Sep 20 04:04 COMPONENTS{77a2c7f1-26f0-11e5-80da-e41d2d741090}.TxR.0.regtrans-ms  
-rwxrwxrwx 1 root root  1048576 Sep 20 04:04 COMPONENTS{77a2c7f1-26f0-11e5-80da-e41d2d741090}.TxR.1.regtrans-ms  
-rwxrwxrwx 1 root root  1048576 Sep 20 04:04 COMPONENTS{77a2c7f1-26f0-11e5-80da-e41d2d741090}.TxR.2.regtrans-ms  
-rwxrwxrwx 1 root root    65536 Sep 20 04:04 COMPONENTS{77a2c7f1-26f0-11e5-80da-e41d2d741090}.TxR.blf  
-rwxrwxrwx 1 root root    65536 Sep 20 04:39 COMPONENTS{77a2c7f2-26f0-11e5-80da-e41d2d741090}.TM.blf  
-rwxrwxrwx 1 root root   524288 Sep 20 04:39 COMPONENTS{77a2c7f2-26f0-11e5-80da-e41d2d741090}.TMContainer00000000000000000001.regtrans-ms  
-rwxrwxrwx 1 root root   524288 Sep 20 13:31 COMPONENTS{77a2c7f2-26f0-11e5-80da-e41d2d741090}.TMContainer00000000000000000002.regtrans-ms  
-rwxrwxrwx 1 root root     8192 Jul 10  2015 COMPONENTS.LOG1  
-rwxrwxrwx 1 root root   491520 Jul 10  2015 COMPONENTS.LOG2  
-rwxrwxrwx 1 root root    65536 Sep 20 13:32 DRIVERS{77a2c7f7-26f0-11e5-80da-e41d2d741090}.TM.blf  
-rwxrwxrwx 1 root root   524288 Sep 20 13:32 DRIVERS{77a2c7f7-26f0-11e5-80da-e41d2d741090}.TMContainer00000000000000000001.regtrans-ms  
-rwxrwxrwx 1 root root   524288 Sep 20 13:32 DRIVERS{77a2c7f7-26f0-11e5-80da-e41d2d741090}.TMContainer00000000000000000002.regtrans-ms  
-rwxrwxrwx 1 root root    32768 Jul 10  2015 ELAM  
-rwxrwxrwx 1 root root    20480 Jul 10  2015 ELAM.LOG1  
-rwxrwxrwx 1 root root        0 Jul 10  2015 ELAM.LOG2  
-rwxrwxrwx 1 root root      164 Jul 10  2015 FP  
drwxrwxrwx 1 root root        0 Jul 10  2015 Journal  
drwxrwxrwx 1 root root        0 Sep 20 13:26 RegBack  
-rwxrwxrwx 1 root root    36864 Sep 21 01:26 sam.hiv  
-rwxrwxrwx 1 root root  8769536 Sep 21 01:27 system.hiv  
drwxrwxrwx 1 root root        0 Sep 20 14:00 systemprofile  
drwxrwxrwx 1 root root     4096 Sep 20 14:00 TxR  
```  
In windows the user passwords are stored in
`/Windows/system32/config/sam.hiv`. So I used samdump2 to extract the password
hashes and used JTR to crack it.  
```bash  
⚡ root@ignite ~/Documents/darkCTF/mountpoint/Program
Files/Windows/system32/config> samdump2 system.hiv sam.hiv  
*disabled* Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
*disabled* :503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
wolfie:1001:aad3b435b51404eeaad3b435b51404ee:474a8dd8b26fbab954a5a30c7e0c722a:::  
⚡ root@ignite ~/Documents/darkCTF/mountpoint/Program
Files/Windows/system32/config> echo "474a8dd8b26fbab954a5a30c7e0c722a" >
/root/Documents/darkCTF/hash.txt  
⚡ root@ignite ~/Documents/darkCTF> john hash.txt --format=NT
--wordlist=/usr/share/wordlists/rockyou.txt  
Using default input encoding: UTF-8  
Loaded 1 password hash (NT [MD4 256/256 AVX2 8x3])  
Warning: no OpenMP support for this hash type, consider --fork=3  
Press 'q' or Ctrl-C to abort, almost any other key for status  
easypeasy        (?)  
1g 0:00:00:00 DONE (2020-09-28 14:25) 11.11g/s 2728Kp/s 2728Kc/s 2728KC/s
elisan..dulceamargo  
Use the "--show --format=NT" options to display all of the cracked passwords
reliably  
Session completed  
```  
Tested the password on the above archive and it works!!! We got our flag  
## Flag  
>darkCTF{easypeasy}  

Original writeup (https://github.com/t3rmin0x/CTF-
Writeups/tree/master/DarkCTF/Forensics/Wolfie's%20Password#wolfies-password).