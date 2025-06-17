# Task  
"Hey, mickey ! - Give me your IP adress ! - I’ll send you what you’re looking
for. - Stay tuned on 5555 !"

# Step by step  
1. Use netcat and listen on 5555, we'll see incoming SSH connection each time we'll run   
> curl -d "IP=ext_ip_here" -X POST http://maninthemirror.challs.malice.fr  
2. Build [SSH](https://github.com/openssh/openssh-portable) with full debug options:   
* run "autoheader && authoconf && ./configure --with-pam"  
* add -DPACKET_DEBUG -DDEBUG_PK to CFLAGS in Makefile and run "make"  
3. Listen on 5555 - "/tmp/openssh-portable/sshd -p 5555 -D -ddd" we'll see failed auth attempt for user "mickey":  
`Failed publickey for mickey from 51.15.185.101 port 39892 ssh2: RSA
0f:2f:eb:55:58:fc:a2:a7:12:97:ac:ac:e9:4d:a8:d9`  
4. Also we'll get the public key:  
```  
buffer 0x7f1da0c3dee0 len = 277  
0000: 00 00 00 07 73 73 68 2d 72 73 61 00 00 00 81 01  ....ssh-rsa.....  
0016: 57 08 9e 22 1f 47 7b 64 7c ef f4 13 b5 bf 96 b8  W..".G{d|.......  
0032: b6 79 ce 16 19 c6 ba 08 7e e7 3a 6f 0f a9 5e 16  .y......~.:o..^.  
0048: f9 f1 d2 28 b4 a0 86 63 9a b8 0a d9 5b 40 ee 48  ...(...c....[@.H  
0064: 33 3d ce aa 57 ac f0 71 dd 01 c1 a1 ed b1 ff 55  3=..W..q.......U  
0080: 6d db 9c b2 ce 38 fd f4 4c 2d 99 47 9f 79 db 54  m....8..L-.G.y.T  
0096: f9 e4 49 a2 91 52 48 aa f9 51 a2 26 84 1c 71 f1  ..I..RH..Q.&..q.  
0112: 0a b1 90 29 11 1b 38 3c 49 16 a2 3a 72 aa 5f 29  ...)..8<I..:r._)  
0128: 02 0b cb 43 0e 36 53 d2 4e 7b 07 34 0f 4f ac f7  ...C.6S.N{.4.O..  
0144: 00 00 00 81 01 b5 fe 6c 8a 71 75 a2 42 15 d2 0c  .......l.qu.B...  
0160: 41 54 2d 4e d0 6a 66 ec d3 e9 24 4f e2 cb 72 e5  AT-N.jf...$O..r.  
0176: fb 07 4f 2c 6d cb f3 a0 6f 9a e4 e6 33 88 ce 90  ..O,m...o...3...  
0192: 6d 36 50 8e dc 3f 9e 11 07 c5 bb 74 c0 00 09 7b  m6P..?.....t...{  
0208: f8 62 e4 c5 80 31 14 cf 39 9a a0 e7 44 9a 4b 99  .b...1..9...D.K.  
0224: 4e 66 72 d2 1a 54 7e 0d 11 b3 ed bf f0 a0 5d d6  Nfr..T~.......].  
0240: 92 a7 6f d1 94 93 36 ae cb fa 8e 56 b7 37 1f 7e  ..o...6....V.7.~  
0256: 22 5d 02 61 e8 42 50 b5 80 a8 48 f0 ca ac 3b 41  "].a.BP...H...;A  
0272: 37 43 74 90 1d                                   7Ct..  
       Public-Key: (1025 bit)  
       Modulus:  
           01:b5:fe:6c:8a:71:75:a2:42:15:d2:0c:41:54:2d:  
           4e:d0:6a:66:ec:d3:e9:24:4f:e2:cb:72:e5:fb:07:  
           4f:2c:6d:cb:f3:a0:6f:9a:e4:e6:33:88:ce:90:6d:  
           36:50:8e:dc:3f:9e:11:07:c5:bb:74:c0:00:09:7b:  
           f8:62:e4:c5:80:31:14:cf:39:9a:a0:e7:44:9a:4b:  
           99:4e:66:72:d2:1a:54:7e:0d:11:b3:ed:bf:f0:a0:  
           5d:d6:92:a7:6f:d1:94:93:36:ae:cb:fa:8e:56:b7:  
           37:1f:7e:22:5d:02:61:e8:42:50:b5:80:a8:48:f0:  
           ca:ac:3b:41:37:43:74:90:1d  
       Exponent:  
           01:57:08:9e:22:1f:47:7b:64:7c:ef:f4:13:b5:bf:  
           96:b8:b6:79:ce:16:19:c6:ba:08:7e:e7:3a:6f:0f:  
           a9:5e:16:f9:f1:d2:28:b4:a0:86:63:9a:b8:0a:d9:  
           5b:40:ee:48:33:3d:ce:aa:57:ac:f0:71:dd:01:c1:  
           a1:ed:b1:ff:55:6d:db:9c:b2:ce:38:fd:f4:4c:2d:  
           99:47:9f:79:db:54:f9:e4:49:a2:91:52:48:aa:f9:  
           51:a2:26:84:1c:71:f1:0a:b1:90:29:11:1b:38:3c:  
           49:16:a2:3a:72:aa:5f:29:02:0b:cb:43:0e:36:53:  
           d2:4e:7b:07:34:0f:4f:ac:f7  
```  
5. Convert modulus from hex to integer:  
```  
$ python -c "print
int('01b5fe6c8a7175a24215d20c41542d4ed06a66ecd3e9244fe2cb72e5fb074f2c6dcbf3a06f9ae4e63388ce906d36508edc3f9e1107c5bb74c000097bf862e4c5803114cf399aa0e7449a4b994e6672d21a547e0d11b3edbff0a05dd692a76fd1949336aecbfa8e56b7371f7e225d0261e84250b580a848f0caac3b41374374901d',16)"

307569736692727958406180015451285106098697672696771741897905376504571347084893287546186220054803521872356396322144508204308478305419348133297314269936980693294246718472184233637693362473375660086646125438780893693972689222896486530878224760475060635867282011015672562082944975858657356059769426828212013666333  
```  
6. ... and exponent ...  
```  
$ python -c "print
int('0157089e221f477b647ceff413b5bf96b8b679ce1619c6ba087ee73a6f0fa95e16f9f1d228b4a086639ab80ad95b40ee48333dceaa57acf071dd01c1a1edb1ff556ddb9cb2ce38fdf44c2d99479f79db54f9e449a2915248aaf951a226841c71f10ab19029111b383c4916a23a72aa5f29020bcb430e3653d24e7b07340f4facf7',16)"

240886430024404135640467333611127514760949927514590637944267678894341944440168577922713169834240158297799927058946439888659186624932021080880071285473055719245355874319147612479546884440082642578796286122516314352185476050564419973211841627126490783685581931437179672786840348447575220837895652156680843537655  
```  
7. Build public key in PEM format with [RsaCtfTool ](https://github.com/Ganapati/RsaCtfTool):  
```  
$ ./RsaCtfTool.py --createpub --n
307569736692727958406180015451285106098697672696771741897905376504571347084893287546186220054803521872356396322144508204308478305419348133297314269936980693294246718472184233637693362473375660086646125438780893693972689222896486530878224760475060635867282011015672562082944975858657356059769426828212013666333
--e
240886430024404135640467333611127514760949927514590637944267678894341944440168577922713169834240158297799927058946439888659186624932021080880071285473055719245355874319147612479546884440082642578796286122516314352185476050564419973211841627126490783685581931437179672786840348447575220837895652156680843537655

-----BEGIN PUBLIC KEY-----  
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKBgQG1/myKcXWiQhXSDEFULU7Q  
ambs0+kkT+LLcuX7B08sbcvzoG+a5OYziM6QbTZQjtw/nhEHxbt0wAAJe/hi5MWA  
MRTPOZqg50SaS5lOZnLSGlR+DRGz7b/woF3Wkqdv0ZSTNq7L+o5WtzcffiJdAmHo  
QlC1gKhI8MqsO0E3Q3SQHQKBgQFXCJ4iH0d7ZHzv9BO1v5a4tnnOFhnGugh+5zpv  
D6leFvnx0ii0oIZjmrgK2VtA7kgzPc6qV6zwcd0BwaHtsf9Vbducss44/fRMLZlH  
n3nbVPnkSaKRUkiq+VGiJoQccfEKsZApERs4PEkWojpyql8pAgvLQw42U9JOewc0  
D0+s9w==  
-----END PUBLIC KEY-----  
```  
8. Convert to PKCS8 for OpenSSH:  
```  
$ ssh-keygen -f pub.key -i -m PKCS8

ssh-rsa
AAAAB3NzaC1yc2EAAACBAVcIniIfR3tkfO/0E7W/lri2ec4WGca6CH7nOm8PqV4W+fHSKLSghmOauArZW0DuSDM9zqpXrPBx3QHBoe2x/1Vt25yyzjj99EwtmUefedtU+eRJopFSSKr5UaImhBxx8QqxkCkRGzg8SRaiOnKqXykCC8tDDjZT0k57BzQPT6z3AAAAgQG1/myKcXWiQhXSDEFULU7Qambs0+kkT+LLcuX7B08sbcvzoG+a5OYziM6QbTZQjtw/nhEHxbt0wAAJe/hi5MWAMRTPOZqg50SaS5lOZnLSGlR+DRGz7b/woF3Wkqdv0ZSTNq7L+o5WtzcffiJdAmHoQlC1gKhI8MqsO0E3Q3SQHQ==  
```  
9. Add the public key and after restart OpenSSH we see succesful incoming connection:  
```  
$ ssh-keygen -f pub.key -i -m PKCS8 > authorized_keys  
Accepted publickey for mickey from 51.15.185.101 port 58048 ssh2: RSA
0f:2f:eb:55:58:fc:a2:a7:12:97:ac:ac:e9:4d:a8:d9  
```  
10. First halt of flag can be found at mickey home:  
```  
$ cat /home/mickey/flag_1.txt  
NDH{a_WInN3r_15_A_Dr3AMeR  
```  
11. Recover private key:  
```  
$ ./RsaCtfTool.py --publickey pub.key --private  
-----BEGIN RSA PRIVATE KEY-----  
MIICOgIBAAKBgQG1/myKcXWiQhXSDEFULU7Qambs0+kkT+LLcuX7B08sbcvzoG+a  
5OYziM6QbTZQjtw/nhEHxbt0wAAJe/hi5MWAMRTPOZqg50SaS5lOZnLSGlR+DRGz  
7b/woF3Wkqdv0ZSTNq7L+o5WtzcffiJdAmHoQlC1gKhI8MqsO0E3Q3SQHQKBgQFX  
CJ4iH0d7ZHzv9BO1v5a4tnnOFhnGugh+5zpvD6leFvnx0ii0oIZjmrgK2VtA7kgz  
Pc6qV6zwcd0BwaHtsf9Vbducss44/fRMLZlHn3nbVPnkSaKRUkiq+VGiJoQccfEK  
sZApERs4PEkWojpyql8pAgvLQw42U9JOewc0D0+s9wIgGRbivJwJdSlS8x7NB4J4  
xbhJWKhljWHJMWnga0qoIMcCQQEZIJceQq+jIJJ8YsxEvjwWVOtkPt8yVmNt2uNN  
+OA8t/mj13mnCI0PXSlHhGOiGzHyF/wvwsbWNyZTvdxbX9ohAkEBjtiBZmqmDb0B  
UXcnBU9fmMeSARSzTvpcYlFXMy/ZQpFFOWchEOZtxjT6Nza8nkG7ePNX6MaGVE6Y  
xoZdVRFOfQIgGRbivJwJdSlS8x7NB4J4xbhJWKhljWHJMWnga0qoIMcCIBkW4ryc  
CXUpUvMezQeCeMW4SVioZY1hyTFp4GtKqCDHAkEAvxQ93dEo5hEGiTZ1IVXR+TmL  
VgyFOnIZnCWfXAhz6UQkk0MJ+yCUICzqQZcmpUmlNMumA36w75lZmcexL22zeA==  
-----END RSA PRIVATE KEY-----  
```  
12. Get the second part of the flag:  
```  
$ ssh -i priv.key [email protected] -p 2222  
Linux bf7749b143b5 4.9.0-3-amd64 #1 SMP Debian 4.9.30-2+deb9u5 (2017-09-19)
x86_64

The programs included with the Debian GNU/Linux system are free software;  
the exact distribution terms for each program are described in the  
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent  
permitted by applicable law.  
Last login: Sat Mar 31 20:56:17 2018 from 192.168.32.3  
mickey@bf7749b143b5:~$ ls -la  
total 28  
drwxr-xr-x 1 root mickey 4096 Mar 27 15:03 .  
drwxr-xr-x 1 root root   4096 Mar 27 15:03 ..  
-rw-r--r-- 1 root mickey  220 May 15  2017 .bash_logout  
-rw-r--r-- 1 root mickey 3526 May 15  2017 .bashrc  
-rw-r--r-- 1 root mickey  675 May 15  2017 .profile  
drwxr-x--- 1 root mickey 4096 Mar 27 15:03 .ssh  
-rw-r--r-- 1 root mickey   21 Mar 27 07:32 flag_2.txt  
mickey@bf7749b143b5:~$ cat flag_2.txt  
_Wh0_NeV3R_gIve5_uP}  
mickey@bf7749b143b5:~$  
```

Flag is NDH{a_WInN3r_15_A_Dr3AMeR_Wh0_NeV3R_gIve5_uP}