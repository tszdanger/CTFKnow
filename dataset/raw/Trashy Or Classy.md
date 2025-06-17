# [ASIS CTF Quals 2018] Trashy or Classy (Forensics-118pts)

## Discovery time !

In this task we were given a tcpdump capture file (pcap).

So we can open it with tool like Wireshark or NetworkMiner.  
In this case we have used NetworkMiner.  
When opened, we saw a lot of http request from `10.0.2.15` to `167.99.233.88`
and it seems like the user as performed a HTTP Directory Brute Force on some
website located at `167.99.233.88`.

The second thing that comes to our attention is the "Credentials" tab in
NetworkMiner.  
In this tab there was that:

|Client   |Server
|Protocol|Username|Password|...|  
|---------|---------------------------------------------------|--------|--------|--------|---|  
|10.0.2.15|167.99.233.88 [167.99.233.88][Private Area] (Other)|HTTP    |admin
|N/A     |...|

wich means that the user authenticate on some `Private Area` with user
`admin`.

So we looked at the "Parameters" tab and we used "filter keyword" with
"Private Area" in parameter value. With this filter we easily saw that the
authentication is for the `/private` directory.  
Then we scrolled down until we found a request to the `/private` directory
followed by a server response with HTTP code 200 OK (and not 403 Forbidden
like 99% of them).

Finaly we saw a request to the "Private Area" followed by a HTTP code 200, and
the `Authorization` parameter of the request was : `Digest username="admin",
realm="Private Area",
nonce="dUASPttqBQA=7f98746b6b66730448ee30eb2cd54d36d5b9ec0c", uri="/private/",
algorithm=MD5, response="3823c96259b479bfa6737761e0f5f1ee", qop=auth,
nc=00000001, cnonce="edba216c81ec879e"`.

It's an HTTP digest authentication so we can easily compute hash for a given
password and compare it with the `response` parameter of the authentication to
see if it is the good password.

We code a little python script to test all paswords of `rockyou.txt`
worldlist:

```python  
import hashlib

cnonce = "edba216c81ec879e"  
nonce = "dUASPttqBQA=7f98746b6b66730448ee30eb2cd54d36d5b9ec0c"  
cnt = "00000001"  
user = "admin"  
realm = "Private Area"  
qop = "auth"  
resp = "3823c96259b479bfa6737761e0f5f1ee"  
uri = "/private/"  
meth = "GET"

ha2 = hashlib.md5()  
ha2.update(meth.upper() + ":" + uri)  
ha2hex = ha2.hexdigest()

with open("/home/raven57/Documents/rockyou.txt", "r") as worldlist:  
   for pswd in worldlist:

       pswd = pswd[:-1]  
       ha1 = hashlib.md5()  
       ha1.update(user + ':' + realm + ':' + pswd)  
       ha3 = hashlib.md5()  
       ha3.update(ha1.hexdigest() + ":" + nonce + ":" + cnt + ":" + cnonce + ":" + qop + ":" + ha2h\  
ex )  
       if resp == ha3.hexdigest():  
           print "Password hit!"  
           print 'Password = '+pswd  
           break  
```

We run it, and after some few millisecond, it print:  
```  
Password hit!  
Password = rainbow  
```  
So now, we have the password of the `/private` directory for user `admin`.

Then, we go to `167.99.233.88/private/` and we enter `admin` as user and
`rainbow` as password.  
Once authenticated we get the `"Index of"` of `/private`.

On that page we see that there is only a file named `flag.caidx` and a
directory named `flag.casrt` on the `/private` directory.

## Extraction time !

Now that we found something interesting, let's try to download that and see
what we can do with it !

We download `flag.caidx` and open it, but it's non printable caracters so we
run the  linux `file` command on it to see what kind of file it is:  
```  
$ file flag.caidx  
flag.caidx: data  
```  
Well, we still don't know what type of file it is, so we ask google and found
that this file is a *"index file referring to a directory tree"* used by
[casync](https://github.com/systemd/casync).

On the *casync* Github we saw that to extract `.caidx` data we need to run a
command like that:  
```  
$ casync extract --store=/var/lib/backup.castr /home/lennart.caidx
/home/lennart  
```

So we need the content of the `flag.castr` directory to extract the data, but
when we try to access it, we got a `403 Forbidden`, so we will try without it.

We download *casync*, build it, and then we run it:  
```  
$ ./casync extract --store=./flag.castr ./flag.caidx ./flag  
Failed to run synchronizer: No such file or directory  
```  
But as we can expect, we got an error, and with `strace` we will try to figure
what is the name of the missing file so that we can download it:  
```  
$ strace ./casync extract --store=./flag.castr ./flag.caidx ./flag 2> tmpfile; cat tmpfile | grep "No such file"  
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or
directory)  
...  
openat(AT_FDCWD,
"./flag.castr/caf4/caf4408bde20bf1a2d797286b1ad360019daa59b53e55469935c6a8443c69770.cacnk",
O_RDONLY|O_NOCTTY|O_NOFOLLOW|O_CLOEXEC) = -1 ENOENT (No such file or
directory)  
write(2, "Failed to run synchronizer: No s"..., 54Failed to run synchronizer:
No such file or directory  
```  
So, now that we have a file name, we download that file from the website and
put it where *casync* looks for it:  
```  
$ wget --user=admin --password=rainbow
http://167.99.233.88/private/flag.castr/caf4/caf4408bde20bf1a2d797286b1ad360019daa59b53e55469935c6a8443c69770.cacnk  
$ mkdir flag.castr  
$ mkdir flag.castr/caf4  
$ mv caf4* ./flag.castr/caf4/  
```  
We run *casync* again and see that there is another file missing, we repeat
the above step several times and understand that there is too many files to
get !

So we code another python script to get all of them:

```python  
import os

while True:  
   command = 'strace ./casync extract -v --without=privileged
--store=./flag.castr ./flag.caidx fla\  
g/ 2> tmpfile; cat tmpfile | grep "No such file" | grep ".cacnk"'  
   process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None,
shell=True)  
   output = process.communicate()

   if not (".cacnk" in output[0]):  
       break

   i1 = output[0].find("flag.castr")  
   i2 = output[0].find("cacnk") + 5  
   f = output[0][i1:i2]

   os.system('wget --user=admin --password=rainbow
http://167.99.233.88/private/' + f)  
   os.system('mkdir ' + f[:15])  
   os.system('mv ' + f[16:] + ' ' + f[:15])  
```  
We run our script and wait until he finished.  
Finaly, we run *casync* one last time and look at the extracted data:  
```  
$ sudo ./casync extract --store=./flag.castr ./flag.caidx ./flag  
$ ls ./flag  
flag.png  
```  
>We open the `flag.png` file and saw the flag written right in front of us.

**Et voilà !**