# Nano

## Problem

It is not difficult to get the flag of this challenge because I have left some clues for you!

## Solution

We are given a simple static website as a blackbox. There's a clue in the sources: `Flag is in /etc/ff3efa4307078c85678c6adee3b5f1b1af2ba16e/nanoflag/`, it will be important later.

Task name is a clue in itself, nano's backup files are appended with a tilde, so accessing source of an `index.html~` page gives us next clue: `This URI may help you: /801910ad8658876d56f5c8b24a563096.php`.

This page spits out its source:

```php
<?php
    $fp = fopen("/etc/tmuctf/another_flag_help.txt", "r");
    if($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['flag_help']) && strlen($_GET['flag_help']) <= 10) {
        include($_GET['flag_help']);
    }
    fclose($fp);
    echo highlight_file(__FILE__, true);
?>
```

Most important part here is that the script opens a file and our file inclusion is done before it's closed. It means, that we can access this file by accessing actual file descriptor in `/dev/fd/`. Simple bruteforce gives us the path `/dev/fd/10` and the next clue: `Just another help for you :) /ffc14c6eb03e852ea2d2cbe18b3f4d76.php Hope be useful...`.

We are presented with a blackbox that accepts ZIP-archives and extracts its contents to some folder. Due to lack of archive content validation, we can use symlinks to access arbitrary files on the system.

We take the path we were given in the first hint and create an archive with a symlink to this folder:

```sh
ln -s /etc/ff3efa4307078c85678c6adee3b5f1b1af2ba16e/nanoflag/ kek   
```

After unzipping, we can access the folder from the web: `/uploads/144f011d6b80333683d593977aebb494e374dafe/kek/`, but file listing isn't available, so we have to just guess that flag is in the `file.txt`, so accessing `/uploads/144f011d6b80333683d593977aebb494e374dafe/kek/flag.txt` gives us the flag.

## TL;DR

 - Local file read
 - ZIP symlink upload