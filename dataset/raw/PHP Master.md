# PHP Master (50 points)

## Description

Another one of *those* challenges.

Target: http://challs.xmas.htsp.ro:3000/

Author: yakuhito

## Solution

```php
<?php

include('flag.php');

$p1 = $_GET['param1'];
$p2 = $_GET['param2'];

if(!isset($p1) || !isset($p2)) {
    highlight_file(__FILE__);
    die();
}

if(strpos($p1, 'e') === false && strpos($p2, 'e') === false  && strlen($p1) === strlen($p2) && $p1 !== $p2 && $p1[0] != '0' && $p1 == $p2) {
    die($flag);
}

?>
```

You just need to bypass the filters here. You can see that there are two comparison operators, one just checks the similarity (==), and the other checks the similarity of types (===). I opened the [documentation](https://www.php.net/manual/en/language.operators.comparison.php) and immediately found the answer.

```php
var_dump(100 == "1e2"); // 100 == 100 -> true
```

But we need to bypass one more filter: the presence of the letter "e" in the string. Simple as it is, just make it uppercase. As a result, we got such a request:

```url
http://challs.xmas.htsp.ro:3000/?param1=1E2&param2=100
```

Flag: X-MAS{s0_php_m4ny_skillz-69acb43810ed4c42}