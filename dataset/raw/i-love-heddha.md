**Description**

> A continuation of the Ez-Web challenge. enjoy  
>  
> 207.154.226.40:8080

**No files provided**

**Solution**

The initial webpage is identical to that of [`ez web`](#100-web--ez-web).
`robots.txt` still disallows `/flag/` and the directory listing in `/flag/`
only contains `flag.txt`. If we click the link from the directory listing,
however, we get a 404 - the link actually points to `/flag/flga.txt`.

We can fix the link to `/flag/flag.txt`, and we get "Bad luck buddy". Once
again we set our `isAllowed` cookie to `true`.

```html  
You are using the wrong browser, 'Builder browser 1.0.1' is required  
```

After this [`User-Agent`](https://developer.mozilla.org/en-
US/docs/Web/HTTP/Headers/User-Agent) check, we get a
[`Referer`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer)
check and finally we get a [Base64](https://en.wikipedia.org/wiki/Base64)
string.

   $ curl --silent \  
     -b "isAllowed=true" \  
     -A "Builder browser 1.0.1" \  
     -H "Referer: hackover.18" \  
     "http://207.154.226.40:8080/flag/flag.txt" | base64 -D

`hackover18{4ngryW3bS3rv3rS4ysN0}`

Original writeup
(https://github.com/EmpireCTF/empirectf/blob/master/writeups/2018-10-05-Hackover-
CTF/README.md#100-web--i-love-heddha).