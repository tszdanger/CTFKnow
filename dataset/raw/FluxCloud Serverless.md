#### [https://waletsec.github.io/posts/2020-10-26-FluxCloud-Serverless-
Hack.lu-Writeup](https://waletsec.github.io/posts/2020-10-26-FluxCloud-
Serverless-Hack.lu-Writeup.html)

### You will need

- Code editor  
- https://serverless.cloud.flu.xxx/  
- [Challenge files](https://pwnhub.fluxfingers.net/static/chall/fluxcloud-serverless_fb116a5dc24279953ce2332a1648e506.zip)

### Solution

- Go to the "FluxCloud Serverless" website, and click **Demo**.

 We deployed our serverless instance. Now we need to find out where the flag
is hidden. We can do this by looking into source files.

 When you search for the word "flag" (e.g. with Search in VSCode) you can
notice, that it only appears in files waf.js and app.js. Let's take a closer
look.

 In app.js, there is a variable called "FLAG", with an environment variable
assigned to it. That is the place where the flag is.

 We can access the solution by requesting
"https://serverless.cloud.flu.xxx/demo/*id***/flag**". The problem here is
that your request is being checked before resolving, by waf.js.

 The firewall (waf.js) checks if the URL's path (specifically the part after
your id) includes one of the words from blocklist, "flag" is one of them. If
it does, instead of giving you the website you requested for, it would send a
response from /blocked.

 There is part in the code that checks for "double-encoding" attack, so it
would not work out. What will work out instead is writing one (or more)
characters with upper case.

- At the end of your URL, add "/flag" with one (or more) letter being upper case.

 E.g.
[https://serverless.cloud.flu.xxx/demo/yaIqnjw2fSjArUaM_4jl1**/flAg**](https://serverless.cloud.flu.xxx/demo/yaIqnjw2fSjArUaM_4jl1/flAg)

 ⚠ After one hour your "deployment" it will stop working. In order to create a
new one, repeat the first step.

### Flag

​       flag{**ca$h_ov3rfl0w**}

#### Credits

- Writeup by [mble](https://ctftime.org/user/93848)  
- Solved by [x2taptap](https://ctftime.org/user/86780)  
- WaletSec 2020

#### License

**CC BY** WaletSec + mble

Original writeup (https://waletsec.github.io/posts/2020-10-26-FluxCloud-
Serverless-Hack.lu-Writeup.html).