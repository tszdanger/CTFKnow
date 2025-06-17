Yeunote - writeup by @terjanq  
---

> After a very, very, very long time of development, I am extremely excited to
> announce that yeunote, a free, simple and secure note manager, is ready to
> be released publicly. However, to ensure that it does not have any security
> vulnerabilities (yeah, I care much about the security), I want to ask you,
> an ethical hacker, to check it one more time before the launch. The rule is
> simple: There is a private & password protected note at
> https://yeunote.ctf.yeuchimse.com/note/view/3, which contains the flag. If
> you can read it, the flag is yours! Good luck.  
>  
> https://yeunote.ctf.yeuchimse.com/

### Page funcionality

We can create a note containing  `title` and `description` with two options
available: `public` and `private`. If we choose the `private` option then only
people added to `share list` can see the note. Additionally, each note can be
protected with the `password`.

On the main page, we see the titles of random *public* notes and their `id`.

Every query related to the note follows the syntax
`https://yeunote.ctf.yeuchimse.com/note/<action>/<note id>`.

Every `form` on the page is protected by `csrf` token created by the following
script:

```js  
function add_csrf_token(csrf_token) {  
   $('form').each(function () {  
       if ($(this).attr('method').toLowerCase() == 'post') {  
           $('<input type="hidden" name="csrf" value="' + csrf_token + '" />').appendTo($(this));  
       }  
   })  
}

if (document.domain == 'yeunote.ctf.yeuchimse.com') {  
   add_csrf_token('bdf0ae82-2284-4b7f-a0b3-26e6d291ff1f');  
}  
```

Where `bdf0ae82-2284-4b7f-a0b3-26e6d291ff1f` is a value from the  `csrf`
cookie. We can change it to `')|alert('xss` which results with successfully
attached `xss injection`. It is also the only place on the site where I found
the mentioned vulnerability but it seems to be not exploitable.

### Bug Bounty  
In the tab `Bug Bounty` we have a simple form allowing us to send the
suspicious URL to the admin. There is also `description` field but I don't
think it does anything at all. If we send the URL `http://yoursite/csrf.html`
he will visit the link using `headless chrome 67`.

### CSRF page – add_share

So what we want to do is to craft a `csrf page` which will allow us to do
malicious things using admin's account. But every form is protected with `csrf
token` and we have to somehow steal admin's `csrf` cookie. Have we?

Earlier posted script adding `csrf token` is hosted on
`https://yeunote.ctf.yeuchimse.com/csrf.js` so we can just attach this script
on our page. But if we try that, we get the `no permissions` error or
something like that. A quick inspection showed that the reason for this is the
`referrer header` set to `https://yoursite`.  
Hopefully no referrer is allowed and adding `<meta name="referrer"
content="no-referrer">` solves the problem.

Another protection we have to bypass is `if (document.domain ==
'yeunote.ctf.yeuchimse.com'`. We cannot change the value of this property
directly because of `CORS Policy` so `document.domain =
'yeunote.ctf.yeuchimse.com'` won't work. But it is easy to bypass. Just
overwrite the property with new one before `csrf.js` is loaded -
`Object.defineProperty(document, 'domain', {value:
"yeunote.ctf.yeuchimse.com"});`.

So this is it. Now we are able to add ourselves to admin's `share list` by a
simple `post form`

```html  
<form method="post"
action="https://yeunote.ctf.yeuchimse.com/note/add_share/3">  
<input name="emails" value="[email protected]"/>  
<input type="submit" value="submit">  
</form>  
```

The complete document [csrf.html]

### CSRF page – password

After the previous step, we are now able to visit
`https://yeunote.ctf.yeuchimse.com/note/view/3` but it results with `password`
prompt. So our task now is to get the password somehow.

On the page `My Notes` there are buttons attached for each note: `Facebook`,
`Google` and `Twitter`. The first two will redirect us to the facebook/google
page and ask our permission to share the post containing the full URL, i.e
`https://yeunote.ctf.yeuchimse.com/note/view/<note id>?p=<password>`.

The third one is using backend app. In order to successfully post the tweet we
have to authorize the app before clicking the button, but only once. Clicking
on the button redirects us to
`https://yeunote.ctf.yeuchimse.com/note/twitter/<note id>` which if we have
the note with the `<note id>` in our inventory redirects us to
`https://api.twitter.com/oauth/authenticate?oauth_token=<oauth token>`. If we
already authorized the app then it will redirect us to
`https://yeunote.ctf.yeuchimse.com/note/twitter?oauth_token=<oauth
token>&oauth_verifier=<oauth verifier>` and if everything went alright we will
see the tweet with an URL containing the password on our twitter account.

But how do we do it? I've spent hours and hours trying to make it work but I
didn't manage o get the password by myself... Well, the guy who solved the
task left the tweet undeleted so anyone could see the password! I tried to
report this but nor the `admins` nor the `team jinmo123x` were responding to
my requests. Link to the tweet:
[https://twitter.com/wwydid/status/1008044466677039105](https://twitter.com/wwydid/status/1008044466677039105)

My attempt was to log in the admin to my dummy twitter account and then share
the password into this account (no confirmation needed). I could achieve that
using a similar method as for the previous step but with a little help of
backed script generating the `authenticity_token` needed to login into the
twitter account. But it didn't work. Twitter is not accepting any referrer
different from `https://twitter.com` including `no referrer`. Tried some
different versions of login page:
[https://mobile.twitter.com/login](https://mobile.twitter.com/login),
[https://twitter.com/login](https://twitter.com/login), also version of
`legacy Twitter` with JavaScript disabled.

I was also trying to generate `oauth token` for flag note which would allow me
to terminate the redirection from `twitter` to `yeunote` and send the
generated URL to the admin. But this trial results with `Note not found` error
and I couldn't find any way to bypass it.

### CSRF page – the missing piece

Comes out that getting the password is as simple as two additional requests by
admin's side  
`GET https://yeunote.ctf.yeuchimse.com/note/twitter/3` and then `GET
https://yeunote.ctf.yeuchimse.com/note/twitter?oauth_token=<oauth
token>&oauth_verifier=<oauth verifier>`. The first one tries to share the note
on Twitter but since admin is not currently logged into an account connected
to the app, the page will wait for authorization.

After that, we send the second query with pre-generated `<oauth token>` and
`<oauth verifier>` created by either sharing random note on the page or from
*login with twitter* funcionality. It is important that tokens can be used
only once so in orded to successfully intercept them we have to terminate/stop
request from `twitter` to `yeunote` before it gets executed. It can be done,
for example, using [burp].

Although `oauth tokens` generated with these steps don't match this solution
will work. It is probably because the app doesn't match the token with an
action on the page but setting something similar to `waiting for <action>` per
session.

Updated [csrf.html] file.

[burp]: <https://portswigger.net/burp>  
[csrf.html]: <https://github.com/terjanq/Flag-
Capture/blob/master/MatesCTF%202018/yeunote/csrf.html>  

Original writeup (https://github.com/terjanq/Flag-
Capture/tree/master/MatesCTF%202018/yeunote#yeunote---writeup-by-terjanq).