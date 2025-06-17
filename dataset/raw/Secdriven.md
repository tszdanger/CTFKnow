# A TL;DR solution to Security Driven by @terjanq

For this year's Google CTF, I prepared a challenge that is based on a real-
world vulnerability. The challenge wasn't solved by any team during the
competition so here is the proof that the challenge was in fact solvable! :)

* Link to the challenge: https://capturetheflag.withgoogle.com/challenges/web-security-driven  
* Link to the PoC: https://github.com/google/google-ctf/tree/master/2021/quals/web-security-driven/solution

The goal of the challenge was to send a malicious file to the admin and leak
their file with a flag. The ID of the file was embedded into the challenge
description (`/file?id=133711377731`) and only admin had access to it, because
the file was private.

## SVG to XSS  
It was possible to upload an SVG file which when provided with `&preview=1`
parameter would render it instead of downloading. But the XSS would be
executed on `doc-XX-YYYY.secdrivencontent.dev` domain.

## Domain collision  
When visiting any site from `secdrivencontent.dev`, e.g. https://doc-
foo.secdrivencontent.dev/ a message with the algorithm is presented:

```  
Invalid URL format. The URL should be in the below form.  
doc-<doc_hash>-<user_hash>.secdrivencontent.dev/<signature>/<nonce>/<timestamp>/<owner_id>/<user_id>/<file_id>  
where <doc_hash>  ~ HASH(SECRET || <file_id> || <user_id> || <owner_id> ||
<timestamp>) MODULO 17,  
and   <user_hash> ~ HASH(SECRET || <user_id> || <owner_id> || <timestamp>)
MODULO 100000

nonce cookie is signed by ~ HASH(SECRET || <random_int> || <user_id>)  
```

It can be noticed that most users will have a different `<user_hash>` part of
the domain because it's dependant on `<user_id>` and `<owner_id>`. The latter
ensures that the same file shared to different accounts will also be
different. However, it's clear that collisions will be possible. With having
enough accounts one could cover the whole space of possible domains. With
160,000 accounts the coverage for all domains should be around 80% which is
more than enough to solve the challenge.

It is worth noticing that the URL is signed with `<signature>` that prevents
URL tampering.

## Session less sandbox domain  
`secdrivencontent.dev` has 0 information about the currently logged-in user
because there were no session cookies or whatsoever. But having the URL of the
file is not enough to access it, the nonce cookie is also required and if it's
not present the app generates a new nonce, retrieves `<user_id>` from the URL,
signs it with a secret, and redirects to `/file?id=XXX&nonce=YYY&sgn=ZZZ` that
will generate a new URL with updated `<nonce>` in the URL.

If the `<nonce>` from the URL matches the nonce from the cookie, then the file
will be retrieved.

## File shares  
One can notice that `<user_hash>` is dependant on two variables `<user_id>`
and `<owner_id>` that are controlled by the player. That means that having
only 400 accounts and sharing one file with each other it generates 400*400
different pairs of `(<user_id>, <owner_id>)` which means different hashes.
This gave my exploit around 80% coverage of all possible `<user_hash>` parts.

## Leaking admin's `<user_hash>` and `<doc_hash>`  
A very important part of the challenge was to somehow leak the domain for the
admin's file to later load an XSS on a collision domain and read its content
because of `same-origin` relation. There are two ways known to me of achieving
this:  
* through CSP violation  
* through CSP rules.

The CSP violation is an instant leak. All that needs to be done is to load an
iframe pointing to `https://chall.secdriven.dev/file?id=133711377731` and the
following CSP rule: `frame-src https://chall.secdriven.dev` and listen to
`securitypolicyviolation` event which contains `blockedURI` property
containing the domain of the blocked URI. That is because the
`https://chall.secdriven.dev/file?id=133711377731` (allowed by CSP) redirects
to `https://doc-XX-YYYY.secdrivencontent.dev` (blocked by CSP). This makes use
of undefined behavior of how to handle iframes with CSP. Chrome and Firefox
behave differently regarding this.

The leak through CSP rules is well defined and is about checking when the CSP
blocked the resource and when not. To increase the performance, binary search
can be used. By creating the following ruleset  
```  
img-src https://chall.secdriven.dev https://doc-1-3213.secdrivencontent.dev
https://doc-2-3213.secdrivencontent.dev ... https://doc-17-3213.secdriven.dev  
```  
depending on the final domain either it gets blocked or not. If it's blocked
that means that the domain is present in the specified ruleset, if not, not.

## Forging custom domain  
Even if we manage to get the collision domain for a file then we somehow need
to force the admin to visit the file on this specific domain. If we tried
`/file?id=<xss_id>` then the admin will end up in a different domain because
of `<user_id>` difference. Because it is possible to write cookies from
`doc-12-321.secdrivencontent.dev` to parent domain `.secdrivencontent.dev`, we
can create a cookie on a specific path on `.secdrivencontent.dev` which will
be used when requesting any `doc-XX-YYYY`. That way, we can ensure that the
malicious code ends up on the same domain.

## Escalating XSS on same-origin  
Even though we have an XSS on the same domain as the admin's file it's not
trivial to leak the contents of it. That is because we can't predict the final
URL and we have to generate the final domain through
`https://chall.secdriven.dev/file?id=133711377731`. We can't use fetch then
because the first request is cross-origin. What we could potentially do is to
load it into the iframe and then read its contents.

But there is another caveat. The file triggers download and loading it in the
iframe won't have its contents stored inside the page but downloaded instead.
We somehow need to intercept the request before downloading. This can be done
with cookie bombing or CSP rules.

The previous trick with reading `blockedURI` from the
`securitypolicyviolation` event, when same-origin, returns the whole URL
instead of only the origin. With that it's possible to leak the first URL
after redirection but there is one problem - `/file?id=XXX` always redirects
first with nonce equal to 0 because of 0 knowledge about nonce in
`secdrivencontent.dev`, then `secdrivencontent.dev` redirects back with the
nonce, and then the real URL is returned.

The flow is summarized below:  
```  
1. chall.secdriven.dev/file?id=133711377731 -> doc-XX-YYYY.secdrivencontent.dev/<signature>/0/<..rest>  
2. doc-XX-YYYY.secdrivencontent.dev/<signature>/0/<...rest> -> chall.secdriven.dev/file?id=133711377731&nonce=<nonce>&sgn=<sgn>  
3. chall.secdriven.dev/file?id=133711377731&nonce=<nonce>&sgn=<sgn> -> doc-XX-YYYY.secdrivencontent.dev/<signature>/<nonce>/<..rest>`  
4. File is retrieved  
```

What in theory could be done is to leak the URL with nonce equal to 0, load it
again, race-condition the CSP (it'd be required because we assign the
secdrivencontent.dev which is set to be blocked in CSP), and leak the final
URL. But this doesn't work. It's impossible to race-condition CSP.

What can be race conditioned is cookie bombing though. After retrieving the
first URL with nonce 0, we can at the same time request `doc-XX-
YYYY.secdrivencontent.dev/<signature>/0/<..rest>` and create a lot of cookies
so the first request goes without them, but when
`chall.secdriven.dev/file?id=133711377731&nonce=<nonce>&sgn=<sgn>` resolves,
the final URL will come with lots of cookies. That way, the final URL will
cause the server to throw an error due to overly long headers and then we can
read the final URL from the iframe because of the same-origin relation. After
that, we clear the cookies and call fetch to retrieve the flag.

## Domain lifetime  
It could be noticed that `<user_hash>` also depends on `<timestamp>` which
changes every 5 minutes it could be deduced from the 0's in the timestamp,
e.g. `1626690000000`. That means, that we only have 5 minutes to execute the
exploit which is more than enough for efficient exploits and is very tight for
unintended solutions, such as bruteforcing all 100,000 accounts.

## Summary  
1. Send SVG to the admin and leak flags's domain via CSP leaks  
2. Find domain collision  
3. Send SVG to the admin that will execute malicious code on the same domain  
4. Retrieve the flag because of same-origin 

**CTF{One_puzzle_after_another_until_it_is_doner}**

Original writeup
(https://gist.github.com/terjanq/458d8ec1148e96f7ccbdccfd908c56f6).