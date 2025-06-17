## Description

Susan Landau (born 1954) is an American mathematician, engineer, cybersecurity
policy expert, and Bridge Professor in Cybersecurity and Policy at the
Fletcher School of Law and Diplomacy at Tufts University. She previously
worked as a Senior Staff Privacy Analyst at Google. She was a Guggenheim
Fellow and a visiting scholar at the Computer Science Department, Harvard
University in 2012. - Wikipedia Entry

Challenge: Connect to our webserver and understand the concerns of this
mathematician and privacy expert.

---

The webserver brings us to a welcome page which then directs us to a login
page that requires a username. We cannot continue unless something is entered
and they provide a clue which is probably important in figuring out the
correct login

**"Welcome Cyber Heroine, you get more details when you don't choose your name
to be heroine but your 'cyberheroine' username"** seems to be important but
for quite a while I wasn't sure what it meant.

Entering a random username, we now get two links, one to an "easy path" and
one to a "difficult path". Going the easy path provides us with a dead end and
going to the hard path allows us to "request help".

Requesting help gives us another dead end but now we have another hint, there
is an image of a gingerbread man and inspecting the element shows that the
image is called *9-tough-cookie*. Viewing the site's cookies I saw that there
was a PHP session (which is very common and I assumed not relevant) and a
csrf_token which was a lot more interesting. CSRF stands for cross-site
request forgery which is a type of web attack where a site is only verifying
permissions based on a http cookie/token. So if we can alter that token to
something important we should be able to access the flag.

I tried a couple different login names just to see if the token changes at all
but it would always stay as *40c331964b7560a4d3baaae420d5e3cd*. So next step
was to try and crack this hash and see if it provides any information. Using
crackstation, which is just an online hash cracker, we see that it is an md5
hash which decrypts to *"hack this"*. Side note, in cracking this hash I was
expecting it to have a title like user or student which I could then alter to
admin or the name of the woman that this challenge was based on.

Without having any more info, I went back to the login page with the hint to
see if I could figure out what I needed. It took a bit of trial and error
which consisted of 'heroine', 'cyberheroine', 'susan landau', and any
combination of those before realizing that I probably needed to encrypt them
in md5 before submitting. Swapping the token in the request help page to the
md5 hash of 'cyberheroine' (*09a206b401aaa7b5315e1d814ce16896*) I got the flag
*chctf{U_a53_$ucc3$$ful!!!}*.

Original writeup (https://jaedyno15.github.io/ctf_writeup/2023-09-10-susan-
landau/).