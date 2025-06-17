# NewPwd writeup (Challenge author perspective)

Unsurprisingly, this turned out to be one of if not the hardest challenges in
the ctf. Here is the intended solution:

First of, if you tried solving this and just completely skipped the landing
page you are going to have a hard time, since it describes exactly how the
login prompt behaves. Basically, there is a user called admin which you need
to attempt to log into. When you enter a wrong password you are also given the
information in the source of the page about which character was wrong, so this
allows you to brute the password one character at a time. The problem is that
there exists a captcha. Each time you fail a captcha, your session is
invalidated and the admin password is reset, so to successfully brute force
the admin password (consisting of the string "keep going" followed by 64
random printable ascii characters) you will need to submit at least roughly
3000 correct captchas in a row. This is nearly impossible to do for a human,
since some of the captchas are almost unreadable and one mistake will reset
you to the beginning. This is the main challenge of NewPwd.

If you investigate further into the session cookie and decode it, you will
find that it contains a captcha_type value. This is always an integer between
0-19, and it's suspicious that anything like this would exist. The next
intended step would be to clear cookies and request captchas until you have
two of the same "type". if you compare them, you will notice that both have
the exact same noise and random lines. Therefore, if you request a bunch of
captchas of the same type and run max() on all of them pixel by pixel, you can
extract the raw noise and random lines of that captcha type. I call this the
captcha overlay. Once we have all the captcha overlays, we can remove the
noise from any captcha by just inverting the captcha overlay and adding it to
the captcha. this gives us a much cleaner image, however the characters are
still somewhat broken up since we don't actually know what the color of a
pixel was behind the captcha overlay.

The second big thing to realize is that every time the same character appears
in any captcha it is always translated and rotated exactly the same amount
from its origin. Therefore, if we split each captcha into 5 parts of equal
width, one for each character, we can then manually label these characters and
take the min() of a bunch of the same character to get a very clear image of
how that specific char looks. The labeling won't take longer than 15 minutes.
With this we are almost at the solution.

Now to actually solve a captcha programatically we first need to split the
captcha up into the 5 parts, one for each char. Then we simply compare each
captcha char with all of the extracted clear characters to see which captcha
char has the least white pixels where the clear image char has a black pixel,
which means that that is the closest match and probably the letter used in the
captcha. From here we we can brute force each character of the password
individually solving captchas each request and we eventually get the flag
after finding the whole password. This captcha solving method is 100% reliable
if trained properly.

There may be different methods of creating a similar captcha solver, some of
which may be better, but this was the one that i came up with. I would
consider any custom written captcha solver to be within the intended solution.

As a side note, there was a bug in earlier versions of newpwd that caused the
captcha to not regenerate if `/captcha` wasn't requested after a login
attempt, basically allowing the same captcha answer to be submitted every time
for every login attempt. This was though fixed as nobody had yet solved the
challenge at the time of discovery of the unintended solution.

If you want to take a look at the challenge source or my captcha solver, it's
in the same folder as this writeup file.  

Original writeup
(https://github.com/wat3vr/watevrCTF-2019/blob/master/challenges/web/NewPwd/writeup.md).