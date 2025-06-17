TheHiddenOne [App Script, 249 points, 13 solves]  
========

### Description

>You can send a python file to the administrator.  
>  
>But he **cat** everything to exec only simple print!  
>  
>Hint: `(^print\([\"'][a-z A-Z]*[\"']\)[;]?$)|(^#.*)`  
>  
>[http://remote1.thcon.party:10200](http://remote1.thcon.party:10200)  
>  
>[http://remote2.thcon.party:10200](http://remote2.thcon.party:10200)  
>  
>**Creators** : gus (Discord: gus#4864)

### Overview

This challenge involves uploading a Python file that has to pass some
validation before being run. After solving this challenge, however, I realized
that my solution was unintended :)

### Ideas

The challenge description mentions that an administrator will examine the
uploaded file (using `cat`) and that it must also match a provided regex
before being run. I wasn't sure what was meant about the administrator
checking the source with `cat`, but that didn't matter because I knew of a way
to run arbitrary Python code while matching the provided regex. In fact, the
only part of the regex I cared about was the `#.*` part, which was _intended_
to only allow comments. Python has a little-known feature where you can, on
the first or second line of a script file, write a special comment that gets
interpreted as a directive to change the encoding used to read the file. This
is most commonly used to change the encoding to UTF-8 (to allow non-ASCII
characters) like so:

```python  
#!/usr/bin/env python  
# -*- coding: utf-8 -*-

#...rest of file...  
```

However, the encoding you pick can be any of Python's register codecs. One of
these supported codecs is `raw_unicode_escape`, which allows you to
intersperse Unicode escape sequences like `\u265F` for a black chess pawn
Unicode character. You can also encode arbitrary ASCII characters this way,
such as a newline (`\u000a`). This means that you can "hide" Python code on a
comment line such that it will actually execute. My [final exploit
script](test.py) is below:

```python  
# coding: raw_unicode_escape  
#\u000aimport os  
#\u000aos.system("ls -laF")  
#\u000aos.system("cat *flag*")  
```

This results in the flag being displayed:
`THCon21{D0nt_tRusT_c4t_4nd_use_c4t_-v}`.

### Unintended solution?

After solving the challenge, the text in the flag made me wonder if my
solution was unintended. I looked up the `-v` flag for `cat` and found that it
controls whether unprintable characters like ASCII control codes are printed.
I then used my ability to execute code to download the challenge's source code
to see how it was actually validating the uploaded Python code. The web
service's [index.php](index.php) effectively just passes the uploaded file to
[/srv/chall.py](chall.py). This script then sets up a terminal emulator using
a Python library called "pyte", with a fixed window size. After effectively
running `cat uploaded.py` in this terminal emulator, the script then matches
the contents of each line against the regex. If any line doesn't match the
regex, it fails validation and refuses to run the script. The use of a
terminal emulator is unnecessary for my exploit, so that leads me to believe
that the intended solution is to use ASCII control codes like `\x7f`
(backspace) to have a line that starts with Python code, then a bunch of
backspace characters, then a '#' character so that the script thinks the line
is a comment and will allow it. Or some other combination of other control
codes to do something similar.

Regardless, my solution worked, and we got the points for the challenge, so
I'm happy :D

Original writeup (https://github.com/kjcolley7/CTF-
WriteUps/blob/master/2021/thcon/TheHiddenOne/README.md).