The challenge during VishwaCTF 2022 was to send a request in which the target
user was to introduce himself by name. In this challenge, we were initially
greeted with a window where after a typical XSS attack
`<script>alert("123")</script>`, the author knew that this page was
vulnerable.

The attack was of course successful, but it was a path to nowhere. The author
tried a lot of Server Side Template Injection.

In the next step, the author proceeded to googling and started searching the
internet for clues. After a quick look at the source code, the author realized
that the website was put up on the Flask framework in Python. With this
knowledge, he was able to list the files on the server. It was also possible
to run commands common to Linux systems.

Everything was simple until the author wanted to display Flask. With the `cat`
command, a space had to be used so that the `flag.txt` argument could be
specified. The space in the URL and the encoding did not work.

The key to solving the space not being read was to use `$IFS`.

The IFS is an acronym for Internal Field Separator or Input Field Separator.
The $IFS is a special shell variable in Bash, ksh, sh, and POSIX.

With this knowledge, the author began testing the various payloads that he
wanted to send with the browser request.

The exploit used the built-in `open` object to open the file.

Thanks to the `ls` command used earlier, the author knew that the flag was in
the same directory.

The final exploit that the author designed looked something like this:  
```  
https://h3y-buddy.vishwactf.com/submit?name=%7B%7Bconfig.__class__.__init__.__globals__[%27os%27].popen(%22cat$%7BIFS%7Dflag.txt%22).read()%7D%7D%3Cscript%3E  
```