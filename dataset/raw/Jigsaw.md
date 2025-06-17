# Description  
Santa has hidden a secret message on the backside of a jigsaw puzzle that he
completed. Sadly, one of his elves dropped the completed puzzle, shuffling all
the pieces. Can you verify that it is indeed impossible for the Grinch to
recover this message?

## Solution  
You were given quite an amount of puzzle pieces, 667 pieces to be exact, in
the form of png images. Checking the files with exiftool (or strings which was
used in the first palce) relvealed some secret:  
```  
Comment                         : Secret data: 'gI'  
```  
Each file had such secret. judging from the charset we deal with base64
encoding (good estimated guess). So next obvious step would be trying to find
the correct order of that secret snippets. Since it's a puzzle it might make
sense to solve it and then check the pieces for example from top-left to
bottom-right to assemble the base64-code-string. Indeed I tried some puzzle
solver scripts. But most failed (ether not matching contours exactly, too many
pieces whatsoever ... nice try, some learing about python PIL (eg. normalized
all images to same height & length, replacing transparent background, writing
the secret sting into the image,.. ) but all fails.

After a few days trying web stuff (without much luck) I again checked the
jigsaw image directory. Since each png had its sha256 sum as its name I
thought we should check that they really match (not sure why I had not done
this earlier) but without much surprise they were all fine aka perfect
matches. But looking at the list list ordered alphabetically by the checksum
what caught my eye next was the timestamps. *ls --full-time* gives you seconds
and it didn't look like there was any image with the very same (modification)
timestamp. After checking *ls -t* and *ls -rt*   it turned out to be quite an
easy challenge.

Just reverse order by time and base64 decode the secret string. On the
commandline looks like this:

```  
../jigsaw_pieces$ for f in `ls -1rt`; do exiftool  -Comment $f | sed -n "s/.*'\(.*\)'/\1/p"; done|xargs | tr -d ' ' | base64 -d  
```

output

```

.       .        _+_        .                  .             .  
                 /|\  
      .           *     .       .            .                   .  
.                i/|\i                                   .               .  
     .    .     // \\*              Santa wishes everyone all  
               */( )\\      .           the best for 2022       .  
       .      i/*/ \ \i             ***************************  
.             / /* *\+\             Hopefully you can use this:   .  
     .       */// + \*\\*       AOTW{Sm4ll_p1ec3s_mak3_4_b1g_pic7ure}       .  
            i/  /^  ^\  \i    .               ... . ...  
.        .   / /+/ ()^ *\ \                 ........ .  
           i//*/_^- -  \*\i              ...  ..  ..               .  
   .       / // * ^ \ * \ \             ..  
         i/ /*  ^  * ^ + \ \i          ..     ___            _________  
         / / // / | \ \  \ *\         >U___^_[[_]|  ______  |_|_|_|_|_|  
  ____(|)____    |||                  [__________|=|______|=|_|_|_|_|_|=  
 |_____|_____|   |||                   oo OOOO oo   oo  oo   o-o   o-o  
-|     |     |-.-|||.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-  
 |_____|_____|

```