# Challenge Info:

#### Challenge Name: ProgrammersHateProgramming 2

#### Challenge Author: ZeroDayTea

#### Challenge Description: oh noes now there are more filters :(( Link:
http://147.182.172.217:42007/

#### Files Provided: ProgrammersHateProgramming2-sourcecode.php

# TLDR:

#### - Use same methodology as the original ProgrammersHateProgramming
challenge, but bypass more "one-time" filters and use nesting or concatenation
on "permanently" filtered out words.

# In-Depth Solution:

#### This challenge starts off with the website looking identical to the first
ProgrammersHateProgramming challenge, but the sourcecode provided is a little
bit different. Pretty much as the description says, more filters. To start off
I always like getting the `str_replace_first` filters out of the way to make
writing the rest of my XSS injection easier. For now my injection just looks
like this:

```php  
flag  
```

#### Now that we've got all of the one-time filters out of the way we can
craft our injection. For the original challenge I used the php `readfile()`
function and was able to do it that way, but this time the word read is
filtered out so we won't be able to use that function ... just kidding! We can
actually get around these stinky filters quite easily and my answer was
**nesting**. If you have something like `readfile()` then when 'read' is
filtered out that read will turn into a blank space and the 'file()' part on
the right side will collapse in and result in just `file()`. That caving in as
I like to call it can be exploited however. If we nest a read inside another
read, then when the inside read is replaced the two sides of the outer read
will collapse in and result in a normal read. Phew, that was long, here's an
example.

#### `rereadad` ---> `re` ~~read~~ `ad` ---> `read`

#### After testing it out it works perfectly and it now means we can use this
with all the other functions. But first let's just get the flag. Here's how my
final XSS injection turned out:

```php  
flag  
```

#### And boom, our flag is printed out. I want to put out a quick note though
saying that this is not the only way to solve this challenge. Php has a ton of
different functions that you can use to do the same thing as I did here.
Another common example I found looks something like:

```php  
flag  
```

#### This was actually the most common method I saw especially in the original
challenge because people had to first even figure out that the flag was being
stored in the file flag.php. However a lot of methods did use the php
`system()` function so I want to recognize MikeCAT's solution here:
https://mikecat.github.io/ctf-
writeups/2021/20210917_PBjar_CTF/web/ProgrammersHateProgramming_2/#en because
it used a different function of `passthru()` which I think is a lot less
common and will be less likely filtered out in similar challenges like this.
MikeCAT's solution also has a different method than nesting which concatenates
strings together using the php `.` operator and this just goes to show how
many different ways you can craft this injection.

#### Anyways enough blabbering here's the flag!

## Flag:
flag{wow_that_was_a_lot_of_filters_anyways_how_about_that_meaningful_connection_i_mentioned_earlier_:)}

Original writeup
(https://github.com/RenchTG/PBJar_CTF_Writeups/blob/main/ProgrammersHateProgramming%202/writeup.md).