# TeamItaly CTF 2023

## [web] LeakyNoteV3 (1 solve)
After @strellic leakynote and leaklessnote, I decided to make my own note service.

I'm sure it's secure. Can you prove me wrong?

Site: http://leakynote.challs.teamitaly.eu

Flag format: flag{[a-z0-9]+}

Authors: Alessandro Mizzaro <@Alemmi>, Stefano Alberto <@Xato>

## Overview

Leakynote is a notes service where an admin has posted a ~~password~~ flag with a strange search engine.

### Openredirect via meta-tag

nginx sets the navigate-to directive but that's an experimental feature not enabled by default.
You can post a meta redirect and the bot will follow any custom link

```php
<div id="contents"><?php echo $post["contents"]; ?></div> 
```

### 404 oracle

Now we have to find an oracle. With security headers properly set, none of the common xs-leaks are possible, how can I leak some information?\
`search.php` returns 404 if no notes are found... Well, it seems that 404 urls do not end up in the browser history. We could try to find a way to leak headless history. How we can do that?
Do you know the `:visited` selector?
[Mozilla Web Docs](https://developer.mozilla.org/en-US/docs/Web/CSS/:visited)

With some tests we discovered that if the bot visits a link whose result is 404 it will not be styled as `:visited`. This still doesn't help us much because there are restrictions on what I can stylize ([docs](https://developer.mozilla.org/en-US/docs/Web/CSS/:visited#privacy_restrictions))

### Chrome render

Okay, now with js we can force the browser to apply complex CSS repaint operations to `:visited` links and we can compare performance measurements with those taken for a known-unvisited "control" URL.
[poc](https://bugs.chromium.org/p/chromium/issues/detail?id=835590)

Now we can script the exploit to open a tab with a search query and then test if the link was visited, repeat for all the chars in alphabet and profit <3


## Credits for che code
Thanks to [@Strellic](https://twitter.com/Strellic_) for writing `leakynote` and `leakless` note that inspired us <3
