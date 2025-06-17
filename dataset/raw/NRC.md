# NRC (955 solves, 107 points)  
## Description  
Find the flag :)

[no-right-click.hsc.tf](https://no-right-click.hsc.tf/)  
## Solution  
Upon visiting the website, we are greeted with some text and no way to right
click. ``Ctrl+Shift+C`` brings up google chromes developer console so we can
poke around.

Looking at the sources we see ``useless-file.css`` containing the following:  
```css

body {  
   text-align: center;  
   font-size: 5rem;  
   font-family: 'Abril Fatface', cursive;  
}

.small {  
   margin-top: 50vh;  
   font-size: 0.5rem;  
}

/* cause i disabled it in index.js */  
/* no right click = n.r.c. */  
/* flag{keyboard_shortcuts_or_taskbar} */

```  
And there's the flag!  
## Flag  
``flag{keyboard_shortcuts_or_taskbar}``  

Original writeup (https://github.com/BASHing-thru-
challenges/HSCTF-2021-Writeups/tree/main/web/NRC).