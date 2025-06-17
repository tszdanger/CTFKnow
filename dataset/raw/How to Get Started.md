## How to Get Started - 0 points - 64 solves

>Welcome to pwnyOS!  
>  
>To get your credentials to access pwnyOS, please visit:
https://uiuc.tf/pwnyos  
>  
>More information about pwnyOS, and how to connect to a VNC server can be
found here: https://github.com/sigpwny/pwnyOS-2020-docs

We see that this challenge tells us to “get started”. (whatever *that*
means...)  Most teams disregard it as a challenge not worth doing because it's
so hard with its extremely high point value of zero, and it’s low solve
percentage, with only 64 solves... Anyway, in this challenge, they give us two
links. We click on the first one and it leads us to this site:

![](https://raw.githubusercontent.com/matdaneth/uiuctf-
writeups/master/Images/how_to_get_started/writeups31.PNG)

We see it tells us a bunch of credentials. They also gave us this password. We
know that it can’t be plaintext, considering how many points this challenge is
worth. It must be encrypted or encoded using a cipher! Maybe it could even be
a flag!

The password that was on the page read  “d8f1328d”, and it’s made up of entirely letters and numbers. That’s a clue for base64 encoding! We run the command “echo d8f1328d | base64 -d” on our computer, and we get the text “wo” and an unprintable character. Too bad.

Next, we try using a Vigenere cipher. We guess that the key would be “pwnyOS”,
so with our supreme guessing skills we decode the cipher. I wrote this python
script to decode for us:

   flag = “”  
   for c in range(len("d8f1328d")):  
	 flag += chr(ord("d8f1328d"[c]) + ord("pwnyOSpwnyOS"[c % 6]))  
   print(flag)

However, despite our efforts, we get some jumbled mess resembling “Ô¯Ôª¨Û”.

Well, that’s not it either.

We continue to scan the page and we find a button that says Go Back. We try to
click on it, but it does nothing. Then we use the clever trick of opening the
link in a new tab, but we come upon a blank page.

We suspect that there is some sort of flag hidden in this blank page.

We open up the inspect element menu, but still, to our disappointment, we find
nothing.

![](https://raw.githubusercontent.com/matdaneth/uiuctf-
writeups/master/Images/how_to_get_started/writeups33.PNG)

We then realize that there is still another website we forgot to check! We
quickly go onto the other link and it leads us to a github page.

![](https://raw.githubusercontent.com/matdaneth/uiuctf-
writeups/master/Images/how_to_get_started/writeups34.PNG)

We see a file called Getting_Started.pdf. Since this is the name of the
challenge is “How to Get Started”, we click on the link, but again, we find
nothing of use. Just some weird documentation. HOW IS THIS HAPPENING THAT
EVERY PROMISING LINK LEADS US ON A WILD GOOSE CHASE!?!

![](https://raw.githubusercontent.com/matdaneth/uiuctf-
writeups/master/Images/how_to_get_started/writeups35.PNG)

So we go back to the original link to look for the flag, but before we can
start searching, the words “go back” remind me of something… The INTERNET
ARCHIVE’S WAYBACK MACHINE!!! That had to be it! I could already see our score
rising by ZERO points and beating DiceGang.

We go onto the Wayback machine internet archive and we put the URL in the
search bar and we find… nothing.

![](https://raw.githubusercontent.com/matdaneth/uiuctf-
writeups/master/Images/how_to_get_started/writeups36.PNG)

The challenge starts to feel like a very, *very* cruel joke meant to distract
us from the real problems and make us waste our time. The *zero points* which
seemed so glorious earlier seem like nothing.

Trying to find something to take out our anger on, we find this grey sliding
bar on the corner of the github. We start sliding it around watching it go up
and down. Then when the gray sliding thing reaches the bottom, we see
something pretty suspicious.

There, in brackets, we see a hint for the flag! It says
“{read_the_docs_carefully!}!”

![](https://raw.githubusercontent.com/matdaneth/uiuctf-
writeups/master/Images/how_to_get_started/writeups37.PNG)

Given this advice, we start reading the doc from top to bottom VERY carefully.
All we find is a bunch of stuff about pwnyOS. Then we realize that TWO things
are highlighted in gray highlights. One of them was the hint we found, the
other one says “kernel.chal.uiuc.tf:PORT”

![](https://raw.githubusercontent.com/matdaneth/uiuctf-
writeups/master/Images/how_to_get_started/writeups38.PNG)

We try wrapping it with uiuctf{} and entering the flag in, but it says we are
incorrect. We try wrapping it with UIUCTF{} as we have seen in some other
challenges, but we are still incorrect.

Again we have that feeling that the *zero points* are actually *nothing*. Then
we see something before the hint. There's an "uiuctf" before it!

![](https://raw.githubusercontent.com/matdaneth/uiuctf-
writeups/master/Images/how_to_get_started/writeups39.PNG)

We take the "uiuctf" part along with the hint and we submit it. CTFd says our
flag is correct and we see the team [sqrt(-1) + 1] gain a whopping *0 points*,
rising from 31st place to the outstanding rank of *31st place*!

Flag: *uiuctf{read_the_docs_carefully!}*

Original writeup (https://github.com/matdaneth/uiuctf-
writeups/blob/7d51ed6b83821feeb3fd70bbe5fc0d86ae08d052/How%20to%20Get%20Started.md).