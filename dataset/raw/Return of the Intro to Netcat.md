# Return of the Intro to Netcat (662 solves, 160 points)  
## Description  
hey, netcat seems fun! (with a twist)

`nc return-of-the-intro-to-netcat.hsc.tf 1337`  
## Solution  
This one was one of the easier challenges.

The server gives us this:  
```== proof-of-work: enabled ==  
please solve a pow first  
You can run the solver with:  
   python3 <(curl -sSL https://goo.gle/kctf-pow) solve
s.AACF.AAD1NSzaviS15ewE/zJ3lZFb  
===================

Solution?  
```  
I opened a new terminal window and ran the given command ``python3 <(curl -sSL
https://goo.gle/kctf-pow) solve s.AACF.AAD1NSzaviS15ewE/zJ3lZFb``

This gives me:
``s.AAB8PXCCRqChJ7WzDBUzjUv6t61ISzLAaSuK5R5W0k/y1gafBydG/gOOgIRgsaudj9OR7ZB2h2PhArYDhQEPFps3wZH2R7NodkCReoUPXoZxHRY2ntcztiZck5lKGxq8bmoYdpW4LWHQ+oTiJ+lVh0P6aB3vN63LXwzzUrhX4RLtfR+IjzXGn29JklaAZST/H37zpebVpF+8Np7BdrWHg1sF``  
To my suprise, supplying the response to the nc server spits out the flag!  
```== proof-of-work: enabled ==  
please solve a pow first  
You can run the solver with:  
   python3 <(curl -sSL https://goo.gle/kctf-pow) solve
s.AACF.AAD1NSzaviS15ewE/zJ3lZFb  
===================

Solution?
s.AAB8PXCCRqChJ7WzDBUzjUv6t61ISzLAaSuK5R5W0k/y1gafBydG/gOOgIRgsaudj9OR7ZB2h2PhArYDhQEPFps3wZH2R7NodkCReoUPXoZxHRY2ntcztiZck5lKGxq8bmoYdpW4LWHQ+oTiJ+lVh0P6aB3vN63LXwzzUrhX4RLtfR+IjzXGn29JklaAZST/H37zpebVpF+8Np7BdrWHg1sF  
Correct  
You got it! Here's what you're looking for: flag{the_cat_says_meow}  
```

## Flag  
``flag{the_cat_says_meow}``

Original writeup (https://github.com/BASHing-thru-
challenges/HSCTF-2021-Writeups/tree/main/misc/Return%20of%20the%20Intro%20to%20Netcat).