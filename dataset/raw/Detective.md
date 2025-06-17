## **Engineer CTF 2022**  
### Detective

Sir Arthur wrote the Hound of B____  
```  
First of all, when we hear Sir Arthur, Sherlock Holmes comes to mind, let's
imagine that this is a clue and use it. Apparently we need to use the missing
letters in the word Baskerville. it was pointless to find any clues in Google.
and I decided to enter them into the sherlock.  
```  
root?kali)-[/home/user/sherlock]```

1. └─# python3 sherlock askerville  
1. [*] Checking username askerville on:  
1. [+] CapFriendly: https://www.capfriendly.com/users/askerville  
1. [+] Chess: https://www.chess.com/member/askerville  
1. [+] Coil: https://coil.com/u/askerville  
1. [+] FanCentro: https://fancentro.com/askerville  
1. [+] Fiverr: https://www.fiverr.com/askerville  
1. [+] GitHub: https://www.github.com/askerville  
1. [+] Gumroad: https://www.gumroad.com/askerville  
1. [+] Houzz: https://houzz.com/user/askerville  
1. [+] LeetCode: https://leetcode.com/askerville  
1. [+] Minecraft: https://api.mojang.com/users/profiles/minecraft/askerville  
1. [+] Pinterest: https://www.pinterest.com/askerville/  
1. [+] Reddit: https://www.reddit.com/user/askerville  
1. [+] Scribd: https://www.scribd.com/askerville  
1. [+] Smule: https://www.smule.com/askerville  
1. [+] Snapchat: https://www.snapchat.com/add/askerville  
1. [+] Spotify: https://open.spotify.com/user/askerville  
1. [+] Telegram: https://t.me/askerville  
1. [+] TradingView: https://www.tradingview.com/u/askerville/  
1. [+] VK: https://vk.com/askerville  
1. [+] Venmo: https://venmo.com/u/askerville  
1. [+] Xvideos: https://xvideos.com/profiles/askerville  
```  
I was immediately interested in the link to the github let's go there and move
on  
```  
```  
there we are immediately greeted by such a message.  
```  
Very good Sherlock, I had been expecting you. If you came from the CTF, this
is the way to go, champ!  
```  
Perfect!  
```  
```  
After a little digging in the repositories, we find the flag  
```  
## **Flag is CTF{@ll-y0U_neEd}**  
`https://github.com/askerville/commit/commit/4b64884cff808b651bed34d2ccc83a141952f098`# Detective (14 solves)

Author: @moratorium08  
Estimated difficulty: Easy

This service write a byte of the flag at almost anywhere in Heap you like.

The trick is to craft a fake chunk at 0xXXXXX41 in order not to crash  
when the a character of flag currently we consider is 'A'  
By repeating this process, the flags can be leaked one byte at a time.

[poc.py](https://github.com/tsg-
ut/tsgctf2020/blob/master/pwn/detective/solver/solve.py)

Original writeup (https://github.com/tsg-
ut/tsgctf2020/blob/master/pwn/detective/writeup.md).