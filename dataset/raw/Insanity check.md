## Insanity check  
## Description:  
```  
insanity introduce inspire something incredible impulse ivory intelligence
incident implication hidden illustrate isolation illusion indirect instinct
inappropriate interrupt infection in item inspector institution infinite
insert the insist import ignite incentive influence instruction invasion
install infrastructure innovation ignore investment impact improve increase
rules identification initial immune inhabitant indulge illness information
iron injection interest intention inquiry inflate impound  
```  
## Solution:  
As you see, we got multiple words starting with "`in`" and they are 4+
characters long. That's except of `something hidden in the rules`.  
Huh, okay. Looking at the rules in the Discord we do become more and more
insane, but there's a trick.  
We see the rules as:  
```  
1. rule 1  
2. rule 2  
...  
```  
But we can click on triple dots `...` at the top-right corner of the rules
message and copy the message with formatting.  
After pasting, turns out the rules have a hidden message:  
```  
107122414347637. rule 1  
125839376402043. rule 2  
122524418662265. rule 3  
122549902405493. rule 4  
121377376789885. rule 5  
```  
Okay! This is something!  
Except... What is it?  
This looks like a Unix time stamp, but that doesn't seem right.  
Let's use a tool like the following: <https://scwf.dima.ninja/>.  
Okay! The first number got decoded into `amateu`!  
Try the second one... It gets decoded into `rsCTF{` and we get a hit in `RSA
Decimal` algorithm!  
Go to this algorithm's output and decode all the rest.  
Good job, we are done!  
---  
Original writeup was posted in [Neon Flags
community](https://discord.gg/SH6Y3dJuU4).

Original writeup (https://discord.gg/SH6Y3dJuU4).TL;DR: Go Insane and try downloading everything on the discord server and
eventually it will lead to the flag :P

Original writeup (https://dunsp4rce.github.io/rgbCTF-2020/forensics-
osint/2020/07/14/Insanity-Check.html).