# elytra - Beginner (50 pts)

## Description  
> I beat the game! But where's the flag?

### Provided files  
iwon.txt - a plaintext file
\[[download](https://ctfnote.shinmai.wtf:31337/files/downloadFile?id=FwMibBXASf8LXCb)\]

### Ideas and observations  
1. googling the task name, [elytra](https://minecraft.fandom.com/wiki/Elytra) are a rare end-game item in the game Minecraft  
2. googling part of the text file, it's the [End Poem](https://minecraft.fandom.com/wiki/End_Poem) (found in the Java Edition's `client.jar` at `assets/minecraft/texts/end.txt`) a poem penned by Julian Gough that appears to players at the end of a Minecraft playthrough before the credits crawl.  
   - the raw text from `end.txt` has some byte-sequences replaced before the text is displayed to the player, in `iwon.txt` the `PLAYERNAME` sequence is replaced with `doubledelete`, the line begining `§2` and `§3` are stripped, and the `§f§k§a§b§3` denoting scrambled text is replaced with `[scrambled]`

### Notes  
1. comparing the original `end.txt` with the aforementioned replacements with `iwon.txt` shows some line-ending differences  
2. not all lines are different, though, some lines in `iwon.txt` are `\r\n` terminated, others are `\n` terminated

### Solution script  
```python  
from Crypto.Util.number import long_to_bytes

text=open('iwon.txt','r', newline='').read()  
flag_l = int(''.join(['1' if x[-1] == '\r' else '0' for x in o.split('\n') if
len(x) > 0]),2)  
print(long_to_bytes(flag_l).decode())  
```

`wctf{ggwp}`

Original writeup
(https://gist.github.com/shinmai/5720d1f0a214d0878cfb530eb975c469#elytra---
beginner-50-pts).