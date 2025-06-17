# Woooosh

```  
Price: 130 points  
Description: Clam's tired of people hacking his sites so he spammed
obfuscation on his new game. I have a feeling that behind that wall of
obfuscated javascript there's still a vulnerable site though. Can you get
enough points to get the flag? I also found the backend source.  
Flag: actf{w0000sh_1s_th3_s0und_0f_th3_r3qu3st_fly1ng_p4st_th3_fr0nt3nd}  
```

I decided to take this challenge diferently. Instead of reversing client-
server protocol, I just won this game, cuz it only needs 20 points to give you
flag. And so I made this simple python script, that looks for red dot on the
screen, and clicks it. xD

```python  
import pyautogui  
import time  
old = ''  
for x in range(200):  
	dot = pyautogui.locateCenterOnScreen('dot.png', region=(665, 310, 580, 325)) # have to take screenshot of this dot, and cut it to size.  
	if old != dot:  
		if dot != None:  
			pyautogui.click(dot, clicks=1)  
			print(f'old is {old}, new is {dot}')  
			old = dot  
		else:  
			pass  
	else:  
		pass  
```

Original writeup
(https://github.com/zus0/ctf/blob/master/actf.2020/whoooosh/writeup.md).