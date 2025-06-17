We were given a python script picmaker.py and a picture inject.png. The
description of the problem was the following:

```  
Pixels don't reveal secrets, or do they?  
Hint : The original file name is inject.bin  
```

What the script basically does is it takes a file, encodes the file as base64
and creates an image with the file data encoded into it as colours. There are
four different colours, which represent four possible combinations of 2 bits.
So every byte is represented by four pixels.

The python code, which reverses the process, is the following:

```python  
import base64  
from PIL import Image

img = Image.open("inject.png")  
pixels = img.load()

width, height = img.size  
colours = [  
		(255, 0, 0),  
		(0, 0, 255),  
		(0, 128, 0),  
		(255, 255, 0)  
	]

enc = ''

for i in range(0, int(width*height)-1, 4):  
	byte = [pixels[i%width,i//width], pixels[(i+1)%width,(i+1)//width], pixels[(i+2)%width,(i+2)//width], pixels[(i+3)%width,(i+3)//width]]  
  
	part = []  
  
	for a in byte:  
		c = 0  
		for b in colours:  
			if a == b:  
				part.append(c)  
				break  
			c += 1  
  
  
	if (len(part) > 0):  
		ans = 0  
		ans |= part[0]<<6  
		ans |= part[1]<<4  
		ans |= part[2]<<2  
		ans |= part[3]<<0

		enc+=chr(ans)

unenc = base64.b64decode(enc)

f = open("inject.bin", "wb")  
f.write(unenc)

f.close()  
```

With a quick google search we can find that inject.bin is a rubber ducky
compiled payload. We can use tools to decompile it, for example Duck-Decoder
(https://github.com/JPaulMora/Duck-Decoder). In the output we can find the
flag **darkCON{p1x3l5_w17h_m4lw4r3}** as well as a Rickroll and some harmless
evil looking commands.

Original writeup (https://github.com/keyboard-monkeys/ctf-
writeups/blob/main/2021-darkctf/misc_pixelify.md).