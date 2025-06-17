## Challenge Description

Sometimes, we must look back in time to bring all the good vibes back!

Flag format: CTF{sha256}

### Intuition

The description and category (OSINT + Stego) seems to hint at using the
wayback machine. We search for the photo on the wayback machine and find the
"original" photo posted on the Defcamp website. We notice that the top-left
corner has modified pixels, so maybe something is hidden in it with the
LSB/MSB technique. We've tried different scripts to extract them, with
different offsets and bit concatenation but we couldn't get anything.

At some point I had the idea to compare the original pixels to the ones
provided. We notice that if we substract any channel value (R, G, B) between
the two pixels, we get a number that lands in printable ASCII range. Last
pixel decodes to ``}`` so we've got our flag.

### Solution

Simple script to make the substractions:

```py  
#!/usr/bin/env python3

from PIL import Image  
from itertools import permutations

image_path = "flag_encoded.png"  
alt_image_path = "./2015_buc_1.jpg"

image = Image.open(image_path)  
alt_image = Image.open(alt_image_path)

pixels = list(image.getdata())  
alt_pixels = list(alt_image.getdata())

extracted_data = ""  
for i in range(69):  
	pixel_values = pixels[i]  
	alt_pixel_values = alt_pixels[i]  
	print(chr(alt_pixel_values[0] - pixel_values[0]), end='')  
```

#### Flag

```CTF{fc5cbfe2cae683a39e7a8376e69a76e759e5720ec5babcb188fc2ffda316ed47}```

Original writeup (https://dothidden.xyz/defcamp_quals_2023/defcamp6/).