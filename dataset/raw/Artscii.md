## Insomni'Hack Teaser 2023 - Artscii (Misc 200)  
##### 21/01 - 22/01/2023 (24hr)  
___

### Description:

*Can you read the flag?*

```  
generate.py  
output.txt  
```  
___

### Solution

The flag is encoded in the
`output-82af45781b1a0057f2bf9b69d1702976928383941b7f9651de8e2c819935bcf2.txt`
file:  
```  
##   ##  #     ####  #    #  ##  
### ###  # #  # ## ####  ##### ##  
#######  ##    ## ##    ###     #  
#### ##  ##     ## #    ##   #  
#    ##  ##       ##    ##   #  #  
#    ##  # #  # # ##### #### ####  
##  ###  #      ## ###   ##  #  
##   ##  ##     ####      # ##  
##   ##     #      #   ##  #### ##   #  ##   ##   ##  
### ###        #  ##    #   ##  ##   #   #   ### ###  
#######        #    #####  ###  ##   #       #######  
#### ##   # ##     ## #     #   ##   #  ###  #### ##  
#    ##   #  ##      ##     ######   #####   #    ##  
#    ##  ### ##      ##     ##  ##   # ##    #    ##  
##  ###  #### ##    ####   #### ##  ### ##   ##  ###  
##   ##  ##   ##     ##    ##   ##  ## ###   ##   ##  
  #     #        ##  #     # # #   ###   # #    ##    ## #   #  # #    #
## ####  
     #  #  ####   #   ##  #  ###   # ##  # ##   #     ####   #  #      #  #### #  # ##    
     #      # #  # #  ##  # #  #   #   # #  #   # #   # # #  #             # # ## # ##    
# ##       #      #  ###   # # #   ###   #  # ####     ## #  #  # # #     #
#  #  #  
#  ##    ### # #  ###  #   # # #   # #   #    ##      ########   ##    #   # #
#   ###  
### ##    ### # #  ##      ##  ##     ### #    ##          ## #   ##    #   #
# #  # ##  
#### ##    #      #### ##  ## #      ##         # #  ####### ###   #      #
## ####  
##   ##           ##   ##           # # #      ##    ######## ## ###
##   ##  
```

The code is in the
`generate-5612300a7e5a0bf0120c06ab3ccbc3cb0003e209d1e6667d70bf0797d82a307c.py`
file:  
```python  
import re  
import art

with open("flag.txt") as f:  
	flag = f.readline()  
	assert(flag[0:4]=="INS{" and flag[-1]=="}")  
	content = flag[4:-1]  
	assert(re.search(r'^[A-Z1-9_]*$', content))  
	assert(content.count("_") == 2)  
	content = content.replace("_","\n")

def mergeLines(line1,line2):  
	line = list(map(lambda xy: " " if xy[0] == xy[1] else "#", zip(line1, line2)))  
	return ''.join(line)

def mergeText(text1, text2):  
	a = text1.split("\n")  
	b = text2.split("\n")  
	c = []  
	for j in range(25):  
		c.append(mergeLines(a[j],b[j]))  
	return '\n'.join(c) 

i = 0  
while i<3:  
	text = art.text2art(content, font="rnd-medium", chr_ignore=False)  
	if re.search(r'^[ #\n]*$', text) and text.count('\n') == 24:  
		if i == 0:  
			res = text  
		else:  
			res = mergeText(res,text)  
		i = i+1

print(res)  
```

### Cracking the Flag

The first task is to find which **3** fonts were used to generate the flag.  
From the output we can easily tell that the first line is `MISC` (or `M1SC` or
`MI5C` or `M15C`).

Therefore, we brute force all font combinations (there are **~100** fonts, so
it doesn't take long)  
and check which combination produces the desired output. After **~1** minute
we get the correct fonts:  
```  
   future_2  
   green_be  
   z-pilot  
```

Then we move on to the second line. We crack the flag character by character.  
We brute force each character and we check **how many columns** matches with
the target output.  
The character that matches the most columns is the correct one. We repeated
the same process for the  
3rd line of the output and get the flag.

For more details, please refer to [artscii_crack.py](./artscii_crack.py) file.

So, the flag is: `INS{MISC_MAYHEM_A7R93Y4E7H}`

___

Original writeup (https://github.com/ispoleet/ctf-
writeups/tree/master/insomnihack_2023/Artscii).