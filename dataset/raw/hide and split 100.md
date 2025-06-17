# Forensic: hide and split

## Task:

```  
Author: underzero

Explore this disk image file, maybe you can find something hidden in it.  
```

## Solution:

Attached is challenge.zip, which, when unzipped, reveals a file called
challenge.ntfs.

In this writeup, I will show 2 ways to solve this challenge.

### Solution 1: Strings

In this solution, we utilize regex to get our answer. First of all, let's run
`strings challenge.ntfs` and see the results.

![Image](https://media.discordapp.net/attachments/1107753568687095889/1163745918277910538/Screenshot_2023-10-17_at_14.50.33.png?ex=6540b1d8&is=652e3cd8&hm=3345c59fec5b433613555c7150ffb9d83ee3a4e18e47866f13728cfeeb7359a7&=&width=392&height=416)

Hmm...Nothing interesting...

Anyways, scrolling down a bit more, you find these set of strings:

![meow](https://media.discordapp.net/attachments/1107753568687095889/1163746789791383632/Screenshot_2023-10-17_at_14.54.07.png?ex=6540b2a8&is=652e3da8&hm=3950328e2d0d246fdaf4c774ee8da44de5d05e8569c7fe862a1b1a92994a293f&=&width=470&height=416)

Ah, cool hexadecimal text. If you've done some forensic before, you might
recognize those first few hex bytes from the first file, 89 50 4e is the first
few magic numbers for a PNG file.

From this information, you can safely say that these random hexadecimal
strings form an image. Cool, but can we extract these all without unzipping
the challenge.ntfs file?

The answer is yes! I utilized `egrep` for this one.

`strings challenge.ntfs | egrep -o '^(?:[0-9a-f]){16,}$'`

Let's see the result...

![meow2](https://media.discordapp.net/attachments/1107753568687095889/1163749761233457152/Screenshot_2023-10-17_at_15.05.59.png?ex=6540b56c&is=652e406c&hm=784faff2269187dd13cc06285c1dcd38ee6c3ac2c762a6cc7911fffb38bc856a&=&width=365&height=416)

Cool, we have them all. Now, we just remove all the new lines and translate it
from hex (I used [cyberchef](https://gchq.github.io/CyberChef/) for this), and
once you do that, you will get an image with a QR code.

![uwu](https://media.discordapp.net/attachments/1162973486273269842/1163066475993645106/test.png?ex=653e3910&is=652bc410&hm=5e397cc4f66243f1374a31c5857fd46f10a396cfd2458e84a7f6677c947222ef&=&width=216&height=216)

Scan it, and you get:

`TCP1P{hidden_flag_in_the_extended_attributes_fea73c5920aa8f1c}`

### Solution 2: Actually "unzipping" it

This solution was how I originally solved it. I just extracted the ntfs file
with 7z, and it results in these files showing up:

![yea](https://media.discordapp.net/attachments/1107753568687095889/1163753226064121918/Screenshot_2023-10-17_at_15.19.44.png?ex=6540b8a6&is=652e43a6&hm=243280a396ae7c843195c38172ddc5051467f3cb6f13f4a23d32273b802044c6&=&width=1060&height=416)

Anyways, the flag-[number].txt just contains  
```  
Unfortunately this is not the flag  
The flag has been split and stored in the hidden part of the disk  
```

However, the flag[number].txt/flag[number] files contain hexadecimal value.
Similar to solution 1, I just piped all the hexadecimal text into a file
called hex.txt, then used cyberchef to convert it from hex to image. Anyways,
you get the flag from both solutions.

## Flag:

`TCP1P{hidden_flag_in_the_extended_attributes_fea73c5920aa8f1c}`

## Notes & Extras:

umm...i realized that newlines existed. i could've solved this challenge
earlier. newlines screwed the final image. shoutout to my teammate xtrimi for
telling me this LOL