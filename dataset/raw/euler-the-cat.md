# Steganography: euler-the-cat

## Task:

```  
Author: Volf

While recording a secret message for the National Day, our dear friend Alex
forgot to close the door to his studio. Euler, his cat, while wandering
through the studio walked from right to left on the keyboard and applied some
unknown effects to the audio. Please help him reverse the transformations.

This challenge is proudly developed by Electron (ETTI).  
```

## Solution:

When you listen to the file normally, you will hear "The secret message is..."
for the first two seconds, before hearing distorted sounds. Upon opening the
file up in Audacity and looking at its spectrogram, you will see that the
distorted part has been reflected vertically.

If you switch the spectrogram to the Linear option, it becomes visible that
the distorted part is reflected along the 10000Hz mark.  
  
  
![meow](https://media.discordapp.net/attachments/1162972185988702288/1165705262187937882/image.png?ex=6547d2a0&is=65355da0&hm=2efcb6b3e34c32f0a16bc8108c8187741301ea7146d3e8a02dd475dd95e2773c&=&width=1792&height=388)

The non-distorted section looks very similar to the upper half of the
distorted section. So, you remove the bottom half by using the Spectral Delete
tool. Now, you have to move the upper section down by 10000Hz by using an
external plugin, Frequency Shifter. The audio now sounds a lot more like
talking, but it's still incomprehensible. To finally get the message, you
simply have to reverse the section.

This is the following message now:  
"The secret message is... the queen must die."

## Flag:

`{the queen must die}`

## Resources:

[https://www.audacityteam.org/](https://www.audacityteam.org/)

[https://forum.audacityteam.org/t/frequency-
shifter/66030](https://forum.audacityteam.org/t/frequency-shifter/66030)