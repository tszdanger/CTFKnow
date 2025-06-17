This was a long, multi-step problem that used steg, crypto, OSINT, and
password cracking. All that was provided was an audio file and details about
this guy Chad. Opening the audio file in spectrogram view revealed the phrase
"twitter me". If you looked up [Chad the jaw bronson on
twitter](https://twitter.com/ChadTheJaw), you would find his page with some
jacked memes and two pastebin links. The first link was a photo with a
password-protected RAR file hidden inside. The second one was to the following
text file:

```  
chadchadchadchadchadchadchadchadchad  
chad  
chadchadchadchadchadchadchadchadchadchadchadchadchad  
chadchadchadchadchadchadchadchadchadchadchadchadchadchadchadchadchadchadchadchad  
chadchadchadchadchadchadchadchad  
chadchadchadchadchad  
chadchadchad  
chadchadchadchadchadchadchadchad  
chad  
chadchadchadchad  
chadchadchadchad  
chadchadchadchadchad  
chadchadchadchadchadchadchadchadchadchadchadchadchadchadchadchadchadchadchad  
chadchadchadchadchadchadchadchadchadchadchadchadchadchadchadchadchadchadchadchad  
thejaw  
the  
thejawthe  
```

If you take the number of words on each line and use an a1z26 cipher (1
word=a, 2 words=b, etc.), you get the password `iamthechaddest213`. If you use
that as the password for the RAR file, you'll see a bunch of cat videos and
photos. The flag was put at the bottom of one of the photos (sort by date
modified and choose the last modified one).

**Flag** - `byuctf{cyb3r_ch@ds_are_th3_r3aL_ch@ds}`

Original writeup (https://github.com/BYU-CTF-
group/BYUCTF-2022/blob/main/miscellaneous/chadthejawbronson/Writeup.md).