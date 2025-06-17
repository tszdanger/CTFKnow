## Music.png - Misc 300:  

**Description:** Name that tune  
**Challenge:** music.png  
**Difficulty:** Medium  
**Solved by:** Tahar  

**Solution:**  
We start by downloading the challenge file and opening it, we see some kind of
random colors & points! I have been trying to do many tricks that I used to do
with Steganography challenges before! None worked, I asked for help and a
friend gave me a hint, he said only one Word that let me work on it till the
end!  

My friend said: LSB. It means the "**Least Significant Bit**", and I was able
to start working on it by just using this little ONE-WORD hint! I always use a
well known toolkit for LSB-Challenges, the name is **Zsteg** and you can find
it on Github!  I downloaded the tool and installed it on my VM Box to start
solving the challenge.  

I started running the **zsteg** toolkit and used the following command:
```zsteg -all music.png```, and got some kind of weird text replying in the
whole output of the toolkit! That was actually an interesting thing to look
for.  

I started by **Googling** for that output text, and found out that it was a
Music :3 **https://jhirniak.github.io/Never-Gonna-Rick-You-Up/index.html**

I Googled again using the name that was appearing in the **URL** ```Never-
Gonna-Rick-You-Up``` and I found out another well known music (Following the
Challenge Description: **Name the Tune**). So probably the name of that tune
is the flag that we are looking for!  

I made my flag and solved that challenge that took me a lot of time and
overthinking =)  
**https://www.youtube.com/watch?v=dQw4w9WgXcQ**

**Flag:**  
RITSEC{never_gonna_give_you_up}  

Original writeup
(https://github.com/ImperiumCTF/Writeups/blob/master/RITSEC%20CTF%202018/Misc/Music.png.md).