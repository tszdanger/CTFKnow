We are given a game similar to candy crush and use cheat engine to reach level
10. This gives as a clue on how to get the flag.

---

The game looks something like this. It is impossbile or very hard to reach
level 10 withoutcheats, given the 60 seconds time limit per level. Of course,
this imediately hinted `Cheat Engine`.

Basically, we have to find the address of the goal variable and change it to 0
in order to pass to the next level.

P.S: I didn't know level 10 had something special, I just tried to pass as
many levels as I could.

Here's how the game looks like when we pass a level:

What will happed is, the game will display some weird rapidly moving text over
the noise background when we reach level 10. This was very hard to read so I
recorded my screen with OBS and saved the frames before and after the text's
appearance and then xored these 2 images.

Here's a screenshot of the Cheat Engine process:

We set the value to scan for to 1250. Initially I didn't know the value type
was `Double` and CheatEngine displayed multiple values. However, after trail
and error I figured this out and I only needed to scan once to find the
address of the `goal` value. After changing it to zero, I passed to the next
level and repeated the process until level 10.

Here's a xor of the 2 images I was talking about earlier:

We can barely see the hint. It says `change tween to see flag`.

Here I got a little bit stuck. I knew what the tween was but had no idea how
to change it and I think I solved this challenge a bit unintended. If we click
randomly on the bottom noise background box we can see something moving very
slightly.

Also, sometimes the text would move on its own with clicking or changing the
tween. I didn't know what this was really about, but it rendered the previous
step useless.

I just used the same xor technique and found the flag:

After staring at this for a bit I figured it said `FL4G_` something. After
playing around a little bit more with this, I finally deciphered the last part
of the flag:

Flag: `FL4G_TW33N`