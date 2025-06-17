# Do You Know GIF?

Description :

```text  
Ah, Dante! He appears in poems, videogames… He wrote about a lot of people but
few have something meaningful to say about him nowadays.

Attached file : [dante.gif(14mb)]  
```

The file size tempted me to check for the embedded files in the GIF using
`steghide`,`stegoveritas` and `stegextract` and many more, but none of them
was able to extract data.

Then tried exiftool on the `dante.gif`. Found a comment but it was not a flag.
After trying all options on exiftool `-a` of exiftool loaded all the comments
of `dante.gif` file.

```bash  
mj0ln1r@Linux:/$ exiftool dante.gif  | grep Comment  
Comment                         : Hey look, a comment!  
mj0ln1r@Linux:/$ exiftool -a dante.gif  | grep Comment  
Comment                         : Hey look, a comment!  
Comment                         : These comments sure do look useful  
Comment                         : I wonder what else I could do with them?  
Comment                         : 44414e54457b673166355f  
Comment                         : 3472335f6d3464335f6279  
Comment                         : 5f626c30636b357d  
Comment                         : At the edges of the map lies the void  
```

Converted the hex strings to ascii to get the flag

```text  
44414e54457b673166355f : DANTE{g1f5_  
3472335f6d3464335f6279 : 4r3_m4d3_by  
5f626c30636b357d : _bl0ck5}  
```

> `Flag: DANTE{g1f5_4r3_m4d3_by_bl0ck5}`

# [Original Writeup](https://themj0ln1r.github.io/posts/dantectf23)

Original writeup (https://themj0ln1r.github.io/posts/dantectf23).