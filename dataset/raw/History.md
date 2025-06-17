#  History  
tags: misc | hist

## Description

>The faculty of PWN history put a quiz online.  
It involves several important characters of fiction, technology, business and
music.  
Watch the video and then name the protagonists
[here](http://namegame.uni.hctf.fun/).

The link contains a form with 9 pictures and ask you to enter the name of the
person/thing in each image.

## Solution  
This is the less tecnical task of the CFT and we managed to solve it with some
knowledge and lots, **lots** of googling (actually a lot of *duckducking*).  
This is how we got each image:

1. We knew from the video he's *Claude Shannon* but inserting the word *Shannon* gives *Invalid* result. So after some looking in his wiki page we found [this](https://it.wikipedia.org/wiki/Claude_Shannon#/media/File:Theseus_Maze_by_Claude_Shannon,_1952_-_MIT_Museum_-_DSC03702.JPG) photo representing almost the same rat, named "*Theseus Maze by Claude Shannon*". So the correct word to insert was *Theseus*.

2. It's something about Macintosh so guessing *Jobs* was enough.

3. No idea who he is, but in the video he is called "*dr Wiesner*" by the other man.

4. He's the CEO of Amazon, *Jeff Bezos*.

5. He's *Bill Gates*

6. No idea what this is, we didn't managed to solve this.

7. Searching some of the phrases he says in the video I found his name - *Selfridge* - in a paper titled *Towards an Ethical Framework for Strong AI*

8. It's *HAL9000*

9. Again no idea who they are, just found the solution using shazam.

Once 8 of the 9 inputs are correct the flag is printed out and it contains an
amazing easter egg:
***flag{[https://www.youtube.com/watch?v=5ycx9hFGHog#Y0u_d0_kn0w_h1st0ry](https://www.youtube.com/watch?v=5ycx9hFGHog#Y0u_d0_kn0w_h1st0ry)}***  

Original writeup
(https://github.com/draane/CTF/tree/master/PWN_CTF_2018/History).## History (Forensics)

### Solution

```  
$ unzip J.zip  
$ binwalk J  
DECIMAL       HEXADECIMAL     DESCRIPTION  
--------------------------------------------------------------------------------  
3912330       0x3BB28A        ARJ archive data, header size: 22472, version 1,
minimum version to extract: 1, compression method: stored, file type: binary,
original name: "1", original file date: 1970-01-01 00:00:00, compressed file
size: 538968064, uncompressed file size: 1441792, os: MS-DOS  
```

Since MS-DOS stores data in 16bits little endian, append `-el` to `strings`
for searching, let's try some keywords:  
```  
$ strings -el J | rg "SEC"  
$ strings -el J | rg "CON"  
```

And will find something like,  
```  

Original writeup (https://github.com/jaidTw/ctf-
writeups/blob/master/seccon-2018/history.md).