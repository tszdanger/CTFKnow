# TokyoWesterns CTF 2018: Challenge  
***Category: Warmup/Misc***  
## Summary  
The [full solution](#Full-Solution) can be found below.

First we unzip [mondai.zip](mondai.zip) to get [y0k0s0.zip](y0k0s0.zip).

`y0k0s0.zip` is password protected with password: `y0k0s0`.

After unzipping `y0k0s0.zip`, we get [capture.pcapng](capture.pcapng) and
[mondai.zip](mondai2.zip). The password for `mondai.zip` is contained in the
length of each payload sent to `192.168.11.5`, which is: `We1come`.

After unzipping `mondai.zip`, we get [list.txt](list.txt) and another
[mondai.zip](mondai3.zip). The password for `mondai.zip` is contained in one
of the lines in `list.txt`. We find it by running `fcrackzip -u -v -D -p
list.txt mondai.zip`, which gives us: `eVjbtTpvkU`.

After unzipping `mondai.zip`, we get
[1c9ed78bab3f2d33140cbce7ea223894](1c9ed78bab3f2d33140cbce7ea223894). The
password for `1c9ed78bab3f2d33140cbce7ea223894` can be found using `fcrackzip
-u -v -D -p /usr/share/wordlists/rockyou.txt
1c9ed78bab3f2d33140cbce7ea223894`, which gives us: `happyhappyhappy`.

After unzipping `1c9ed78bab3f2d33140cbce7ea223894`, we get a
[README.txt](README.txt) and another [mondai.zip](mondai4.zip). The password
for `mondai.zip` can be found using `fcrackzip -u -v -l 2 mondai.zip`, which
gives us: `to`.

After unzipping `mondai.zip`, we get [secret.txt](secret.txt), which contains
instructions for getting the flag. If we follow the instructions in, we get
the flag: `TWCTF{We1come_to_y0k0s0_happyhappyhappy_eVjbtTpvkU}`.

## Full Solution  
For this challenge, we are just given a zip file, [mondai.zip](mondai.zip),
with no challenge description.

We begin by unzipping `mondai.zip`. From this, we get another zip file,
[y0k0s0.zip](y0k0s0.zip). However, when we try to unzip the second file, we
find it is password protected. First I run `binwalk` on the file to see what
the contents are. We see there is a `capture.pcapng` and `mondai.zip` inside.
No hints there. Next, I try to see if the password was hidden within the file
somewhere using:  
```  
strings y0k0s0.zip  
```  
It wasn't. So I try to run a dictionary attack on the file with:  
```  
fcrackzip -u -v -D -p /usr/share/wordlists/rockyou.txt y0k0s0.zip  
```  
No luck with that either. Then I started thinking about how the challenge had
no description with it. Usually challenges would have some type of clue in the
description for challenges like this, so I started looking within the zip for
clues. I thought it was strange that `y0k0s0.zip`, which was inside
`mondai.zip`, contained another `mondai.zip`. Why would the name be different?
So I tried unzipping the file using password: `y0k0s0`. It worked!

After unzipping `y0k0s0.zip`, we get [capture.pcapng](capture.pcapng) and
[mondai.zip](mondai2.zip). `mondai.zip` seems to be protected with a password
too, so we go to `capture.pcapng` to try and find the password. The pcap
contained a bunch of ICMP traffic. While looking through the packets, I notice
the payloads kept changing with each request. Upon further analysis, there was
nothing interesting about the data itself. However, the payload lengths
themselves all seemed to fall within the printable ascii range. If we only
look at the payload lengths going between `192.168.11.3->192.168.11.5`, we get
the next password: `We1come`.

After unzipping `mondai.zip`, we get [list.txt](list.txt) and another
[mondai.zip](mondai3.zip). Once again, `mondai.zip` is password protected, so
we look at `list.txt` for the password. It looks to be a file containing 1000
lines of random strings of 10 characters. Naturally, we assume one of the
lines in this file will contain the password, so we run:  
```  
fcrackzip -u -v -D -p list.txt mondai.zip  
```  
which gives us: `eVjbtTpvkU`.

After unzipping `mondai.zip`, we get
[1c9ed78bab3f2d33140cbce7ea223894](1c9ed78bab3f2d33140cbce7ea223894). After
running `file 1c9ed78bab3f2d33140cbce7ea223894`, we find out this is another
zip file. As expected, the zip is password protected, but this time, there is
no other file that comes with it. Although I didn't think it would actually
work, I tried unzipping using the file name, like in the first stage. It was
unsuccessful, as expected. Naturally, the next step would be to do a quick run
through with rockyou, so we  
run:  
```  
fcrackzip -u -v -D -p /usr/share/wordlists/rockyou.txt
1c9ed78bab3f2d33140cbce7ea223894  
```  
which gives us: `happyhappyhappy`.

After unzipping `1c9ed78bab3f2d33140cbce7ea223894`, we get a
[README.txt](README.txt) and yet another [mondai.zip](mondai4.zip). If we look
at the contents of `README.txt`, we get:  
```  
password is too short  
```  
Since the last couple of stages had been solved with `fcrackzip`, I assumed
this stage would be solved with it as well. The hint alluded to the password
being *too short*. The default length of a brute force using `fcrackzip` is 6,
so maybe it meant the password was "too short" for `fcrackzip` to brute force.
I try running:  
```  
fcrackzip -u -v -l 1-5 mondai.zip  
```  
which gives us: `to`.

Unzipping the file gives us [secret.txt](secret.txt). It looks like we've
finally made it to the end! we read the contents of `secret.txt` which gives
us:  
```  
Congratulation!  
You got my secret!

Please replace as follows:  
(1) = first password  
(2) = second password  
(3) = third password  
...

TWCTF{(2)_(5)_(1)_(4)_(3)}  
```  
If we follow the instructions, we can piece together the flag with the
passwords from the previous stages, which gives us:
`TWCTF{We1come_to_y0k0s0_happyhappyhappy_eVjbtTpvkU}`.

***Flag: `TWCTF{We1come_to_y0k0s0_happyhappyhappy_eVjbtTpvkU}`***  

Original writeup
(https://github.com/scai16/CTF/tree/master/2018/TokyoWesterns%20CTF%202018/mondai.zip).