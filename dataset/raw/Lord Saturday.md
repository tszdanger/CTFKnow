# Lord Saturday

I removed the vulnerable binary, so what could go wrong using an old version
of  
sudo?

Challenge: http://34.72.152.156

Authors: Robin Jadoul & qxxxb \  
Attachments: `lord_saturday.zip`

## Solution

> Write-up and solve script by Robin Jadoul

We're clearly dealing with an instance of the Baron Samedit CVE.  
However, we need to get around some restrictions such as:  
- `/usr/bin/sudoedit` has been removed  
- We have no compiler and no good way to get anything from the internet (no  
 `curl`, `wget` or even `nc`)

Once we can circumvent those restrictions, using an "off-the-shelf" PoC like  
https://github.com/stong/CVE-2021-3156 should be a feasible way to go.

For the first problem, realize that `/usr/bin/sudoedit` is in fact not a
binary  
file, but simply a symlink to `/usr/bin/sudo`, which functions differently  
depending on the value of `argv[0]`.  If we create our own symlink, say  
`/home/ctf/sudoedit`, pointing to `/usr/bin/sudo`, this will work in exactly  
the same manner.

The second problem can be handled by several methods, e.g. sending a binary  
file through `base64 -d` and copy-pasting or piping it into the remote.  To  
keep libc compatibility, we can compile the exploit binary in the same docker  
image locally.  

Original writeup
(https://github.com/qxxxb/ctf_challenges/blob/master/2021/ccc/pwn/lord_saturday/solve).