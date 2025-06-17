# Defcamp 2018 Quals: Broken TV

![date](https://img.shields.io/badge/date-22.09.2018-brightgreen.svg)  
![solved in time of CTF](https://img.shields.io/badge/solved-
in%20time%20of%20CTF-brightgreen.svg)  
![misc category](https://img.shields.io/badge/category-misc-lightgrey.svg)  
![score](https://img.shields.io/badge/score-330-blue.svg)  
![solves](https://img.shields.io/badge/solves-17-brightgreen.svg)

## Description  
An experienced hacker gained unauthorised access into a facility with limited
options to exfiltrate data but he managed to launch a backdoor to solve this
issue. However, he got arrested before intercepting the confidential data. Can
you recover the information and maybe do some profits on his behalf? Flag
format: `DCTF\{[A-Za-z0-9\-]+\}`  
**For this challenge you are allowed to scan using nmap, but it won't help you
too much :)**  
Target: 104.248.38.191

## Summary  
Analyse `ping` time response

## Flag  
```  
DCTF{EXF1LTRAT3-L1K3-4-PR0-1S-4W3S0M3}  
```

## Detailed solution  
After pinging the server with `ping 104.248.38.191`, we observe that the
response time is in interesting ranges: *under 200*(must be ignored), *greater
than 200 and smaller than 1000*(binary 0), *above 1000*(binary 1).  
We create some files with pings result and a **Python** [script](solve.py)
that analyses and converts them in *binary digits*. Then, we use an [online
tool](www.rapidtables.com/convert/number/binary-to-ascii.html), with
additional padding and extract some parts of the flag, that helps us to
reconstruct the valid flag.  

Original writeup (https://github.com/iosifache/CTF-
writeups/blob/master/misc/exfil/writeup.md).