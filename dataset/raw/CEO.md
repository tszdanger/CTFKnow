# UIUCTF: CEO

![date](https://img.shields.io/badge/date-08.01.2021-brightgreen.svg)  
![solved in time of CTF](https://img.shields.io/badge/solved-
in%20time%20of%20CTF-brightgreen.svg)  
![warmup category](https://img.shields.io/badge/category-misc-lightgrey.svg)  
![score](https://img.shields.io/badge/score-50-blue.svg)  
![solves](https://img.shields.io/badge/solves-197-brightgreen.svg)

## Description  
You just wirelessly captured the handshake of the CEO of a multi-million
dollar company! Use your password cracking skills to get the password! Wrap
the password in the flag format.

E.g.: uiuctf{password}

## Tags  
MISC, Cracking, Beginner

## Attached files  
- [megacorp-01.cap](https://raw.githubusercontent.com/Diplodongus/CTFs/main/UIUCTF2021/attachments/megacorp-01.cap?raw=true)  
- [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)

## Summary  
This challenge gave a packet capture that contained a wireless connection to
an AP with SSID joesheer. I was able to decrypt the password using hashcat
version 6.2.3.

## Flag  
```  
uiuctf{nanotechnology}  
```

## Required Software  
Hashcat ```sudo apt install hashcat```

## Detailed solution  
The first thing I did was open the pcap file in wireshark to see if there was
any low-hanging fruit; maybe the password is unencrypted. (Based off the tags,
this is obviously not true, but always worth trying.)

Wireshark tells us that there is a connection to the SSID “joesheer”.

![Wireshark
Screenshot](https://raw.githubusercontent.com/Diplodongus/CTFs/main/UIUCTF2021/img/CEO/1-wireshark.png?raw=true
"Wireshark Screenshot")

From here, I used an online-based cap-to-hccapx converter to put the file in
the format that hashcat can utilize properly. (I used
https://www.onlinehashcrack.com/tools-cap-to-hccapx-converter.php)

```  
**IMPORTANT NOTE:**  
IF YOU ARE FOLLOWING THIS WITH SENSITIVE INFORMATION  
I.E. A CLIENT DO NOT SEND INFORMATION TO 3RD PARTIES SUCH AS THE WEBSITE
ABOVE.  
YOU HAVE NO CONTROL OVER WHAT THEY SAVE AND ANYTHING YOU SEND CAN POTENTIALLY
BE LEAKED

To do this with more sensitive information / offline,  
I would recommend using the official hashcat-utils cap2hccapx.c file.

(https://github.com/hashcat/hashcat-utils/blob/master/src/cap2hccapx.c)  
```

![HCCAPX
Conversion](https://raw.githubusercontent.com/Diplodongus/CTFs/main/UIUCTF2021/img/CEO/2-hccapx.png?raw=true
"HCCAPX Conversion from external site")

Now that I had the file in the correct format, I could use hashcat to crack
the file. You must also have a password dictionary for hashcat to try with. I
used the official rockyou.txt file which is attached.

```  
hashcat -m 2500 wifi.hccapx rockyou.txt --show  
```  
![Hashcat
Output](https://raw.githubusercontent.com/Diplodongus/CTFs/main/UIUCTF2021/img/CEO/3-hashcat.png?raw=true
"Output from Hashcat")

(Screenshot is in PowerShell, but essentially the same output.)

Within 6 seconds, my GPU was able to crack the WiFi password, and the flag is
uiuctf{nanotechnology}.

Original writeup
(https://github.com/Diplodongus/CTFs/blob/main/UIUCTF2021/CEO.md).