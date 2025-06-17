# How to Breakdance

## Description

My friend ctf_playah has been learning to breakdance, can you find his youtube
password? Upon submission, wrap his password with UMDCTF{}.

[how_to_breakdance](how_to_breakdance.pcapng)

## Solution

The file contains a usb keyboard caputure, so we can use [this
tool](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser) to extract the
pressed keys

```console  
$ tshark -r how_to_breakdance.pcapng -Y 'usb.capdata && usb.data_len == 8' -T
fields -e usb.  
capdata | sed 's/../:&/g2' > key

$ python usbkeyboard.py key  
best breakdancing videos on the iternet  
hoo to lean breakdancing in one day  
ctf_playah  
1_luv_70_f1nd_c7f_fl46s  
https://www.youtube.com/watch?v=7j5-u7hS0fs  
This is it!The tutorial Ihave been waiting for my whole life!  
```

#### **FLAG >>** `UMDCTF{1_luv_70_f1nd_c7f_fl46s}`

Original writeup (https://github.com/K1nd4SUS/CTF-
Writeups/tree/main/UMDCTF_2022/How%20to%20Breakdance).