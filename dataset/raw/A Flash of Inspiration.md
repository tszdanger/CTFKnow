# A Flash of Inspiration

From the previous challenge, we know that this file is a compiled binary for
the Arduino.

We are given a .bin file but we need to convert it to an Intel Hex file so it
can be flashed to the Arduino.

There are various tools to do this, such as Bin2Hex.py, which is linked.

After converting flash.bin, to flash.hex, I flashed it onto my Arduino Uno
with:

```"C:\Program Files (x86)\Arduino\hardware\tools\avr/bin/avrdude" -C
"C:\Program Files (x86)\Arduino\hardware\tools\avr/etc/avrdude.conf" -v
-patmega328p -carduino -PCOM3 -b115200 -D -Uflash:w:C:\Path\To\flash.hex:i```

I got this command from uploading a sketch to the Arduino with the software.

Once flashed, I checked the Serial Monitor in the Arduino software, but it was
only outputting invalid characters.

I thought that the baudrate could be the problem, so I tried turning it down.

There were less invalid characters as I went further down and at 19200, I got
the flag:

#### Flag: ractf{DidYouDoAnalysis?}  

Original writeup
(https://github.com/TheWinRaRs/Writeups/blob/master/RACTF/Pwn/A%20Flash%20Of%20Inspiration/A%20Flash%20of%20Inspiration.md).