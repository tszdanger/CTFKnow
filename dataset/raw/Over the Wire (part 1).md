# Over the Wire (part 1)  
## 50  
I'm not sure how secure this protocol is but as long as we update the
password, I'm sure everything will be fine ?

---

We're given a PCAP file. It seems like there's something involved with a
password, so I used Ctrl+F to search for the string 'password' in the packet
bytes with Wireshark. I immediately found a packet with the following
information.  

   Hi cat,

   This flag is really important so I had to encrypt it in case it falls into
the wrong hands.

   You already know the FTP password.. Just use the same here, but update it
accordingly ;)

Hm. So there's a flag being transferred and a password used. Since Ctrl+F with
password returns nothing more of importance, let's first look for the flag.  
I used Ctrl+F for 'flag' and found the following packet:  

   -rwxrw-rw-   1 crypto   crypto       7616 Oct 29 12:50 README.md  
   -rwxrw-rw-   1 crypto   crypto        236 Oct 29 12:49 flag.zip  
   -rwxrw-rw-   1 crypto   crypto        190 Oct 29 12:50 reminder.txt

Seems like the result of an "ls -l" command, and it includes something called
flag.zip! Continuing to Ctrl+F for "flag", I found another suspicious packet
following a packet described as "Request: RETR flag.zip". Taking a look at the
packet data, I noticed that it certainly looked like a zip file -- it had the
PK file header! (\x50\x4b is PK in ASCII)

   0000   50 4b 03 04 0a 00 09 00 00 00 77 65 5d 57 cf eb  
   0010   72 36 36 00 00 00 2a 00 00 00 08 00 1c 00 66 6c  
   0020   61 67 2e 74 78 74 55 54 09 00 03 82 53 3e 65 82  
   0030   53 3e 65 75 78 0b 00 01 04 e8 03 00 00 04 e8 03  
   0040   00 00 8c 44 05 3b 76 ba 81 95 01 56 86 18 a7 d2  
   0050   dc 4f 76 81 42 51 92 9b 37 ab 7f 0a dc 21 7f 4e  
   0060   fc 3a c1 2c 6a 0d fd 46 23 46 a1 d1 73 ab 47 32  
   0070   b7 aa c2 b0 5b 36 2a dc 50 4b 07 08 cf eb 72 36  
   0080   36 00 00 00 2a 00 00 00 50 4b 01 02 1e 03 0a 00  
   0090   09 00 00 00 77 65 5d 57 cf eb 72 36 36 00 00 00  
   00a0   2a 00 00 00 08 00 18 00 00 00 00 00 01 00 00 00  
   00b0   a4 81 00 00 00 00 66 6c 61 67 2e 74 78 74 55 54  
   00c0   05 00 03 82 53 3e 65 75 78 0b 00 01 04 e8 03 00  
   00d0   00 04 e8 03 00 00 50 4b 05 06 00 00 00 00 01 00  
   00e0   01 00 4e 00 00 00 88 00 00 00 00 00

I created a simple Python script to write this to a file and voila, I got a
zip file!  

```  
import binascii

s =
'000c29f3d174000c29f50a4308004500012094fa400040060235c0a810d5c0a81083bf99cbb55bd08fedb9cf5a42801101f6bc1300000101080a9af023ebb080049e504b03040a000900000077655d57cfeb7236360000002a00000008001c00666c61672e747874555409000382533e6582533e6575780b000104e803000004e80300008c44053b76ba819501568618a7d2dc4f76814251929b37ab7f0adc217f4efc3ac12c6a0dfd462346a1d173ab4732b7aac2b05b362adc504b0708cfeb7236360000002a000000504b01021e030a000900000077655d57cfeb7236360000002a000000080018000000000001000000a48100000000666c61672e747874555405000382533e6575780b000104e803000004e8030000504b050600000000010001004e000000880000000000'  
f = open('warmup/overthewire1/flagzip', 'wb')  
for i in range(0, len(s), 2):  
   f.write(binascii.unhexlify(s[i:i+2]))  
f.close()  
```

But, only problem was, when I tried to extract flag.txt from the file, it
asked me for a password. Right, the message also included something about a
password. Where could this be?  
Well, my previous search for the string 'password' returned nothing, but
there's something odd about what was said in the message. They specified that
it was an FTP password... why?  
Maybe that's a hint to filter for FTP packets! I filtered for FTP packets and
found the password:  

   5up3r_53cur3_p455w0rd_2022

I went back to my zip file and put in the password and... got it wrong?  
I took a look back at the message. It included a final statement that the user
should "update it [the password] accordingly". This password contains 2022,
what if we change it to 2023?  
With the new password of 5up3r_53cur3_p455w0rd_2023, I unzipped flag.txt and
got the flag!  

   INTIGRITI{1f_0nly_7h3r3_w45_4_53cur3_FTP}