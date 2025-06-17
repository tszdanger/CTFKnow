There's 38,651 packets in this pcap so we're going to need to get rid of the
noise to find the interesting traffic.  Opening up the pcap in Wireshark, one
of the first thing we see is a bunch of DNS requests for Mozilla domains, so
we're dealing with some browser activity here.

Filter down the DNS traffic with the filter `dns` to find what sites we're
hitting.  656 packets so we can look through all of those manually to find
anything of interest.  Mozilla, YouTube, various Google domains, Yahoo, all
look innocuous.  One possibly interesting result is www.gutenberg.org, which
is followed up by some unencrypted HTTP traffic, but that ends up being a red
herring as well.

Let's assume we're not going to be able to decrypt any HTTPS traffic, so
filter that out with `not tcp.port == 443`.  2499 packets left, so a little
more tractable but still a lot.  And continuing with Occam's Razor, the
simplest explanation is usually the right one, so let's see what else we can
find.

There are several HTTP requests to some Mozilla domains for Firefox's captive
portal detection, those can be ignored.  NTP is normal so let's ignore that.
MDNS, ARP, OCSP, TCP keep-alive, all normal.

Starting at packet 33311 there's some IPP traffic to a printer.  That might be
interesting.  The document is sent starting at packet 35628.  I extracted the
stream, and after some experimentation found
[urf2image](https://github.com/mbevand/urf2image) could convert it to a bmp,
but that just yielded the red herring `(: thanks for participating in
UMassCTF`.

After poking around some more and filtering out more and more common traffic,
I found some unusual traffic coming from local IP 192.168.1.19 (in particular,
the UDP broadcast in packet 3 from port 889 -> 889 was a bit curious).
Filtering down to just `ip.addr==192.168.1.19` yields 162 packets from that
host: a number of those UDP broadcasts, and a single TCP stream sending
exactly 139 bytes every 2 seconds.  How very curious.  Some cursory googling
suggests the UDP broadcasts may be coming from a product called cFosSpeed, so
let's focus on the TCP stream.

The first two packets are nearly entirely ASCII, after that they're mostly
random bytes so probably some kind of encryption going on.  All the packets
start with the same 4 fixed bytes `SM\x92-`, then one byte that's always
`\xFE`, `\xFF`, `\x00`, `\x01`, `\x02`, `\x03`, or `\x04`.  The first two
packets use `\xFE` and `\xFF`, while all the rest use `\x00`-`\x04`
sequentially and cyclically.  After that we get a 6-byte command that's always
`--help`, `--init`, `getflg`, or `getjnk`, so we're going to need to use those
`getflg` commands to get the flag and can ignore those `getjnk` commands.
Finally there's 128 bytes of payload to round out the 139-byte packet, which
would be perfect for AES.

The payload in the first 2 packets is all ASCII and has lots of punctuation,
so let's try decoding it as Ascii85.  The second packet decodes cleanly:

```  
'exfiltration initialized. switching protection. subsequent payload blocks
protected in ctr mode.      '  
```

but the first packet hits a decoding error due to the non-ASCII byte of `\x01`
in it.  The encoder probably messed up and converted `\\1` into `\1`.  If we
replace the `\x01` with the two-byte sequence `\\1` (and drop the `\x00` at
the end of the packet), it decodes cleanly to:

```  
"'init' command will alter implant to initialize data exfiltration. cmd
'get[a-z][a-z][a-z]' to exfil. "  
```

Now, the second packet clues us in about ctr mode.  We don't have any clues
about the key or IV yet, but Byte 5 is likely that counter, and since it
repeats 0-4, we can exploit that, since every 5th packet would be encrypted
with the same key stream.  There are 3 copies of the help packet with counters
0xFE, 0, and 0, and indeed the two with counter 0 are completely identical.
There are 4 getflg commands, with counters 0, 0, 2, and 1, and again the two
packets with counter 0 have identical payloads.

We have the plaintext for the help command (the Ascii85 decoding) and the
ciphertext with counter 0, so we can compute the keytream for anything else
with counter 0 from those.  XOR those with the payload from any packet with
counter 0, and Bob's your uncle:

```  
'getflg: located flag sequence in /opt/flag.txt: UMASS{c4ll_me_sh3rl0ck}
'  
```

---

```lang=python  
import base64  
import socket  
import struct

data = b''  
rows = []

with open('easy_as_123.pcap', 'rb') as f:  
   header = f.read(24)  
   while True:  
       packet_header = f.read(16)  
       if not packet_header:  
           break  
       ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', packet_header)  
       raw_packet = f.read(incl_len)

       if (raw_packet[0x0E] & 0xF0) != 0x40: # IPv4?  
           continue  
       if raw_packet[0x17] != 0x06: # TCP?  
           continue  
       src_ip = socket.inet_ntoa(raw_packet[0x1A:0x1E])  
       dest_ip = socket.inet_ntoa(raw_packet[0x1E:0x22])  
       src_port, dest_port = struct.unpack('>HH', raw_packet[0x22:0x26])

       if src_ip != '192.168.1.19': # and dest_ip != '192.168.1.19':  
           continue

       if not raw_packet[0x2F] & 0x08: # PSH?  
           continue

       row = raw_packet[0x36:]  
       rows.append(row)  
       data += row  
       #print('%d.%06d: %s:%d -> %s:%d: %d bytes' % (ts_sec, ts_usec, src_ip, src_port, dest_ip, dest_port, len(raw_packet)-0x36))

# 66 packets  
#  
# 139 bytes:  
#    4 bytes fixed: SM\x92-  
#    1 byte counter: 0xfe/0xff/0x00/0x01/0x02/0x03/0x04  
#    6 bytes command: --help, --init, getflg, getjnk  
#  128 bytes payload

# replace \x01 => \\1 (and ignore final \x00) in initial help text for some
reason  
# --help: "'init' command will alter implant to initialize data exfiltration.
cmd 'get[a-z][a-z][a-z]' to exfil. "  
# --init: "exfiltration initialized. switching protection. subsequent payload
blocks protected in ctr mode.      "

# Counter values seen:  
# help: 0 (fe), 17 (00), 62 (00) - 00's identical  
# init: 1 (ff)  
# getflg: 2 (00), 27 (00), 44 (02), 63 (01) - 00's identical  
# getjnk: rest (00-04)

print(repr(base64.a85decode(rows[0][11:-1].replace(b'\x01', b'\\1'))))  
print(repr(base64.a85decode(rows[1][11:])))

keystream = [a ^ b for a, b in zip(b"'init' command will alter implant to
initialize data exfiltration. cmd 'get[a-z][a-z][a-z]' to exfil. ",
rows[17][11:])]  
for i, row in enumerate(rows):  
   if row[4] == 0:  
       dec = bytes(a ^ b for a, b in zip(row[11:], keystream))  
       line = '%d:' % i  
       for k in range(len(dec)):  
           if dec[k] < 0x20:  
               line += ' %d' % k  
       print('%d: %r' % (i, dec))  
```

Original writeup (https://github.com/adamantoise/ctf-
writeups/blob/mainline/umass2021/ekrpat.md).