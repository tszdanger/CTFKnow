Description

Marian Rogers Croak is a Vice President of Engineering at Google. She was
previously the Senior Vice President of Research and Development at AT&T. She
holds more than 200 patents. She was inducted into the Women in Technology
International Hall of Fame in 2013. In 2022, Croak was inducted into the
National Inventors Hall of Fame for her patent regarding VoIP (Voice over
Internet Protocol) Technology. She is one of the first two Black women to
receive that honor, along with Patricia Bath. Her invention allows users to
make calls over the internet instead of a phone line. Today, the widespread
use of VoIP technology is vital for remote work and conferencing. - Wikipedia
Entry

Challenge: Find the discarded flag and return it to this Hall of Fame Inventor

---

Because this gives us a disk image, I always start by using autopsy,
especially since the challenge mentions a 'discarded flag' so I want to look
for deleted items.

Looking through the disk there is not much to see except for a pcap file which
looks promising. Extracting this file to my desktop, I can open it up in
wireshark to analyze next.

We know that Marian Croak was known for VoIP and I see some SIP protocol
packets that seem to hold the most information. So after quickly looking up
what I can do with them on wireshark, I saw that under *telephony -> VoIP
Calls* we can see a list of them and even play them.

I listened to all of them and once you reach the last two which are 24 and 23
seconds long, you can hear the flag being spelled out for you. It took a few
tries to determine what was being said but after some trial and error I got
the flag chctf{d3v3l0p3d_vo1c3_0v3r_1p}.

Images and steps included at:
https://jaedyno15.github.io/ctf_writeup/2023-09-09-marian-croak/

Original writeup (https://jaedyno15.github.io/ctf_writeup/2023-09-09-marian-
croak/).