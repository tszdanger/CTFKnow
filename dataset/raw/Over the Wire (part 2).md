# Over the Wire (part 2)  
## 50  
Learning the lessons from the previous failed secure file transfer attempts,
CryptoCat and 0xM4hm0ud found a new [definitely secure] way to share
information ?

---

We're given a PCAP file. Similar to Over the Wire 1, let's Ctrl+F for some
strings in hopes of finding something. I eventually ended up looking for
'share' because of its inclusion in the problem description, which returned
the following SMTP/IMF packet (email).  

---  
   Hi CryptoCat,

   It's been a long time since we last saw each other, and I've been thinking
about our friendship. I believe it's important for us to stay connected and
share important things in a way that only you and I can understand.

   I wanted to remind you that we need to pay more attention to our
communications, especially when it comes to discussing crucial matters.
Sometimes, we might need to hide our messages in plain sight, using our own
secret language. As you know SMTP isn't secure as you think!

   It's like we're on a treasure hunt, and the treasure is our bond. You know
the drill - for our important stuff, we'll need to hide it somewhere unique,
somewhere only we can find it.

   Looking forward to hearing from you soon. Let's make our conversations more
interesting and secure.

   Best,  
   0xM4hm0ud  
---  
From this, I realized that these two were definitely communicating via email.
I filtered for 'imf' packets (since SMTP referred to other packets related to
emails), and got the following packets:  

---  
   Hey 0xM4hm0ud,

   It's great to hear from you! I completely agree that we should keep our
conversations private and intriguing. Our special bond deserves nothing less.
I'm up for the challenge!

   I've been thinking about a unique way we can communicate securely.  
   Maybe we could use a combination of our favorite books, movies or pets as a
code, or even a simple cipher? Let's brainstorm ideas and keep our messages
hidden from prying eyes.

   Looking forward to rekindling our friendship in this exciting and
mysterious way.

   Talk to you soon,  
   CryptoCat  
---  
   Hi CryptoCat,

   I want to buy a cat. I know you already have some nice cats.  
   What do you think about this cat?  
   Let me know as soon as possible!

   0xM4hm0ud  
---  
(This one had a JPG file attached, encoded in base64)

---  
   Hey 0xM4hm0ud,

   I love all kind of cats, but I prefer this cat.

   CryptoCat  
---  
(This one had a PNG file attached, encoded in base64)

I wrote a short python script to create the files locally:  

```  
import base64

print(len(jpg), len(png))

jpgstr = ''  
pngstr = ''  
for i in range(0, len(jpg), 2):  
   if i % 100000 == 0:  
       print(i)  
   jpgstr += chr(int(jpg[i:i+2], 16))

f = open('warmup/overthewire2/cat.jpg', 'wb')  
f.write(base64.b64decode(jpgstr))  
f.close()

for i in range(0, len(png), 2):  
   pngstr += chr(int(png[i:i+2], 16))  
f = open('warmup/overthewire2/cat.png', 'wb')  
f.write(base64.b64decode(pngstr))  
f.close()  
```

(Note that extracting the JPEG takes a really long time, which I probably
should have realized hinted towards not needing to use it).  

Once I had the files, I noticed that they both seemed like plain images. Maybe
they're hiding some data with Least Significant Bit Steganography?  
Using stegsolve, I eventually used 'Data Extract' to extract data from all 0
bits of Red, Green, and Blue of the PNG file, resulting in the flag at the
very top of the hex dump!  

   INTIGRITI{H1dd3n_Crypt0Cat_Purr}