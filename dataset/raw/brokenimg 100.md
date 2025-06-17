### Slightly cheesy solution

Open with a hex editor. The description of the challenge seems suspicious --
maybe let's search for "image"?

Fourth result shows something suspicious nearby:

	<tiff:Artist>Maybe here : 150 164 164 160 163 72 57 57 146 151 154 145 163 56 144 157 170 142 151 156 56 147 147 57 157 63 126 144 162 115 160 164 56 160 156 147</tiff:Artist>

Decimal to ASCII doesn't work. But, notice how each digit is less than 8 --
maybe this is octal!  
Octal to ASCII results in [https://files.doxbin.gg/o3VdrMpt.png](http://).
This is probably what we're looking for.

We can try using a photo editor like Photopea to unstretch the photo, which
shows several base32 encoded strings! But, we're missing parts of the strings,
and typing in some of them doesn't really produce results.

Using binwalk, meanwhile, produces the following result:

	DECIMAL       HEXADECIMAL     DESCRIPTION  
	--------------------------------------------------------------------------------  
	0             0x0             PNG image, 500 x 501, 8-bit/color RGB, non-interlaced  
	41            0x29            Zlib compressed data, default compression  
	132290        0x204C2         MySQL MISAM index file Version 7

Though it might seem promising, in general, binwalk's recognization of a MySQL
MISAM index file for any forensics problem is often misleading.

Let's go back to base32 encoded strings. Given its evident inclusion in the
image, it's probably part of this challenge!

If you decode the portion of the base32 string we are shown under the red
woman, you'll get this: VENQMV@  
Huh... VENQMV is an odd sequence of characters. Maybe VENQMV is base64
encoded? Put it into a base64 decoder, and you'll actually get TCP1

So we're on the right track! Now we just have to figure out the rest of the
base32 string. Well, if you take a look at the photo again, it almost seems as
if the left side of the photo belongs on the ride side... aha! The entire
string is in the photo, just split up because of the photo's editing.

The entire base32 string ends up being

	KZCU4UKNKZBDOY2HKJWVQMTHGBSGUTTGJZDDSUKNK5HDAZCYJF5FQMSKONSFQSTGJZDTK22YPJLG6TKXLIYGMULPHU======

This is decoded into

	VENQMVB7cGRmX2g0djNfNF9QMWN0dXIzX2JsdXJfNG5kXzVoMWZ0fQo=    

Put VENQMVB7cGRmX2g0djNfNF9QMWN0dXIzX2JsdXJfNG5kXzVoMWZ0fQo= into a base64
decoder to receive the flag!

	TCP1P{pdf_h4v3_4_P1ctur3_blur_4nd_5h1ft}