[Original
writeup](https://ohaithe.re/post/624202013681549312/uiuctf-2020-nookstop-20)

This is a *very un-hacking* solution: we basically just guess the flag!

We start with [this page](https://nookstop2.chal.uiuc.tf/), which looks a lot
like Nookstop 1.0. Just as before, we run

```language-javascript  
document.cookie="secret_backend_service=true";  
```

to enable the "secret backend service" (as clued by the Japanese text in the
source code of the page). Reloading the page gives a link to [the real
challenge](https://nookstop2.chal.uiuc.tf/b9157a97-3a50-42c4-b08a-f19ebcc579fc/abd),
which is running Emscripten.

```  
Grabbing your banking information......  
Your routing number is: 0x9a0 2464  
Your account number has been successfully transmitted using the latest XOR
encryption, and is not shown here for security reasons.  
Please stand by while the ABD decrypts it.......

Calling decrypt function....  
 wkwcwg{c3oo33os[Byte 7F here]  
Uh-oh! There's been an error!  
```

One approach would be to dump out [the WebAssembly
file](https://nookstop2.chal.uiuc.tf/b9157a97-3a50-42c4-b08a-f19ebcc579fc/index.wasm),
as easily found by looking at the page's network requests; then it can be
reversed with the help of tools like [wasm](https://github.com/wwwg/wasmdec)
or [wabt](https://github.com/WebAssembly/wabt). Unfortunately, Emscripten adds
a bunch of external code that is hard to reason about within the context of
just the .wasm file, and so these decompilers produce output that is next-to-
useless. Let's skip the reversing.

The text above hints that there's some kind of XOR going on, and we have a
corrupted key: `"wkwcwg{c3oo33os\x7f"`. This corrupted key looks awfully
similar to `"uiuctf{"`, in the start. Let's XOR the two together and see what
the difference is.

```language-python  
>>> os = "wkwcwg{c3oo33os\x7f"  
>>> bs = "uiuctf{"  
>>> print( [ord(os[i])^ord(bs[i]) for i in range(len(bs))] )  
[2, 2, 2, 0, 3, 1, 0]  
```

Aha, so all of the XORs are off by a number from 0 to 3 -- that is, just the
bottom two bits are wrong. Let's dump out all the candiate characters in the
flag:

```language-python  
>>> for b in os:  
...  print( chr(ord(b) ^ 0) + chr(ord(b) ^ 1) + chr(ord(b) ^ 2) + chr(ord(b) ^
3) )  
...  
wvut  
kjih  
wvut  
cba`  
wvut  
gfed  
{zyx  
cba`

Original writeup
(https://ohaithe.re/post/624202013681549312/uiuctf-2020-nookstop-20).