# Cat girl breach (re/misc, 273p, 19 solved)

In the task we start off with a
[binary](https://raw.githubusercontent.com/TFNS/writeups/master/2020-07-25-CybricsCTF/catgirl/do_not_pet_me.exe)
and [encrypted
flag](https://raw.githubusercontent.com/TFNS/writeups/master/2020-07-25-CybricsCTF/catgirl/flag.enc).

## VBS/Powershell dropper

If we look inside this binary with 7zip we notice there is a VBS script and a
.bat file.

The VBS simply runs the bat:

```  
Set oShell = CreateObject ("Wscript.Shell")  
Dim strArgs  
strArgs = "cmd /c madoka.bat"  
oShell.Run strArgs, 0, false  
```

And bat is really just dumping lots of ints into a file and finally converts
this to a binary file:

```  
@echo off  
echo|set /p=>456.hex  
attrib +h 456.hex  
echo|set /p=77 90 144 0 3 0 0 0 4 0 0 0 255 255 0 0 184 0 0 0 0 0 0 0 64 0 0 0
0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 8 1 0 0 14 31
186 14 0 180 9 205 33 184 1 76 205 33 84 104 105 115 32 112 114 111 103 114 97
109 32 99 97 110 110 111 116 32 98 101 32 114 117 110 32 105 110 32 68 79 83
32 109 111 100 101 46 13 13 10 36 0 0 0 0 0 0 0 >>456.hex  
echo|set /p=217 61 194 213 157 92 172 134 157 92 172 134 157 92 172 134 41 192
93 134 154 92 172 134 41 192 95 134 52 92 172 134 41 192 94 134 144 92 172 134
166 2 175 135 154 92 172 134 166 2 169 135 129 92 172 134 166 2 168 135 142 92
172 134 64 163 103 134 154 92 172 134 157 92 173 134 238 92 172 134 15 2 168
135 140 92 172 134 15 2 83 134 156 92 172 134 15 2 174 135 156 92 172 134 82
105 99 104 157 92 172 134 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 >>456.hex

...

powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile
-WindowStyle Hidden -Command "[string]$hex = get-content -path
456.hex;[Byte[]] $temp = $hex -split '
';[System.IO.File]::WriteAllBytes('.\main.exe', $temp)"  
```

This takes a long time, so we wrote a short python script to do the same:

```python  
data = open('madoka.bat', 'rb').read()  
res = map(int, re.findall('\d+', data))  
res = [x for x in res if x != 456]  
open('out.exe', 'wb').write("".join(map(chr, res)))  
```

## Pyinstaller dropper

What we get back is another executable.  
From looking at the icon, and also poking around strings it's clear this is a
python executable created with pyinstaller.  
We can either use binwalk to dump zlibs which are in fact `pyc` files, or we
can use some ready pyinstaller unpack script like
https://github.com/extremecoders-re/pyinstxtractor  
The latter is faster because it also recovers the file names.

Now we have `main.pyc` and we can run `uncompyle6` on it to get [source
code](https://raw.githubusercontent.com/TFNS/writeups/master/2020-07-25-CybricsCTF/catgirl/main.py).

This turns out to be yet another dropper.  
Instead of executing the code, we can swap this for a `print` to dump the
[dropped
code](https://raw.githubusercontent.com/TFNS/writeups/master/2020-07-25-CybricsCTF/catgirl/final.py)

## Ransomware

The final code is a bit obfuscated, and has encrypted strings, but we have the
`higurashi` function to decrypt them.  
We can look at all the included strings and it seems pretty clear that the
code is scanning disk looking for the `flag file` and then ecrypts it using
`WAKATTARA` function.

This function is pretty simple, it takes the input pads it so it's multiple of
8 bytes and then converts each 8-byte chunk into 2 integers.  
Then each pair is encrypted via `stage1_enc_8`.  
There is a key parameter, however it's calculated directly by:

```python  
   android = b"https://www.youtube.com/watch?v=yzpGUxateUg"  
   yapapapa = b"https://www.youtube.com/watch?v=DN2ylk6AT5w"  
   liar = 0xff  
   im_feeling_so_broken = bytes([android[i] ^ yapapapa[-1] for i in
range(len(yapapapa))])  
   key = [0, 0, 0, 0]  
   for i in range(len(im_feeling_so_broken)):  
       key[i % 4] = (key[i % 4] + im_feeling_so_broken[i]) % liar  
   print(key)  
```

so we don't need to care about it.

Beatified encryption code is:

```python  
def stage1_enc_8(data, key):  
   a = ctypes.c_uint32(data[0])  
   b = ctypes.c_uint32(data[1])  
   wtf = ctypes.c_uint32(0)  
   const = 0x9e3779b8  
   for i in range(32):  
       b.value -= (a.value << 4) + key[2] ^ a.value + wtf.value ^ (a.value >> 5) + key[3]  
       a.value -= (b.value << 4) + key[0] ^ b.value + wtf.value ^ (b.value >> 5) + key[1]  
       wtf.value -= const  
   return a.value, b.value  
```

And from this we can simply invert the order and turn every `-` into `+` to
get:

```python  
def stage1_dec_8(data, key):  
   a = ctypes.c_uint32(data[0])  
   b = ctypes.c_uint32(data[1])  
   wtf = ctypes.c_uint32(0)  
   const = 0x9e3779b8  
   for i in range(32):  
       wtf.value -= const  
   for i in range(32):  
       wtf.value += const  
       a.value += (b.value << 4) + key[0] ^ b.value + wtf.value ^ (b.value >> 5) + key[1]  
       b.value += (a.value << 4) + key[2] ^ a.value + wtf.value ^ (a.value >> 5) + key[3]  
   return a.value, b.value  
```

We call this by pretty much the same code as encryption:

```python  
def WAKATTARA_dec(crypt, key):  
   crypt += b"\x00" * (8 - (len(crypt) % 8))  
   s = struct.Struct(higurashi("=KH"))  
   j = [(i[0], i[1]) for i in s.iter_unpack(crypt)]  
   ans = []  
   for block in j[0:]:  
       clock = stage1_dec_8(block, key)  
       ans.append(clock)  
   return b"".join(struct.pack(higurashi("=KH"), *i) for i in ans)  
```

And we decrypt the given flag file:

```python  
with codecs.open("flag.enc", 'rb') as en:  
   print(WAKATTARA2(en.read(), key))  
```

And get: `cybrics{me0w_d0_j01n_t0_catgirl_industrial}`

Original writeup
(https://github.com/TFNS/writeups/blob/master/2020-07-25-CybricsCTF/catgirl/README.md).