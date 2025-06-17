# Forensics

> On the campground of the CCCamp, someone is trying to troll us by encrypting
> our flags. Sadly, we only got the memory dump of the PC which encrypted our
> flags.

## Intro

We get a zipped ```flagchecker.dmp``` file. There are 3 different levels to
this task, all of which are solved using that one file. We know that:  
- the first flag has not yet been encrypted which points at something being typed when the dump was dumped  
- the second flag was encrypted moments before the dump  
- the third flag is somewhere in there without any more precisions

This was a super fun challenge with lots of layers. I'll divide the write-up
into 4 parts: a general approach, and one for each of the flags.

## Solving  
### General

A dump file. Did someone say
[vola](https://github.com/volatilityfoundation/volatility/wiki/Command-
Reference)? Vola is the best (imo) tool out there for these kinds of tasks. It
allows you to pretty much extract anything useful including, but not limited
to, screenshots, clipboard, last commands used, entire binaries and much much
more.

So how do you start? First you need to identify what kind of dump is. The
```imageinfo``` command is your best friend, though it doesn't alwazs work.
Sometimes you have to actually dig in there and find references to a specific
OS. But this wasn't one of those times and it recognized it as a Win7SP1x64.
From there on you can start playing. Off the bat, I like to list all running
processes using ```pslist```as well as the contents of the clipboard using
```clipboard``` (which I didn't do right waya this time). I also dump all
filenames present in the binary for later use using ```filescan``` and any
available screenshots using ```screenshot```. For a better explanation on how
to use the commands, have a look at the link above.

### Part 1

This took me much longer than it should have. I took the road not traveled on
this one but it ended up helping for part 2. After dumping the processes I
noticed 2 suspicious candidates:

```  
0xfffffa800246e530 converter.exe          2308   2280     11      183      1
0 2019-08-21 05:52:25 UTC+0000  
0xfffffa800246fb00 converter.exe          2316   2280     10      152      1
0 2019-08-21 05:52:25 UTC+0000  
```  
Well this seems like it's worth investigating. The first step is to dump the
memory associated with those 2 PIDs which can be done using the ```memdump```
command. This yielded 2 large-ish files (~280mb). I started looking through
them to see if anything was interesting but the size made it a bit difficult.

At this point I did what I should have done first and looked up the flag
format for the competition. Sure enough, searching for ```ALLES{``` quickly
revealed the first flag. I then went back to the original dmp file and dang if
it wasn't there as well. Long story short, remember to simply look for your
flag with a simple hex editor as a first thing, could have been solved in 10
seconds.

### Part 2

At this point I was at least getting reaacquainted with volatility. While
poking around I ran the ```clipboard``` command and noticed that the first
flag was also present there as a base64 string. Oh well. What it did motivate
me to do however was to run ```strings``` on the dump to find other base64
strings. And I found one:

```ZuwJUgfmKzIMbo4F8agPy1MPLq+r7cAlDLowY+RT2wgp1uifc2TXeNH4bvbb2VqfK6r77SPHFrrMYR+GMGv8JGS87Tiybyi4LNNHQWnTR8LlGlSeHWWA9pydAXuJjSk8FzUFbqHOKqHc+bCtJ/4K2Q==```

Decoding it produced junk so this might be our encrypted ```ciphertext```?

I started focusing on the 2 ```converter.exe``` processes. First thing was to
dump the binaries associated with them using ```procdump```. Immediately I
noticed that ```2308``` was around 8mb while ```2316``` only 8kb.
Somethingisfishy.gif. Both were simple ```.net``` executables, which are
easily disassembled by [dotPeek](https://www.jetbrains.com/decompiler/), an
excellent tool, especially if you use JetBrains software.

The large ```converter.exe``` can actually be run as an executable and you'll
see that it's a useful small Forms based app to encode/decode strings into
useful formats. Kind of cute but after finding the base64 of the first flag in
the dump I figured this was the tool that was being used and the upper
textblock contained the plaintext, which I found, while the bottom one
contained the base64 encoded flag that the user had copied and which I had
found in the clipboard. So I let it go.

The second looked much more promising. A simple Forms application, extremely
lightweight, with only one textbox and one button. Upon clicking, this
happens:

```c#  
private void Click_Button(object sender, EventArgs e)  
   {  
     Crypto crypto = new Crypto();  
     crypto.function03();  
     this.string_0 = Convert.ToBase64String(crypto.function02(this.text.Text));  
     crypto.Dispose();  
     GC.Collect();  
     GC.WaitForPendingFinalizers();  
     this.ms.Read(Encoding.ASCII.GetBytes(this.string_0), 0, Encoding.ASCII.GetBytes(this.string_0).Length);  
     this.text.Text = this.string_0;  
   }  
```  
  
Moreover, at the top of the program, we have a singular include: ```using
someCrypto;``` which points towards some kind of Crypto module. But he latter
couldn't be found and prevented the app from running on my Win10 PC (yes, I
use Win10 and WSL). But now we know it calls it up, creates a new object,
calls some ```function03(void)``` and specifically runs ```function02``` on
the input to encrypt it.  
  
At this point I was a little stumped so I started looking at other interesting
volatility functions. I came accross ```dlldump```. This wonderful function
dumps all the ```dll``` associated with a specific process if specified. This
yielded around 40 ```dll``` files. Here is an extract of the output:  
  
```  
0xfffffa800246fb00 converter.exe        0x0000000074ef0000 Crypto.dll
OK: module.2316.3e66fb00.74ef0000.dll  
0xfffffa800246fb00 converter.exe        0x000007fefbb90000 gdiplus.dll
OK: module.2316.3e66fb00.7fefbb90000.dll  
0xfffffa800246fb00 converter.exe        0x000007fefd540000 RpcRtRemote.dll
OK: module.2316.3e66fb00.7fefd540000.dll  
```

Uh-oh spaghetti-oh it looks like we have a winner. Now as we all know, most
```dll``` can be decompiled like a normal executable. Again using dotPeek we
get a full-frontal view of the missing import. And now we have our missing
```function02```

```c#  
public byte[] function02(string string_0)  
   {  
     SymmetricAlgorithm symmetricAlgorithm = this.function01();  
     MemoryStream memoryStream = new MemoryStream();  
     CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream, symmetricAlgorithm.CreateEncryptor(), CryptoStreamMode.Write);  
     byte[] bytes = new UnicodeEncoding().GetBytes(string_0.PadRight(string_0.Length % 8, char.MinValue));  
     cryptoStream.Write(bytes, 0, bytes.Length);  
     cryptoStream.FlushFinalBlock();  
     memoryStream.Position = 0L;  
     byte[] array = memoryStream.ToArray();  
     string_0 = (string) null;  
     cryptoStream.Close();  
     memoryStream.Close();  
     GC.Collect();  
     GC.WaitForPendingFinalizers();  
     return array;  
   }  
```  
  
Seems like it's a wrapper for the rest of the module. Lets have a closer look
at what symmetricAlgorithm is:  
  
```c#  
    private SymmetricAlgorithm function01()  
   {  
     RijndaelManaged rijndaelManaged = new RijndaelManaged();  
     rijndaelManaged.KeySize = 256;  
     rijndaelManaged.IV = this.byte_1;  
     rijndaelManaged.Key = this.byte_0;  
     return (SymmetricAlgorithm) rijndaelManaged;  
   }  
```  
  
OK then, kids won't remember but [Rijndael is the original name for
AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard). What we have
here is garden variety AES running in CBC. We also see that ```IV``` and
```key``` are part of a ```Crypto``` instance. So how are they determined?
Well this is where ```function03``` comes in:  
  
```c#  
public void function03()  
   {  
     byte[] binaryForm = new byte[28];  
     WindowsIdentity.GetCurrent().User.GetBinaryForm(binaryForm, 0);  
     this.byte_1 = new byte[16];  
     Array.Copy((Array) binaryForm, 0, (Array) this.byte_1, 0, 16);  
     this.byte_0 = new byte[32];  
     Array.Copy((Array) binaryForm, binaryForm.Length - 16, (Array) this.byte_0, 0, 16);  
     Array.Copy((Array) binaryForm, binaryForm.Length - 16, (Array) this.byte_0, 16, 16);  
   }  
```  
  
I had to do some digging to understand the ```WindowsIdentity``` part. Turns
out it essentially returns the SID of the current user. More info can be found
[here](https://docs.microsoft.com/en-
us/dotnet/api/system.security.principal.windowsidentity.getcurrent?view=netframework-4.8).
So in other words, the program uses the current user's ```SID``` as ```key```
and ```IV```. So all we need is the ```SID``` at runtime and we're golden. But
how do we do that? Yup, there's a function for that. ```getsids``` will
retrieve what you need.  
  
```  
converter.exe (2308): S-1-5-21-2947568794-2193893069-2968809547-1000 (ALLES)  
converter.exe (2308): S-1-5-21-2947568794-2193893069-2968809547-513 (Domain
Users)  
````

Ding ding din we got a winner.  
  
After retrieveing I played around with a simple function on my local machine
to check my own SID and make sure that's what was being used here and because
it also seemed easier than rewrite the function in python. Plus I like c#:  
  
```c#  
using System;  
using System.Security.Principal;

namespace ConsoleApp1  
{  
   class Program  
   {  
       static void Main(string[] args)  
       {  
           byte[] byte_0;  
           byte[] byte_1;  
           byte_0 = new byte[32];  
           byte_1 = new byte[16];  
           byte[] binaryForm = new byte[28];  
           SecurityIdentifier testi = new SecurityIdentifier("S-1-5-21-2947568794-2193893069-2968809547-1000");  
           testi.GetBinaryForm(binaryForm, 0);  
  
           Array.Copy((Array)binaryForm, 0, (Array)byte_1, 0, 16);  
           Array.Copy((Array)binaryForm, binaryForm.Length - 16, (Array)byte_0, 0, 16);  
           Array.Copy((Array)binaryForm, binaryForm.Length - 16, (Array)byte_0, 16, 16);

           string converted = BitConverter.ToString(byte_0);  
           string converted2 = BitConverter.ToString(byte_1);

           Console.WriteLine(converted);  
           Console.WriteLine(converted2);

       }  
   }  
}  
```

What this does is return the hexstring for both ```key``` and ```IV```. At
this point just use python to decrypt:

```python  
from Crypto.Cipher import AES  
mode = AES.MODE_CBC  
encryptor = AES.new(key, mode, IV=IV)  
encryptor.decrypt(ct.decode('base64'))  
```

At first glance I got garbage. Then I noticed that the plaintext was simply
littered with `\x00`s. Removing those yielded the flag. Probably could have
gleaned that from the source code but why bother when it's so easy?

### Part 3

Sadly we had a wedding that night which meant I didn't have any more time. So
I didn't solve the last part but found it a day later though I had to look at
another writeup to fully get it. Turns out there is a weird filename in the
file list:

```\Device\HarddiskVolume2\Program
Files\D9f\gCFhd\yxEUQSFyoHU1ybvQ0S9TOOwUWFCR+HWh+YicMXXJ2hzO39bjKEbONClpsoTzUtfuC86APEJGe46byt7fmJGBEkmrtktbMIZ5Mk4LnGFkyNVkAwEKm\O7dnFs7JKPrXrI9Co8Z4ULFf1UzT1cK5wFiIONE\0t33K+0.bat```

And running ```screenshots``` also displays an open window with part of that
filepath shown, so I guess there were enough hints. What I found to be a
stretch was that the path had to be truncated, the ```\``` replace with
```/``` and finally padded to yield:

```D9f/gCFhd/yxEUQSFyoHU1ybvQ0S9TOOwUWFCR+HWh+YicMXXJ2hzO39bjKEbONClpsoTzUtfuC86APEJGe46byt7fmJGBEkmrtktbMIZ5Mk4LnGFkyNVkAwEKm/O7dnFs7JKPrXrI9Co8Z4ULFf1UzT1cK5wFiIONE/0t33K+0=```

Which then had to be decoded using the encryption service from part 2. There
were a lot of assumptions there, not the least of which that it was the same
user. I would have enjoyed some added twist here like for example an
environment variable pointing to a fake SID and a function not unlike the one
I wrote it to convert it to a WindowsIdentity token to be used for encryption.
It felt like a bit of a letdown.

## Conclusion

Be that as it may, I loved solving the challenge and I learned a ton.
Definitely would recommend this as a begginer-friendly challenge if you want
to become more familiar with volatiliy :)

Original writeup
(https://github.com/Gdasl/CTFs/blob/master/ChaosCTF/Foreniscs.md).