## Heisenberg's Password  
So this is a memory forensics challenge, which I solve quite often with
Volatility, a memory forensics tool from Volatility Foundation. We got this
humongous raw file, which I always reckon as a memory dump. 

> Description: Some undercover cops were trying to get info from a drug dealer
> named Heisenberg. He stored all the details of the drug mafia in an
> encrypted file in his PC. PC is with cops now. But they don't know the
> password. According to the Intelligence team, Heisenberg has weak memory and
> He used to store his strong password as different parts in different places
> in his wife's PC. The Intelligence team were able to collect his wife's PC
> memory dump. The Intelligence team informed us that getting the answers for
> given questions and setting them in a given format might give us the
> password. So could you help them to get the password?  
>PS: Follow the order of questions while wrapping the answers  
> When is the last time loveyou.png modified? eg: 2020–10–10_11:45:33  
> What is the physical offset of Loveletter text? eg: 0x000000007ac06539  
> When is the last time the MEGA link opened? eg: 2020–10–10_11:45:33  
> Wrap the answers in the format:
> BSDCTF{2020–10–10_11:45:33$7ac06539$2020–10–10_11:45:33}

Oh, I love this. This is like SANS forensics challenge, which is not
necessarily a flag finding, but also learning what you could find in a memory
dump.

### 1st section - Identifying what dump is this  
Is it brown? Yellow? Or Windows 98? Usually it will be obviously on Windows
due to its unique Little-Endian style of encoding. BUT to check it, we just
need to do the Volatility magic command.

`python vol.py -f ../../BsidesDelhi/Win7mem/Win7mem.raw imageinfo`

`imageinfo` will tell you based on KDBG search, which is a Windows-thing for
debugging purposes. From the [Security StackExchange
Answer](https://security.stackexchange.com/a/71117) :

_The KDBG is a structure maintained by the Windows kernel for debugging
purposes. It contains a list of the running processes and loaded kernel
modules. It also contains some version information that allows you to
determine if a memory dump came from a Windows XP system versus Windows 7,
what Service Pack was installed, and the memory model (32-bit vs 64-bit)._

So yeah, just to see the Windows version of this, you need to parse the
debugging style.  
```  
INFO    : volatility.debug    : Determining profile based on KDBG search...  
         Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418  
                    AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)  
                    AS Layer2 : FileAddressSpace (/this/should/be/my/directory/Win7mem.raw)  
                     PAE type : No PAE  
                          DTB : 0x187000L  
                         KDBG : 0xf800029fc070L  
         Number of Processors : 2  
    Image Type (Service Pack) : 0  
               KPCR for CPU 0 : 0xfffff800029fdd00L  
               KPCR for CPU 1 : 0xfffff880009ee000L  
            KUSER_SHARED_DATA : 0xfffff78000000000L  
          Image date and time : 2020-09-30 14:08:36 UTC+0000  
    Image local date and time : 2020-09-30 19:38:36 +0530  
```  
Cool, so we get the Windows version which is `Win7SP1x64` or Windows 7 Service
Pack 1 64-bit. Now what?

### 2nd section - Finding the last modified file date on the dump  
Hmmm... how do we find the date of modified file? Using Volatility, simply put
a `mftparser` command. This should parse the MFT of the dump. What's MFT, you
might ask? According to [The official Windows
Documentation](https://docs.microsoft.com/en-us/windows/win32/fileio/master-
file-table):

_The NTFS file system contains a file called the master file table, or MFT.
There is at least one entry in the MFT for every file on an NTFS file system
volume, including the MFT itself. All information about a file, including its
size, time and date stamps, permissions, and data content, is stored either in
MFT entries, or in space outside the MFT that is described by MFT entries._

Cool, so metadata of a file is stored in MFT which we can acquire by using
Volatility. So we can run command:

`python vol.py -f ../../BsidesDelhi/Win7mem/Win7mem.raw --profile=Win7SP1x64
mftparser > ../../BsidesDelhi/Win7mem/mft.txt`.

It will be a long output so I need to put it in a TXT file to make sure I
didn't need to run the same command again.

So we left with `mft.txt` with 300,000 lines of output. But we just need to
find the interesting file of `loveyou.png`. Using simple search, we could find
two entries of `loveyou.png`:

```  
Line 44562: 2020-09-30 13:54:56 UTC+0000 2020-09-30 13:54:56 UTC+0000
2020-09-30 13:54:56 UTC+0000   2020-09-30 13:54:56 UTC+0000
Users\bsides\Desktop\loveyou.png

Line 106429: 2020-09-30 13:34:58 UTC+0000 2020-09-30 13:34:58 UTC+0000
2020-09-30 13:34:58 UTC+0000   2020-09-30 13:34:58 UTC+0000
Users\bsides\DOWNLO~1\loveyou.png  
```

The second date of a line is the modified date, so we get `2020-09-30
13:54:56` as the first answer.

### 3rd section - Finding the actual offset of a file

So in Volatility we can simply use `filescan` to get the file listing and its
offset, because of NTFS nature of tracking things.

`python vol.py -f ../../BsidesDelhi/Win7mem/Win7mem.raw --profile=Win7SP1x64
filescan > ../../BsidesDelhi/Win7mem/filelist.txt`

Again, we're putting it in TXT because there is an enormous amount of file
here. After it's finished, we can look around and search the interesting file.

`Line 2983: 0x000000007fa07960     16      0 RW-r--
\Device\HarddiskVolume2\Users\bsides\Desktop\loveletter.txt`

Got it. The second answer is `7fa07960`.

### 4th section - Finding the browser history :floshed:

Are you using your Windows to open questionable websites? Worry yes, with the
memory dump we can get your recent history. First we have to look for the
browser it is using by looking at the processes using `cmdline` command. But
apparently there is no info about the browser, at least not running. So,
blindly, I'm using `chromehistory` plugin by
[superponible](https://blog.superponible.com/2014/08/31/volatility-plugin-
chrome-history/). And apparently it works, and returned several recent history
of the browser.  
```  
...  
   33 https://www.google.com/
Google
2     1 2020-09-30 14:05:05.765148        N/A  
   32
https://mega.nz/file/iehAyJYR#VdDc7oPuH225hp_orw4TswOU5dOSLMhqntpfoVEGjds
https://mega.nz/file/iehAyJYR#VdDc7oPuH225hp_orw4TswOU5dOSLMhqntpfoVEGjds
2     1 2020-09-30 14:04:39.493154        N/A  
...  
```

This is the most recent Mega link opened. So the third answer is `2020-09-30
14:04:39`

So, based on those answers, the flag is:

`BSDCTF{2020-09-30_13:54:56$7fa07960$2020-09-30_14:04:39}`

Original writeup (https://medium.com/@spitfirerxf/bsidesdelhi-2020-ctf-
writeup-my-part-703bb69c89fa).