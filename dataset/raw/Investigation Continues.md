> Investigation Continues  
>  
> 936  
>  
> There are still some more questions that have come up. Provide the answers
> for them too.  
>  
> When was the last time Adam entered an incorrect password to login?  
>  
> Answer should be in the format DD-MM-YYYY_HH:MM:SS. Timestamp in UTC.  
>  
> When was the file 1.jpg Opened?  
>  
> Answer should be in the format DD-MM-YYYY_HH:MM:SS. Timestamp in UTC.  
>  
> When did Adam last use the taskbar to launch Chrome?  
>  
> Answer should be in the format DD-MM-YYYY_HH:MM:SS. Timestamp in UTC.  
>  
> Note-1: The challenge file is the same as that of the challenge
> Investigation.  
>  
> Note-2: Wrap the answers around inctf{}. Sample flag:
> inctf{01-02-2019_21:04:59_05-08-2016_13:04:45_03-05-2018_12:54:35}  
>  
> Author: stuxn3t

*Investigation* challenge was fairly simple once you get a hang of using [Volatility](https://www.volatilityfoundation.org/releases), but *Investigation Continues* was more difficult.

The first piece of the flag was the toughest to find. It usually requires
access to event logs, but ```evtlogs``` plugin refused to play ball. After
lots and lots of googling I finally found [this page](http://what-when-
how.com/windows-forensic-analysis/registry-analysis-windows-forensic-analysis-
part-7/). Bytes 40-47 of value F in the user key under SAM has the timestamp
of the last failed login:

```  
$ volatility -f raw_image --profile=Win7SP1x64 printkey -K
"SAM\Domains\Account\Users\000003E8"  
Volatility Foundation Volatility Framework 2.6  
Legend: (S) = Stable   (V) = Volatile

----------------------------  
Registry: \SystemRoot\System32\Config\SAM  
Key name: 000003E8 (S)  
Last updated: 2020-07-22 09:05:19 UTC+0000

Subkeys:

Values:  
REG_BINARY    F               : (S)  
0x00000000  02 00 01 00 00 00 00 00 4d 87 04 39 07 60 d6 01   ........M..9.`..  
0x00000010  00 00 00 00 00 00 00 00 60 26 1a c7 98 5e d6 01   ........`&...^..  
0x00000020  00 00 00 00 00 00 00 00 e8 0b 82 34 07 60 d6 01   ...........4.`..  
0x00000030  e8 03 00 00 01 02 00 00 10 00 00 00 01 00 e4 04   ................  
0x00000040  00 00 0b 00 01 00 00 00 00 00 00 00 00 00 00 00   ................  
...  
```

The timestamp value we need is ```e8 0b 82 34 07 60 d6 01```. Let's decode it:

```python  
Python 2.7.18 (default, Apr 20 2020, 20:30:41)  
[GCC 9.3.0] on linux2  
Type "help", "copyright", "credits" or "license" for more information.  
>>> import time  
>>> def to_seconds(h):  
...    s=float(h)/1e7 # convert to seconds  
...    return s-11644473600 # number of seconds from 1601 to 1970  
>>> timestamp = 0x01d6600734820be8  
>>> time.asctime(time.gmtime(to_seconds(timestamp)))  
'Wed Jul 22 09:05:11 2020'  
```

The JPEG file timestamp can be found in the recent documents list:

```  
$ volatility -f raw_image --profile=Win7SP1x64 printkey -K
"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.jpg"  
Volatility Foundation Volatility Framework 2.6  
Legend: (S) = Stable   (V) = Volatile

----------------------------  
Registry: \??\C:\Users\Adam\ntuser.dat  
Key name: .jpg (S)  
Last updated: 2020-07-21 18:38:33 UTC+0000

Subkeys:

Values:  
REG_BINARY    MRUListEx       : (S)  
0x00000000  00 00 00 00 ff ff ff ff                           ........  
REG_BINARY    0               : (S)  
0x00000000  31 00 2e 00 6a 00 70 00 67 00 00 00 4c 00 32 00   1...j.p.g...L.2.  
0x00000010  00 00 00 00 00 00 00 00 00 00 31 2e 6c 6e 6b 00   ..........1.lnk.  
0x00000020  38 00 08 00 04 00 ef be 00 00 00 00 00 00 00 00   8...............  
0x00000030  2a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   *...............  
0x00000040  00 00 00 00 00 00 00 00 00 00 31 00 2e 00 6c 00   ..........1...l.  
0x00000050  6e 00 6b 00 00 00 14 00 00 00                     n.k.......  
```

Finally, ```userassist``` gives us the update timestamp of the Chrome link in
the taskbar:

```  
$ volatility -f raw_image --profile=Win7SP1x64 userassist  
Volatility Foundation Volatility Framework 2.6  
...  
REG_BINARY    %APPDATA%\Microsoft\Internet Explorer\Quick Launch\User
Pinned\TaskBar\Google Chrome.lnk :  
Count:          3  
Focus Count:    0  
Time Focused:   0:00:00.503000  
Last updated:   2020-07-21 17:37:18 UTC+0000  
Raw Data:  
0x00000000  00 00 00 00 03 00 00 00 00 00 00 00 03 00 00 00   ................  
0x00000010  00 00 80 bf 00 00 80 bf 00 00 80 bf 00 00 80 bf   ................  
0x00000020  00 00 80 bf 00 00 80 bf 00 00 80 bf 00 00 80 bf   ................  
0x00000030  00 00 80 bf 00 00 80 bf ff ff ff ff 10 54 ef 94   .............T..  
0x00000040  85 5f d6 01 00 00 00 00                           ._......  
...  
```

The flag is
```inctf{22-07-2020_09:05:11_21-07-2020_18:38:33_21-07-2020_17:37:18}```.

Original writeup (https://0xd13a.github.io/ctfs/inctf2020/investigation-
continues/).