# file reader

#### Description:  
```  
hello guys, I started this new service check note.txt file for a sanity check
207.180.200.166 2324  
```  
#### Files:  
reader.py  
```python  
import glob

blocked = ["/etc/passwd", "/flag.txt", "/proc/"]

def read_file(file_path):  
   for i in blocked:  
       if i in file_path:  
               return "you aren't allowed to read that file"  
  
   try:  
       path = glob.glob(file_path)[0]  
   except:  
       return "file doesn't exist"  
  
   return open(path, "r").read()

user_input = input("> ")  
print(read_file(user_input))  
```

#### Auther:  
No Auther was mentioned foor this challenge.  
#### Points and solvers:  
At the end of the CTF, 77 teams solved this challenge and it was worth 459
points.

## Solution:  
We need of course to print the content of the "/flag.txt" file, we cannot
though because of the `blocked` list.  
The [`glob.glob`](https://docs.python.org/3/library/glob.html#glob.glob)
function "can contain shell-style wildcards",  
what this means is that if we would write `/flag.tx*` the function will try to
complete this pattern and match `/flag.tx*` with the file names in the system
where `*` can be everything.  
Insert that and the flag will appear.

## Flag:  
```  
flag{oof_1t_g0t_expanded_93929}  
```  

Original writeup (https://github.com/yonlif/0x41414141-CTF-
writeups/blob/main/filereader.md).# DarkCTF 2020 – File Reader

* **Category:** web  
* **Points:** 494?

## Challenge

> My friend developed this website but he says user should know some Xtreme >
> Manipulative Language to understand this web.  
>  
> Flag is in /flag.txt  
>  
> http://filereader.darkarmy.xyz/

## Solution

The web site is a form to upload files. Reading the challenge description, an
*XXE* should be involved.

The form allows only PDF and DOCX files.

Uploading a DOCX file, you can notice that some information are shown. One of
them is the number of pages.

DOCX files are archives of files where XML documents are present.

It is sufficient to create a DOCX and to alter the
[`test.docx\docProps\app.xml`](https://raw.githubusercontent.com/m3ssap0/CTF-
Writeups/master/DarkCTF%202020/File%20Reader/app.xml) file, where the number
of pages is stored, like the following.

```xml

]>  
<Properties
xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-
properties"
xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Template>Normal.dotm</Template><TotalTime>0</TotalTime><Pages>&xx;;</Pages><Words>0</Words><Characters>4</Characters><Application>Microsoft
Office
Word</Application><DocSecurity>0</DocSecurity><Lines>1</Lines><Paragraphs>1</Paragraphs><ScaleCrop>false</ScaleCrop><Company>Reply</Company><LinksUpToDate>false</LinksUpToDate><CharactersWithSpaces>4</CharactersWithSpaces><SharedDoc>false</SharedDoc><HyperlinksChanged>false</HyperlinksChanged><AppVersion>16.0000</AppVersion></Properties>  
```

Uploading the file in the web application will return the flag where the
number of pages is shown. The flag will be the following.

```  
darkCTF{1nj3ct1ng_d0cx_f0r_xx3}  
```

Original writeup (https://github.com/m3ssap0/CTF-
Writeups/blob/master/DarkCTF%202020/File%20Reader/README.md).