The given file was foren2.E01.tar.gz and the problem was the following:

```  
We need to few answers from you do you know them?  
1. Recently accessced docs folder  
2. Last keyword searched  
3. Last link entered  
Flag Format: darkCON{recently accessced docs folder_last keyword searched_last
link entered}  
```

The first thing to is to decompress with `tar -xzf foren2.E01.tar.gz` for
example. After that we can use sleuthkit to examine the file. Now we could
find the files we are interested in with fls and extract the files with icat
but for me it was easier to extract all the files and look through the folders
with tools like ls or find. We can extract all the files with the command
`tsk_recover foren2.E01 out`, which puts all the files into the folder called
out.

On Windows, the things we are looking for are stored in a registry hive called
NTUSER.DAT, which is in the user folder. In our case, the only user is John
Wick and the path to the hive we are looking for is out/Users/John
Wick/NTUSER.DAT. The hive can be opened and examined with tools like regripper
and Registry Explorer.

The path to the key containing values about recently accessed folders is
`NTUSER.DAT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\Folder`.
The value named MRUListEx contains sequential 4 bite hexadecimal numbers,
which refer to the names of other values under the key. The first number is
the name of the value, containing data about the last accessed resource, which
is in our case the last accessed folder. The data of that value contains the
name of the resource and in our case it is **secluded**. Some tools like
Registry Explorer automatically parse the data and the sequence into a more
human readable format.

The path to the key about last keyword searched is
`NTUSER.DAT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`.
There you can find data in the same format as the last key and our answer is
**Anachronistic**.

The last link entered is a bit different. In our case, the browser used is
Internet Explorer and the urls are also in the hive. Other browsers usually
keep their data in other locations on the drive. The path to the key is
`NTUSER.DAT\SOFTWARE\Microsoft\Internet Explorer\TypedURLs` and the value we
are looking for is the first value named url1. The answer is
**https://www.youtube.com/watch?v=Z1xs1BRBO7Q**.

All the information found must be combined and the final flag is
**darkCON{secluded_Anachronistic_https://www.youtube.com/watch?v=Z1xs1BRBO7Q}**.
The dark**CON** part is very important or you might possibly lose your mind
for half an hour about what is wrong before noticing, that you wrote darkCTF.

Some resources which helped me solve the problem:  
https://www.sans.org/security-resources/posters/windows-forensic-
analysis/170/download  
https://forensic4cast.com/2019/03/the-recentdocs-key-in-windows-10/  
https://crucialsecurity.wordpress.com/2011/03/14/typedurls-part-1/

Original writeup (https://github.com/keyboard-monkeys/ctf-
writeups/blob/main/2021-darkctf/forensics_do_you_know_them%253F.md).