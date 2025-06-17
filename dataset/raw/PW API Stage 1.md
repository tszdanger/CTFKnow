#  PW API Stage 1  
tags: misc | frsc

## Description

>Prof. Hackevoll always forgets his passwords. Thats why he wrote himself a
password storage API...  
He also used a self developed ticketing system.  
It got so spammed that he doesn't use it anymore.  
Maybe you can still find something useful in the [database
dump](http://dl1.uni.hctf.fun/pwapi/tickets.zip) I found.

## Solution  
The given dump is a zip that contains only the file `tickets.sql`, a big
collection of SQL insert statements.  
The first obvious attempt was to search in the file for the keyword "*flag*",
but, as expected, the task is not so easy.

So looking at the sql statements the table *attachments* seems pretty
interesting. It contains 60 rows formatted this way: `('id', 'ticket_id',
'attachment')`, where the attachment is a long hex value. Since trying to
decode the first hex value result in a file, I decided to decode all af them,
with a simple python script. To simplify the string processing in the  string
I just copied all the rows in a new file *input.txt*.  
The script does some string processing to extract the id and the hex string of
each files and convert it to a new binary file:

```python  
from binascii import unhexlify

with open('input.txt', 'r') as fd:  
   for line in fd:  
       index = line.split("(")[1].split(",")[0]  
       hex_str = line.split(" ")[2].split(")")[0].split("x")[1]

       result = unhexlify(hex_str)  
       with open('files/file_' + index, 'wb') as new_file:  
           new_file.write(result)  
```

So after running it I can check out all the attachments, which turns out to be
all memes images. The only different image is *file_30* and in fact it
contains the flag:

![img](https://github.com/draane/CTF/blob/master/PWN_CTF_2018/API%20stage%201/file_30?raw=true)

*file_30* also contains some useful information for the task **PW API**.  

Original writeup
(https://github.com/draane/CTF/tree/master/PWN_CTF_2018/API%20stage%201).