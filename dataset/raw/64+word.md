# 64+word

## __Description__

Help Keith with his word search!!!! Where is the flag?

[64word.txt](64word.txt)

## __Solution__

It's a word search game in base64 format.

First I converted 'hsctf{' to base 64:

```  
>>> base64.b64encode(b'hsctf{')  
b'aHNjdGZ7'  
```

Then I tried to look for 'aHNj' in the file.

It is located in the 35th line in the file and is diagonal.

Write a simple [script](solve.py) to retrieve and decode it.

```  
aHNjdGZ7YjRzM182NF93MHJkX3MzYXJjaDNzX2FyM19mdTk/fQ5H  
b'hsctf{b4s3_64_w0rd_s3arch3s_ar3_fu9?}\x0eG'  
```

The flag is

```  
hsctf{b4s3_64_w0rd_s3arch3s_ar3_fu9?}  
```  

Original writeup (https://github.com/kuruwa2/ctf-
writeups/tree/master/HSCTF%206/64%2Bword).