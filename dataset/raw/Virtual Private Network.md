# Virtual Public Network  
*HITCON CTF 2019 Qual ? 183*  
  
*Writeup by Payload, KAIST GoN*

## Problem

Vulnerable Point of Your Network :)  
[http://13.231.137.9](http://13.231.137.9)

## Look up

It's a good habit that check the HTML source code when website is given. Then
we can find some comments.

```html

```

In two links, we can download two files [diag.cgi](src/diag.cgi) and
[DSSafe.pm](src/DSSafe.pm)

`diag.cgi` has 2 features mainly, do `tcpdump` and `backdoor`

```perl  
sub tcpdump_options_syntax_check {  
   my $options = shift;  
   return $options if system("timeout -s 9 2 /usr/bin/tcpdump -d $options
>/dev/null 2>&1") == 0;  
   return undef;  
}  
  
# backdoor :)  
my $tpl = CGI::param("tpl");  
if (length $tpl > 0 && index($tpl, "..") == -1) {  
   $tpl = "./tmp/" . $tpl . ".thtml";  
   require($tpl);  
}  
```

So, when we provide `tpl` parameter in GET request, diag.cgi will include it
and run as perl cgi.

## orange's Perl 101 in Black Hat

Every year, orange (author of problem) announced coooool skills.

CVE-2019-11539 introduced great command injection technique using stderr. The
main key point is the error message of tcpdump, `tcpdump: (filename): No such
file or directory`. If user give filename as `print 123#`, then the error
message will be `tcpdump: print 123#: No such file or directory`. It's normal
error message familar with us, however it's also valid perl script! For
details, please check [orange's blog
article](http://blog.orange.tw/2019/09/attacking-ssl-vpn-part-3-golden-pulse-
secure-rce-chain.html)

Kindly, blog article also teaching us full exploit, I quickly write exploit
script in python to execute arbitrary command in server. [exp.py](./exp.py)

## Execute

To find a flag, firstly I looked up root directory, and I found two files,
`FLAG` and `$READ_FLAG$`. Of coursely, just run a `$READ_FLAG` binary will
print flag. However, dollar sign has special role, some trick is needed to
execute binary.

?(question mark) is a wildcard chracter that only matches one letter, thus
`/?READ_FLAG?` is representation of `/$READ_FLAG$`. Great!

**`hitcon{Now I'm sure u saw my Bl4ck H4t p4p3r :P}`**  

Original writeup (https://github.com/mdsnins/ctf-
writeups/blob/master/2019/HITCON%202019/Virtual%20Public%20Network/VPN.md).