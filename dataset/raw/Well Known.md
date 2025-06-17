# Well Known

This task was part of the 'Web' category at the 2020 Hexion CTF (during 11-13
April 2020).  
It was solved by [The Maccabees](https://ctftime.org/team/60231) team.

# The challenge

Description:

```  
Well... it's known (:  
https://wk.hexionteam.com  
```

When entering the website, we get a 404 error code.

The challenge name and description indicates this has some connections to
[RFC8615](https://tools.ietf.org/html/rfc8615) - which defines a path prefix
in HTTP(S) URIs for these "well-known locations", "/.well-known/".  
This wikipedia page lists all the possible well-known URIs: [List of /.well-
known/ services offered by
webservers](https://en.wikipedia.org/wiki/List_of_/.well-
known/_services_offered_by_webservers).

So we just iterated over all of them in this python script:

```python  
#!/usr/bin/env python  
import requests  
domain = "https://wk.hexionteam.com/.well-known/{}"  
well_known_uris = [  
   "acme-challenge",  
   "ashrae",  
   "assetlinks.json",  
   "caldav",  
   "carddav",  
   "coap",  
   "core",  
   "csvm",  
   "dnt",  
   "dnt-policy.txt",  
   "est",  
   "genid",  
   "hoba",  
   "host-meta",  
   "host-meta.json",  
   "http-opportunistic",  
   "keybase.txt",  
   "mercure",  
   "mta-sts.txt",  
   "ni",  
   "openid-configuration",  
   "openorg",  
   "pki-validation",  
   "posh",  
   "reload-config",  
   "repute-template",  
   "resourcesync",  
   "security.txt",  
   "stun-key",  
   "time",  
   "timezone",  
   "uma2-configuration",  
   "void",  
   "webfinger",  
   "apple-app-site-association",  
   "apple-developer-merchantid-domain-association",  
   "browserid",  
   "openpgpkey",  
   "autoconfig/mail",  
   "change-password",  
   "nodeinfo", ]

for well_known_uri in well_known_uris:  
   d = domain.format(well_known_uri)  
   r = requests.get(d)  
   if r.status_code != 404:  
       print(well_known_uri)  
```

The script returned two results:

```  
http-opportunistic  
security.txt  
```

When browsing to the `security.txt` URI, we get the flag!

```  
Flag: hexCTF{th4nk_y0u_liv3_0v3rfl0w}  
```

Original writeup (https://github.com/TheMaccabees/ctf-
writeups/blob/master/HexionCTF2020/WellKnown/README.md).