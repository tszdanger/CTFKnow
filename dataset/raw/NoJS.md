# No-JS

Square 2022 Web CTF challenge

## Description

Reverting back to the ye-olde days, absolutely no javascript is allowed on my
pure site. No vulnerabilities allowed here, no sir!

## Notes

The flag is stored as a post on the admin user's profile. When you share a
note to the admin, it'll show up in the same page as the post (`"/"`), and the
admin bot will visit it.

The site (intentionally) uses Go's `text/template` instead of `html/template`
package. This allows for arbitrary HTML injection to occur on the site, as
text/template doesn't attempt to sanitize at all. The site also sets the
following security headers:

```  
Content-Security-Policy: "default-src 'self'; script-src 'none'"  
X-XSS-Protection: 0  
X-Content-Type-Options: "nosniff"  
X-Frame-Options: "sameorigin"  
```

This has the following (important to note) consequences:  
1. No javascript is allowed to execute at all on the page.   
2. Unsafe-inline isn't set, so inline <style></style> tags are also blocked. 

The flag is in the admin post below. To leak the post, you can do dangling
markdown as follows:

```  

Original writeup (https://github.com/tnek/nojs).