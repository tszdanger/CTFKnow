# Something Sw33t

## Task

My sweet friend tried telling me about something on this page, but I can’t
seem to find anything… Can you help me: https://cyberyoddha.baycyber.net:33001

## Solution

The title of the page is Flask application. There is nothing interesting in
the source, let's look at the network traffic through the developer consoles
network tab.

We see a random cookie `don't look here` with a base64 looking value. It's
random stuff so I suspect it's a flask specific cookie. There is a tool to
decode them: https://pypi.org/project/flask-cookie-decode/

Using the `examples/app.py`:

```bash  
$ FLASK_APP=app.py ./flask cookie decode "$BASE64"  
UntrustedCookie(contents={'Astley-Family-Members': 6, 'family': {'Cynthia
Astley': [{'description': {' b': 'nice'}, 'flag':  
{' b': 'bm90X2V4aXN0YW50'}, 'name': {' b': 'Cynthia Astley'}}, {'description':
{' b': 'nicee='}, 'flag': {' b': 'YmFzZTY0X2lzX3N1cHJlbWU='}, 'name': {' b':
'Horace Astley'}}, {'description': {' b': 'human'}, 'flag': {' b':
'flag=flag'}, 'name': {'  
b': ''}}, {'description': {' b': 'the man'}, 'flag': {' b':
'Q1lDVEZ7MGtfMV9zZWVfeW91X21heWJlX3lvdV9hcmVfc21hcnR9'}, 'name': {' b': 'Rick
Astley'}}, {'description': {' b': 'yeedeedeedeeeeee'}, 'flag': {' b':
'dHJ5X2FnYWlu'}, 'name': {' b': 'Lene Bausager'}}, {'description': {' b':
'uhmm'}, 'flag': {' b': 'bjBwZWVlZQ=='}, 'name': {' b': 'Jayne Marsh'}},
{'description': {' b': 'hihi'}, 'flag': {' b': 'bjBfYjB0c19oM3Iz'}, 'name': {'
b': 'Emilie Astley'}}]}}, expiration='2020-11-16T23:40:39')  
```

Now we need to parse the json and base64 decode all the values.

```bash  
$ FLASK_APP=app.py ./flask cookie decode "$BASE64" | sed 's|.*contents=\(.*\),  
expiration.*|\1|g' | tr "'" '"' | jq '.family."Cynthia Astley" | map(select(.flag." b" != "flag=flag") | .flag." b" | @base64d)'  
[  
 "not_existant",  
 "base64_is_supreme",  
 "CYCTF{0k_1_see_you_maybe_you_are_smart}",  
 "try_again",  
 "n0peeee",  
 "n0_b0ts_h3r3"  
]  
```  

Original writeup (https://github.com/klassiker/ctf-
writeups/blob/master/2020/cyberyoddha/web-exploitation/something-sw33t.md).