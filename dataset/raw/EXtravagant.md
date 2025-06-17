# Personnel

![Personnel.PNG](https://github.com/vichhika/CTF-
Writeup/blob/main/NahamCon%20CTF%202022/Personnel/resource/Personnel.PNG?raw=true)

- __Attachments:__ [app.py](resource/app.py)

# Resources  
| File | Description |  
|------|-------------|  
| [app.py](resource/app.py) | Source code |

# Exploitation

![lookup.jpeg](https://github.com/vichhika/CTF-
Writeup/blob/main/NahamCon%20CTF%202022/Personnel/resource/lookup.jpeg?raw=true)

Look at the [app.py](resource/app.py), We see that `flag` and `users` variable
read file and `flag`'s values was appended to `users`. Look at route `/` there
are two methods `GET`, and `POST` was accepted. In `POST` method, it qeury two
variables, `name` and `setting` from `POST` request.

```python  
#!/usr/bin/env python

from flask import Flask, Response, abort, request, render_template  
import random  
from string import *  
import re

app = Flask(__name__)

flag = open("flag.txt").read()  
users = open("users.txt").read()

users += flag

@app.route("/", methods=["GET", "POST"])  
def index():  
   if request.method == "GET":  
       return render_template("lookup.html")  
   if request.method == "POST":  
       name = request.form["name"]  
       setting = int(request.form["setting"])  
       if name:  
           if name[0].isupper():  
               name = name[1:]

       results = re.findall(r"[A-Z][a-z]*?" + name + r"[a-z]*?\n", users, setting)  
       results = [x.strip() for x in results if x or len(x) > 1]

       return render_template("lookup.html", passed_results=True, results=results)

if __name__ == "__main__":  
   app.run()  
```

![exploit.jpeg](https://github.com/vichhika/CTF-
Writeup/blob/main/NahamCon%20CTF%202022/Personnel/exploit.jpeg?raw=true)

We input `name`= `A.*`  and     `setting = 2`.   So we will bypass if
condition and we get full regex.  
regex = `[A-Z][a-z]*?.*[a-z]*?\n` but at `[a-z]*?` is not matched with flag,
so we need to ignore case sensitive for this case.  
so we set setting = 2 similar
[`re.IGNORECASE`](https://docs.python.org/3/library/re.html#:~:text=re.-,IGNORECASE,-%C2%B6)  
# Flag

```  
flag{f0e659b45b507d8633065bbd2832c627}  
```  

Original writeup (https://github.com/vichhika/CTF-
Writeup/tree/main/NahamCon%20CTF%202022/Personnel).